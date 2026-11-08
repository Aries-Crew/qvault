"""`/api/encrypt` 與 `/api/decrypt` 的測試(#22;設計見 ADR-002 決策 2、7、8、9)。

一律以 **`http.client`** 打真 socket、伺服器 `port=0` 起在 daemon thread、測試
結束 `shutdown()`——夾具 `server` 來自 `tests/conftest.py`、`send()` / `Response`
來自 `tests/webui_client.py`,與 `tests/test_webui_server.py` 共用同一份:六道門的
語意與「每一道都可以單獨拆掉」的旋鈕只有一份,複製一份只會讓兩份慢慢漂,而漂掉
的那一份就是入口防線。

三類測試(AGENTS.md 鐵律 4)在本檔的落點:
  round-trip → `test_encrypt_*_round_trip*`、`test_decrypt_restores_the_golden_vector`
               (golden 那條走**真** scrypt,其餘吃 `fast_kdf`)
  tamper     → `test_tampered_container_is_indistinguishable_from_a_wrong_passphrase`
               (header / chunk 0 / 資料塊 / tag 各改一處 → 422 且訊息完全相同)
  邊界       → 0 bytes 與 3 個資料塊、`force` / `passphrase` / `out_dir` 的型別、
               409 / 404 / 400 / 422 各自的碼、兩條並行的 encrypt

另有三組**結構性**測試,守的是「不會在行為測試裡自己現形」的規矩:
  `test_both_ends_import_the_same_classifier`      —— 分類只有一個事實源
  `test_webui_does_not_duplicate_the_cli_messages` —— 共用訊息只有一本帳
  `test_errors_module_knows_nothing_about_http`    —— 狀態碼不汙染錯誤體系
"""

from __future__ import annotations

import ast
import hashlib
import http.client
import json
import os
import pathlib
import re
import threading
import uuid

import pytest

from qvault_core import cli, errors, vault, webui
from qvault_core import kek as kek_mod
from qvault_core.container import HEADER_SIZE_KEM1
from qvault_core.errors import (
    MSG_OUT_DIR_MISSING,
    QVaultDecryptError,
    QVaultFormatError,
    QVaultVersionError,
)
from qvault_core.vault import CHUNK0_SEALED_LEN

# `send` / `Response` 是工具,住在非測試模組 `tests/webui_client.py`(見模組 docstring)。夾具
# `server` 由 `tests/conftest.py` 註冊——import 一個夾具只為了讓 pytest 看見它,
# 在 gate 的 ruff 下是 F401 + 每個參數一次 F811(`# noqa` 在 gate 不算數)。
from tests.webui_client import Response, send

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_PATH = REPO_ROOT / "qvault_core" / "cli.py"
WEBUI_PATH = REPO_ROOT / "qvault_core" / "webui.py"
ERRORS_PATH = REPO_ROOT / "qvault_core" / "errors.py"

#: golden 向量(#2 的 [M2]);密碼與預期明文與 `tests/test_vault.py` 同一份事實。
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"
GOLDEN_PW = "correct horse"
GOLDEN_NAME = "golden.txt"
GOLDEN_DATA = b"QVault golden vector v1\n"

PW = "correct horse battery staple"
WRONG_PW = "incorrect horse battery staple"

#: 錯密碼與竄改**共用**的那一句(ADR-001 保證③:兩者完全不可區分)。
AUTH_FAILED = "AEAD authentication failed"

#: AC「`kind → status`」那張表,**寫死在測試裡**(不從 `webui` 讀,否則表被改掉
#: 這裡會跟著漂)。ADR-002 決策 8 的行文逐列轉錄。
EXPECTED_STATUS_BY_KIND = {
    "format": 422,
    "decrypt": 422,
    "version": 422,
    "missing": 404,
    "exists": 409,
    "not_dir": 400,
    "usage": 400,
    "unexpected": 500,
}

# ---------------------------------------------------------------- 夾具與工具


@pytest.fixture
def fast_kdf(monkeypatch):
    """把 scrypt 換成便宜但**參數敏感**的派生(同 `tests/test_cli.py` 的那一招)。

    參數敏感是重點:密碼/salt/n/r/p 任一不同就派生出不同的 KEK,所以「錯密碼」
    與「改一個 byte」這類測試仍然如實地失敗在 AEAD 驗證上。`log2n/r/p/salt` 與
    header 欄位全維持正規值,故這不是「測一個不同的格式」。

    走**真** scrypt 的那條(golden 向量)刻意不吃這個夾具。
    """

    def cheap(passphrase_bytes, salt, *, n, r, p, dklen=32):
        material = b"|".join(
            [passphrase_bytes, salt, str(n).encode(), str(r).encode(), str(p).encode()]
        )
        return hashlib.sha256(material).digest()[:dklen]

    monkeypatch.setattr(kek_mod, "_scrypt", cheap)


class _Prompter:
    """假的 `getpass`(同 `tests/test_cli.py`):依序吐出測試預先餵的答案。"""

    def __init__(self) -> None:
        self.queue: list[str] = []

    def feed(self, *passphrases: str) -> "_Prompter":
        self.queue.extend(passphrases)
        return self

    def __call__(self, label: str = "") -> str:
        if not self.queue:
            raise AssertionError("CLI asked for more passphrases than the test fed")
        return self.queue.pop(0)


@pytest.fixture
def ask(monkeypatch):
    """接管 `getpass.getpass`——CLI 對帳用(密碼永遠不進 argv)。"""
    prompter = _Prompter()
    monkeypatch.setattr(cli.getpass, "getpass", prompter)
    return prompter


def cli_error(capsys, ask, argv: list[str], *answers: str) -> str:
    """`cli.main(argv)` 印出的那一行,**去掉 `qvault: ` 前綴**。

    只挑帶前綴的那一行:伺服器的 access log 也寫 stderr,而它與本函式無關
    (`tests/test_webui_server.py::test_access_log_has_only_method_path_and_status`
    才是管它的那條)。
    """
    ask.feed(*answers)
    capsys.readouterr()
    assert cli.main(argv) != 0, "失敗的操作必須以非零 exit 收場"
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err + captured.out
    lines = [ln for ln in captured.err.splitlines() if ln.startswith("qvault: ")]
    assert len(lines) == 1, f"錯誤輸出不是一行 `qvault: …`:{captured.err!r}"
    return lines[0][len("qvault: ") :]


def make_file(directory: pathlib.Path, name: str, size: int) -> pathlib.Path:
    """生一個 `size` 位元組、內容逐位置相異的輸入檔。"""
    path = directory / name
    pattern = bytes(range(256))
    path.write_bytes((pattern * (size // 256 + 1))[:size])
    return path


def api_encrypt(srv, path, passphrase, **extra) -> Response:
    payload = {"path": str(path), "passphrase": passphrase, **extra}
    return send(srv, path=webui.API_ENCRYPT_PATH, payload=payload)


def api_decrypt(srv, path, out_dir, passphrase, **extra) -> Response:
    payload = {
        "path": str(path),
        "out_dir": str(out_dir),
        "passphrase": passphrase,
        **extra,
    }
    return send(srv, path=webui.API_DECRYPT_PATH, payload=payload)


# ================================================================ encrypt:round-trip


def test_encrypt_writes_the_suffixed_file_and_round_trips(server, tmp_path, fast_kdf):
    """AC:100 bytes 進去 → `200 {"out": "<path>.qvt"}`,且 `vault` 還原得回來。

    還原刻意走 **`vault.decrypt_file`**(不是 API):這條驗的是「API 寫出來的
    東西是個真的 `.qvt`」,拿同一個 API 解回來會讓兩邊的 bug 互相抵銷。
    """
    src = tmp_path / "a.txt"
    src.write_bytes(os.urandom(100))
    original = src.read_bytes()

    res = api_encrypt(server, src, "pw")
    assert res.status == 200
    assert set(res.json()) == set(webui.RESULT_KEYS)
    out = pathlib.Path(res.json()["out"])
    assert out == tmp_path / "a.txt.qvt"
    assert out.exists()

    dest = tmp_path / "back"
    dest.mkdir()
    restored = vault.decrypt_file(out, dest, "pw")
    assert restored.name == "a.txt"
    assert restored.read_bytes() == original


@pytest.mark.parametrize("size", [0, 1, 3 * 65536 + 1])
def test_api_round_trip_over_sizes(server, tmp_path, fast_kdf, size):
    """邊界 AC:0 bytes 與 `3 * 65536 + 1` bytes(≥ 3 個資料塊)都還原相等。

    這一條**整圈都走 API**:encrypt 端點寫出的檔由 decrypt 端點讀回來,故
    「分塊 / 末塊 flag / `orig_size`」在 HTTP 這一層也被走過一次。
    """
    src = make_file(tmp_path, "payload.bin", size)
    original = src.read_bytes()
    dest = tmp_path / "out"
    dest.mkdir()

    enc = api_encrypt(server, src, PW)
    assert enc.status == 200, enc.text
    dec = api_decrypt(server, enc.json()["out"], dest, PW)
    assert dec.status == 200, dec.text

    restored = pathlib.Path(dec.json()["out"])
    assert restored == dest / "payload.bin"
    assert restored.read_bytes() == original
    assert len(original) == size


# ================================================================ encrypt:409 / force


def test_encrypt_refuses_to_overwrite_without_force(server, tmp_path, fast_kdf):
    """AC:已存在且不帶 `force` → `409` 且既有檔**逐位元組不變**;`force` → `200`。"""
    src = make_file(tmp_path, "a.txt", 100)
    first = api_encrypt(server, src, PW)
    assert first.status == 200
    out = pathlib.Path(first.json()["out"])
    frozen = out.read_bytes()

    refused = api_encrypt(server, src, PW)
    assert refused.status == 409
    assert refused.json()["error"] == errors.MSG_REFUSE_OVERWRITE.format(path=out)
    assert out.read_bytes() == frozen

    forced = api_encrypt(server, src, PW, force=True)
    assert forced.status == 200
    assert forced.json()["out"] == str(out)
    # salt 與 nonce_prefix 每檔重生(決策 10),故覆寫後的位元組必然不同。
    assert out.read_bytes() != frozen


def test_encrypt_409_message_is_the_one_the_cli_prints(server, tmp_path, fast_kdf, ask, capsys):
    """同一個狀況,UI 與 CLI 說**同一句話**(訊息只有一本帳:`errors.MSG_*`)。"""
    src = make_file(tmp_path, "a.txt", 64)
    assert api_encrypt(server, src, PW).status == 200

    refused = api_encrypt(server, src, PW)
    assert refused.status == 409
    assert refused.json()["error"] == cli_error(capsys, ask, ["encrypt", str(src)])


def test_force_reaches_the_vault_layer(server, tmp_path, fast_kdf, monkeypatch):
    """`force` 必須**傳下去**,不能只靠端點自己那個「已存在」前置檢查。

    前置檢查只是為了給 `409` 一句可操作的訊息;真正的守門人是 `encrypt_file`
    (前置檢查與 `os.replace` 之間有 TOCTOU 窗口)。寫死 `force=True` 傳下去的
    話,那個窗口裡出現的檔案就會被默默覆寫。
    """
    seen: dict[str, object] = {}

    def spy(inp, out, passphrase, **kwargs):
        seen.update(kwargs)
        return pathlib.Path(out)

    src = make_file(tmp_path, "a.txt", 16)
    monkeypatch.setattr(webui, "encrypt_file", spy)

    assert api_encrypt(server, src, PW).status == 200
    assert seen["force"] is False
    assert api_encrypt(server, src, PW, force=True).status == 200
    assert seen["force"] is True


# ================================================================ encrypt:輸入錯誤碼


def test_encrypt_on_a_missing_path_is_404(server, tmp_path, fast_kdf, ask, capsys):
    """AC:`path` 不存在 → `404`,訊息逐字等於 CLI 的那一行。"""
    missing = tmp_path / "nope.txt"
    res = api_encrypt(server, missing, PW)
    assert res.status == 404
    assert res.json()["error"] == cli_error(capsys, ask, ["encrypt", str(missing)])
    assert res.json()["error"] == errors.MSG_INPUT_MISSING.format(path=missing)


def test_encrypt_with_an_empty_passphrase_is_400(server, tmp_path, fast_kdf, ask, capsys):
    """AC:`passphrase` 為 `""` → `400`;訊息同 CLI(空字串不是弱、是無)。"""
    src = make_file(tmp_path, "a.txt", 16)
    res = api_encrypt(server, src, "")
    assert res.status == 400
    assert res.json()["error"] == errors.MSG_PASSPHRASE_EMPTY
    assert res.json()["error"] == cli_error(capsys, ask, ["encrypt", str(src)], "")
    assert not (tmp_path / "a.txt.qvt").exists()


def test_encrypt_with_an_unencodable_passphrase_is_400(server, tmp_path, fast_kdf, ask, capsys):
    """AC:孤兒代理對 → `400`,且 `error` **不含那個字元**(它是密碼的一部分)。

    不得轉述 `UnicodeEncodeError`:它的訊息會把出錯的字元印出來(鐵律 5)。
    """
    src = make_file(tmp_path, "a.txt", 16)
    res = api_encrypt(server, src, "\udc80")
    assert res.status == 400
    assert res.json()["error"] == errors.MSG_PASSPHRASE_UNENCODABLE
    assert "\udc80" not in res.json()["error"]
    assert "\\udc80" not in res.text
    assert "dc80" not in res.text.lower()
    assert res.json()["error"] == cli_error(capsys, ask, ["encrypt", str(src)], "\udc80")
    assert not (tmp_path / "a.txt.qvt").exists()


@pytest.mark.parametrize(
    "passphrase", [None, 1, 1.5, True, ["pw"], {"pw": 1}, {}, []]
)
def test_encrypt_without_a_string_passphrase_is_400(server, tmp_path, fast_kdf, passphrase):
    """AC:`passphrase` 非字串 → `400`。`True` 也不算(`bool` 不是 `str`)。"""
    src = make_file(tmp_path, "a.txt", 16)
    res = send(
        server,
        path=webui.API_ENCRYPT_PATH,
        payload={"path": str(src), "passphrase": passphrase},
    )
    assert res.status == 400
    assert set(res.json()) == {"error"}
    assert not (tmp_path / "a.txt.qvt").exists()


def test_encrypt_with_an_absent_passphrase_is_400(server, tmp_path, fast_kdf):
    """AC:`passphrase` 缺席 → `400`(缺席與送 `null` 同一個碼、同一句話)。"""
    src = make_file(tmp_path, "a.txt", 16)
    absent = send(server, path=webui.API_ENCRYPT_PATH, payload={"path": str(src)})
    null = send(
        server, path=webui.API_ENCRYPT_PATH, payload={"path": str(src), "passphrase": None}
    )
    assert absent.status == null.status == 400
    assert absent.json() == null.json()


@pytest.mark.parametrize("force", [1, 0, "true", "", None, [], {}, "false"])
def test_non_boolean_force_is_400(server, tmp_path, fast_kdf, force):
    """AC:`force` 非 bool → `400`。

    寬鬆解讀(「非空就是真」)在這裡的代價是覆寫別人的檔案,故 `1` 與 `"true"`
    都不算真;`0` / `""` / `null` 也不算假——型別錯就是型別錯。
    """
    src = make_file(tmp_path, "a.txt", 16)
    res = api_encrypt(server, src, PW, force=force)
    assert res.status == 400
    assert set(res.json()) == {"error"}
    assert not (tmp_path / "a.txt.qvt").exists()


@pytest.mark.parametrize("name", ["con.txt", "a:b.txt"])
def test_encrypt_rejects_names_the_vault_cannot_restore(
    server, tmp_path, fast_kdf, ask, capsys, name
):
    """AC:ADR-001 決策 21 會拒絕的來源檔名 → `422`,訊息逐字等於 CLI 的那一行。

    `vault.encrypt_file` 對**來源檔名**跑 `_sanitize_name`(`vault.py:336-341`):
    Windows 保留裝置名(`con`)與禁用字元(`:`)都會拋 `QVaultFormatError`——
    寧可在加密時當場說清楚,也不要寫出一個在別的平台還原不了的檔。
    """
    src = make_file(tmp_path, name, 32)
    res = api_encrypt(server, src, PW)
    assert res.status == 422
    assert res.json()["error"] == cli_error(capsys, ask, ["encrypt", str(src)], PW, PW)
    assert "cannot be restored" in res.json()["error"]
    # 失敗的那一刻不留半成品(決策 16)。
    assert not (tmp_path / f"{name}.qvt").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == [name]


# ================================================================ encrypt:並行


def test_two_concurrent_encrypts_both_succeed(server, tmp_path, fast_kdf, monkeypatch):
    """AC:兩個執行緒各打一個 encrypt(不同檔)→ 兩個都 `200` 且各自 round-trip。

    `threading.Barrier(2)` 讓兩個請求**必須真的同時**在端點裡:若
    `ThreadingHTTPServer` 其實是串行的,先到的那個會在 barrier 上等到逾時、
    拋 `BrokenBarrierError` → `500`,這條測試就紅。所以它測的是並行本身,
    不只是「連打兩次都成功」。
    """
    barrier = threading.Barrier(2, timeout=30)
    real_encrypt = vault.encrypt_file

    def both_at_once(*args, **kwargs):
        barrier.wait()
        return real_encrypt(*args, **kwargs)

    monkeypatch.setattr(webui, "encrypt_file", both_at_once)

    sources = [make_file(tmp_path, f"p{index}.bin", 128 + index) for index in range(2)]
    results: dict[int, Response] = {}

    def worker(index: int) -> None:
        results[index] = api_encrypt(server, sources[index], f"{PW}-{index}")

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    assert sorted(results) == [0, 1]
    for index, src in enumerate(sources):
        res = results[index]
        assert res.status == 200, res.text
        out = pathlib.Path(res.json()["out"])
        assert out == tmp_path / f"p{index}.bin.qvt"
        dest = tmp_path / f"back{index}"
        dest.mkdir()
        restored = vault.decrypt_file(out, dest, f"{PW}-{index}")
        assert restored.read_bytes() == src.read_bytes()


# ================================================================ decrypt:golden(真 scrypt)


def test_decrypt_restores_the_golden_vector(server, tmp_path):
    """AC:golden 向量(密碼 `correct horse`)→ `200`,還原 bytes 等於預期明文。

    **這一條刻意不吃 `fast_kdf`**:走真正的 scrypt(15/8/1),故它同時是
    「API 解得開一個 repo 裡凍結的、不是本次測試造出來的檔」的證明。預期明文與
    檔名是 `tests/test_vault.py` 的 `GOLDEN_DATA` / `GOLDEN_NAME` 同一份事實。
    """
    res = api_decrypt(server, GOLDEN, tmp_path, GOLDEN_PW)
    assert res.status == 200, res.text
    assert set(res.json()) == set(webui.RESULT_KEYS)

    out = pathlib.Path(res.json()["out"])
    assert out == tmp_path / GOLDEN_NAME
    assert out.read_bytes() == GOLDEN_DATA
    # 原始檔名由 `decrypt_file` 從 chunk 0 解出來,不是從 `golden_v1.qvt` 推的。
    assert out.name != GOLDEN.stem


def test_decrypt_of_the_golden_vector_with_a_wrong_passphrase_is_422(server, tmp_path):
    """真 scrypt 的錯密碼路徑:`422` + 那一句共用的訊息,且目錄裡什麼都沒留下。"""
    before = sorted(os.listdir(tmp_path))
    res = api_decrypt(server, GOLDEN, tmp_path, GOLDEN_PW + "!")
    assert res.status == 422
    assert res.json()["error"] == AUTH_FAILED
    assert sorted(os.listdir(tmp_path)) == before


# ================================================================ decrypt:錯密碼與 tamper


@pytest.fixture
def container(tmp_path, fast_kdf) -> dict:
    """一個 100 bytes 的 `.qvt`(走 `fast_kdf`)+ 一個空的 `out_dir`。"""
    src = make_file(tmp_path, "payload.bin", 100)
    qvt = tmp_path / "payload.bin.qvt"
    vault.encrypt_file(src, qvt, PW)
    dest = tmp_path / "out"
    dest.mkdir()
    return {"src": src, "qvt": qvt, "dest": dest, "plaintext": src.read_bytes()}


def test_decrypt_round_trips_and_restores_the_original_name(server, container):
    res = api_decrypt(server, container["qvt"], container["dest"], PW)
    assert res.status == 200
    out = pathlib.Path(res.json()["out"])
    assert out == container["dest"] / "payload.bin"
    assert out.read_bytes() == container["plaintext"]


def test_decrypt_with_a_wrong_passphrase_is_422_with_the_cli_message(
    server, container, ask, capsys
):
    """AC:錯密碼 → `422`,`error` **逐字等於** CLI 對錯密碼印出的訊息(去前綴)。"""
    dest = container["dest"]
    before = sorted(os.listdir(dest))

    res = api_decrypt(server, container["qvt"], dest, WRONG_PW)
    assert res.status == 422
    expected = cli_error(
        capsys,
        ask,
        ["decrypt", str(container["qvt"]), "--out-dir", str(dest)],
        WRONG_PW,
    )
    assert res.json()["error"] == expected
    assert res.json()["error"] == AUTH_FAILED
    # 原子性:失敗的解密不留半成品(決策 16)。
    assert sorted(os.listdir(dest)) == before


@pytest.mark.parametrize(
    "where,offset",
    [
        ("header-salt", 11),
        ("header-nonce-prefix", 27),
        ("header-wrapped-dek", 40),
        ("chunk0", HEADER_SIZE_KEM1 + 7),
        ("data-chunk", HEADER_SIZE_KEM1 + CHUNK0_SEALED_LEN + 3),
        ("last-tag", -1),
    ],
)
def test_tampered_container_is_indistinguishable_from_a_wrong_passphrase(
    server, container, where, offset
):
    """AC:header / chunk 0 / 資料塊 / tag 各改一處 → `422`,訊息與錯密碼**完全相同**。

    這是 ADR-001 保證③ 在 HTTP 這一層的形式:狀態碼與 `error` 都不區分「密碼錯」
    與「被竄改」。區分得出來就是一個 oracle——攻擊者拿它一個 byte 一個 byte 地
    問「我改對了嗎」。

    竄改點刻意挑 **AEAD 蓋得到的那些**(salt / nonce_prefix / wrapped_dek /
    chunk 0 / 資料塊 / 末塊 tag)。`magic` 與 `version` 那幾個 byte 是另一類
    (「這根本不是一個 v1 `.qvt`」,`QVaultFormatError` / `QVaultVersionError`),
    見 `test_decrypt_of_a_non_container_is_422_with_the_cli_message`:同樣 `422`,
    但那句話本來就不該與「解不開」同一句——它在容器被**讀進來之前**就成立,
    不含任何「密碼對不對」的資訊。
    """
    raw = bytearray(container["qvt"].read_bytes())
    raw[offset] ^= 0x01
    tampered = container["dest"].parent / "tampered.qvt"
    tampered.write_bytes(bytes(raw))

    dest = container["dest"]
    before = sorted(os.listdir(dest))
    res = api_decrypt(server, tampered, dest, PW)

    assert res.status == 422, (where, res.text)
    assert res.json()["error"] == AUTH_FAILED, where
    assert sorted(os.listdir(dest)) == before, f"{where}:竄改的容器留下了半成品"


def test_wrong_passphrase_and_tamper_are_byte_for_byte_the_same_response(server, container):
    """同一個 body、同一個狀態碼:兩條路徑的回應**逐位元組相等**。"""
    raw = bytearray(container["qvt"].read_bytes())
    raw[HEADER_SIZE_KEM1 + 1] ^= 0x80
    tampered = container["qvt"].with_name("t.qvt")
    tampered.write_bytes(bytes(raw))

    wrong = api_decrypt(server, container["qvt"], container["dest"], WRONG_PW)
    tamper = api_decrypt(server, tampered, container["dest"], PW)
    assert (wrong.status, wrong.body) == (tamper.status, tamper.body)


# ================================================================ decrypt:輸入錯誤碼


def test_decrypt_into_a_missing_out_dir_is_400(server, container, ask, capsys):
    """AC:`out_dir` 不存在 → `400`(決策 8 明列),訊息逐字等於 CLI 的那一行。"""
    nowhere = container["dest"].parent / "nowhere"
    res = api_decrypt(server, container["qvt"], nowhere, PW)
    assert res.status == 400
    assert res.json()["error"] == errors.MSG_OUT_DIR_MISSING.format(path=nowhere)
    assert res.json()["error"] == cli_error(
        capsys,
        ask,
        ["decrypt", str(container["qvt"]), "--out-dir", str(nowhere)],
        PW,
    )
    assert not nowhere.exists()


def test_decrypt_into_a_file_instead_of_a_directory_is_400(server, container):
    """`out_dir` 指到一個**檔案**:同一句話、同一個碼(它一樣不是目錄)。"""
    res = api_decrypt(server, container["qvt"], container["src"], PW)
    assert res.status == 400
    assert res.json()["error"] == errors.MSG_OUT_DIR_MISSING.format(
        path=container["src"]
    )


def test_decrypt_refuses_to_overwrite_without_force(server, container, ask, capsys):
    """AC:目標檔已存在且無 `force` → `409`;帶 `force` → `200` 且被覆寫。"""
    dest = container["dest"]
    target = dest / "payload.bin"
    target.write_bytes(b"do not clobber me")

    refused = api_decrypt(server, container["qvt"], dest, PW)
    assert refused.status == 409
    assert target.read_bytes() == b"do not clobber me"
    assert refused.json()["error"] == cli_error(
        capsys, ask, ["decrypt", str(container["qvt"]), "--out-dir", str(dest)], PW
    )

    forced = api_decrypt(server, container["qvt"], dest, PW, force=True)
    assert forced.status == 200
    assert target.read_bytes() == container["plaintext"]


def test_decrypt_of_a_non_container_is_422_with_the_cli_message(
    server, tmp_path, fast_kdf, ask, capsys
):
    """AC:不是 `.qvt` 的檔 → `422`,訊息逐字等於 CLI 的那一行。

    判準是**內容**不是副檔名(同 CLI:它也不看副檔名)。「不是 `.qvt`」在這裡
    的可觀察形式就是 `deserialize` 的 `bad magic`。
    """
    junk = tmp_path / "notes.txt"
    junk.write_bytes(b"not a qvault container at all, really" * 8)
    dest = tmp_path / "out"
    dest.mkdir()

    res = api_decrypt(server, junk, dest, PW)
    assert res.status == 422
    assert res.json()["error"] == "bad magic: not a .qvt container"
    assert res.json()["error"] == cli_error(
        capsys, ask, ["decrypt", str(junk), "--out-dir", str(dest)], PW
    )
    assert sorted(os.listdir(dest)) == []


@pytest.mark.parametrize("out_dir", [None, 1, True, ["/tmp"], {"a": 1}])
def test_decrypt_without_a_string_out_dir_is_400(server, container, out_dir):
    res = send(
        server,
        path=webui.API_DECRYPT_PATH,
        payload={
            "path": str(container["qvt"]),
            "out_dir": out_dir,
            "passphrase": PW,
        },
    )
    assert res.status == 400
    assert set(res.json()) == {"error"}


def test_decrypt_with_an_absent_out_dir_field_is_400(server, container):
    res = send(
        server,
        path=webui.API_DECRYPT_PATH,
        payload={"path": str(container["qvt"]), "passphrase": PW},
    )
    assert res.status == 400


@pytest.mark.parametrize("payload", [{}, {"path": None}, {"path": 1}, {"path": ["x"]}])
def test_the_new_endpoints_need_a_string_path(server, payload):
    """`path` 缺席或非字串 → `400`(與 `/api/inspect` 同一條規矩)。"""
    for route in (webui.API_ENCRYPT_PATH, webui.API_DECRYPT_PATH):
        res = send(server, path=route, payload={**payload, "passphrase": PW})
        assert res.status == 400, route
        assert set(res.json()) == {"error"}


@pytest.mark.parametrize("route", [webui.API_ENCRYPT_PATH, webui.API_DECRYPT_PATH])
def test_the_new_endpoints_reject_a_directory_as_input(server, tmp_path, route):
    """輸入是目錄 → `400`(#21 的「擇一並固定」:目錄**存在**,不是 `404`)。"""
    res = send(
        server,
        path=route,
        payload={"path": str(tmp_path), "out_dir": str(tmp_path), "passphrase": PW},
    )
    assert res.status == 400
    assert res.json()["error"] == errors.MSG_INPUT_IS_DIR.format(path=tmp_path)


# ================================================================ 錯誤收斂(決策 8)

#: AC 的「一張 `(exc, kind, message)` 共用表」:每一列都要在**兩端**產生一致的
#: 輸出。`message` 寫死在這裡,不從 `classify` 讀——否則分類改掉訊息,這張表
#: 會跟著漂,而這條測試就什麼都沒守住。
CONVERGENCE: tuple[tuple[BaseException, str, str], ...] = (
    (QVaultFormatError("bad magic: not a .qvt container"), "format", "bad magic: not a .qvt container"),
    (QVaultVersionError("unknown .qvt version: 99"), "version", "unknown .qvt version: 99"),
    (QVaultDecryptError(AUTH_FAILED), "decrypt", AUTH_FAILED),
    (FileNotFoundError(2, "No such file or directory", "/nope/x"), "missing", "No such file or directory: /nope/x"),
    (FileExistsError("refusing to overwrite existing output: /tmp/x"), "exists", "refusing to overwrite existing output: /tmp/x"),
    (NotADirectoryError("output directory does not exist: /tmp/nope"), "not_dir", "output directory does not exist: /tmp/nope"),
    (PermissionError(13, "Permission denied", "/tmp/x"), "usage", "Permission denied: /tmp/x"),
    (RuntimeError("internals that must never be echoed"), "unexpected", "RuntimeError"),
)

CONVERGENCE_IDS = [kind for _, kind, _ in CONVERGENCE]


@pytest.mark.parametrize("exc,kind,message", CONVERGENCE, ids=CONVERGENCE_IDS)
def test_classify_returns_the_table_row(exc, kind, message):
    """AC:`classify` 回 `(kind, message)`,逐列。"""
    assert errors.classify(exc) == (kind, message)
    assert kind in errors.KINDS


@pytest.mark.parametrize("exc,kind,message", CONVERGENCE, ids=CONVERGENCE_IDS)
def test_the_cli_reports_the_table_message(tmp_path, fast_kdf, ask, capsys, exc, kind, message):
    """同一列:CLI 印的那一行(去前綴)就是表上的 `message`。

    未預期例外是唯一的例外:CLI 把它包成 `internal error (<型別名>)`,好讓使用者
    分得出「你的檔案有問題」與「我們有 bug」。包起來的內容仍然**只有型別名**。
    """
    src = make_file(tmp_path, "a.txt", 16)

    def boom(*args, **kwargs):
        raise exc

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cli, "encrypt_file", boom)
        line = cli_error(capsys, ask, ["encrypt", str(src)], PW, PW)

    expected = f"internal error ({message})" if kind == "unexpected" else message
    assert line == expected


@pytest.mark.parametrize("exc,kind,message", CONVERGENCE, ids=CONVERGENCE_IDS)
def test_the_api_reports_the_table_row(server, tmp_path, fast_kdf, monkeypatch, exc, kind, message):
    """同一列:API 的 `(status, error)` 由 `kind` 的對映表 + 表上的 `message` 決定。"""
    src = make_file(tmp_path, "a.txt", 16)

    def boom(*args, **kwargs):
        raise exc

    monkeypatch.setattr(webui, "encrypt_file", boom)
    res = api_encrypt(server, src, PW)

    assert res.status == EXPECTED_STATUS_BY_KIND[kind], (kind, res.text)
    assert res.json() == {"error": message}


def test_the_unexpected_row_never_echoes_the_exception_message(server, tmp_path, fast_kdf, capfd, monkeypatch):
    """AC:未預期例外 → `500`,body **只有型別名**(#21 行為不變)。"""
    marker = f"boom-{uuid.uuid4()}"

    def boom(*args, **kwargs):
        raise RuntimeError(f"{marker} {PW}")

    monkeypatch.setattr(webui, "encrypt_file", boom)
    src = make_file(tmp_path, "a.txt", 16)
    capfd.readouterr()

    res = api_encrypt(server, src, PW)
    assert res.status == 500
    assert res.json() == {"error": "RuntimeError"}

    output = "".join(capfd.readouterr())
    assert marker not in output
    assert PW not in output
    assert "Traceback" not in output


def test_the_status_table_covers_every_kind_and_nothing_else():
    """AC:`kind → status` 的對映表逐列等於 ADR-002 決策 8,且 `kind` 全集齊了。"""
    assert set(webui._STATUS_BY_KIND) == set(errors.KINDS)
    assert {k: int(v) for k, v in webui._STATUS_BY_KIND.items()} == EXPECTED_STATUS_BY_KIND


def _relative_imports_from(path: pathlib.Path, module: str) -> set[str]:
    """`from .<module> import a, b` 的那些名字。"""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.level and node.module == module:
            names |= {alias.name for alias in node.names}
    return names


def test_both_ends_import_the_same_classifier():
    """AC:`cli.py` 與 `webui.py` 都 import `errors.classify`(同一個符號)。

    行為測試只能證明「現在兩邊說一樣的話」;這條證明的是**結構上**只有一個
    分類器——有人哪天在其中一邊手寫一份 `if isinstance(...)`,這裡會紅。
    """
    assert "classify" in _relative_imports_from(CLI_PATH, "errors")
    assert "classify" in _relative_imports_from(WEBUI_PATH, "errors")
    assert errors.classify is cli.classify is webui.classify


def test_both_ends_take_the_three_usage_messages_from_errors():
    """AC 點名的那三句:兩端都從 `errors` 取常數,沒有人自己編。"""
    required = {"MSG_INPUT_MISSING", "MSG_REFUSE_OVERWRITE", "MSG_OUT_DIR_MISSING"}
    assert required <= _relative_imports_from(CLI_PATH, "errors")
    assert required <= _relative_imports_from(WEBUI_PATH, "errors")
    for name in required:
        assert "{path}" in getattr(errors, name)


def _string_literals(path: pathlib.Path) -> list[str]:
    """`path` 裡所有**非 docstring** 的字串字面值。"""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstrings.add(id(first.value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def _shared_message_fragments() -> list[str]:
    """`errors` 的每一句 `MSG_*` 去掉 `{path}` 之後那段可辨識的文字。"""
    fragments = []
    for name, value in vars(errors).items():
        if name.startswith("MSG_"):
            fragments.append(value.split("{")[0].strip() or value)
    assert len(fragments) >= 3
    return fragments


def test_webui_does_not_duplicate_the_cli_messages():
    """AC(主管層裁定後的字面):與 CLI 共用的訊息在 `webui.py` 一律取 `errors.MSG_*`。

    守的是「訊息兩本帳」的回頭路:有人圖方便在端點裡寫
    `f"input file does not exist: {p}"`,這條會紅。`webui` 自己那幾句
    (六道門、型別錯)不在此列——它們在 CLI 沒有對應情境,不可能漂。
    """
    fragments = _shared_message_fragments()
    for literal in _string_literals(WEBUI_PATH):
        for fragment in fragments:
            assert fragment not in literal, (fragment, literal)


def test_the_cli_has_no_message_literals_of_its_own():
    """同一條,另一端:`cli.py` 也不自己編那幾句(常數改一個字,兩端一起改)。"""
    fragments = _shared_message_fragments()
    for literal in _string_literals(CLI_PATH):
        for fragment in fragments:
            assert fragment not in literal, (fragment, literal)


def test_errors_module_knows_nothing_about_http():
    """主管層裁定:HTTP 狀態碼**不進** `errors.py`——它是 web 那一層的表達。

    `classify` 的簽章只回 `(kind, message)`;狀態碼的那張表住 `webui.py`。
    這條掃的是 AST(註解裡解釋分層是文件,不是相依)。
    """
    tree = ast.parse(ERRORS_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert "http" not in imported
    assert not imported, f"`errors.py` 是相依圖的葉子,不該 import 任何東西:{imported}"

    status_codes = {400, 401, 403, 404, 405, 409, 413, 415, 422, 500}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            assert node.value not in status_codes, ast.unparse(node)
    for literal in _string_literals(ERRORS_PATH):
        assert "HTTPStatus" not in literal


def test_classify_is_a_pure_function_of_the_exception():
    """同一個例外問兩次,答案相同;不同例外不互相汙染(純函式,無狀態)。"""
    first = FileNotFoundError(2, "No such file or directory", "/x")
    twin = FileNotFoundError(2, "No such file or directory", "/x")
    before = (first.args, first.filename)
    assert errors.classify(first) == errors.classify(twin)  # 只看例外本身,不看身分
    assert (first.args, first.filename) == before  # 不改動傳進來的例外
    exc = first
    assert errors.classify(RuntimeError("a")) == ("unexpected", "RuntimeError")
    assert errors.classify(exc)[0] == "missing"


# ================================================================ 不外洩(決策 5、9)


def test_the_sentinel_passphrase_never_escapes_any_of_the_four_paths(
    server, tmp_path, fast_kdf, capfd
):
    """AC:一把唯一的 sentinel 密碼走完四條路徑,它**一個 byte 都不出現**在:

    stdout / stderr(`capfd`,fd 層:伺服器跑在別的執行緒)、所有回應 body、
    `tmp_path` 樹下除 `.qvt` 之外的所有檔案內容、以及 `.qvt` 的 bytes。

    四條路徑:encrypt 成功、decrypt 成功、decrypt 錯密碼、encrypt 409。
    """
    sentinel = f"pw-{uuid.uuid4()}"
    src = make_file(tmp_path, "secret.bin", 300)
    dest = tmp_path / "out"
    dest.mkdir()
    other = make_file(tmp_path, "other.bin", 64)
    capfd.readouterr()

    responses = []
    # ① encrypt 成功
    enc = api_encrypt(server, src, sentinel)
    responses.append(enc)
    assert enc.status == 200, enc.text
    qvt = pathlib.Path(enc.json()["out"])

    # ② decrypt 成功
    dec = api_decrypt(server, qvt, dest, sentinel)
    responses.append(dec)
    assert dec.status == 200, dec.text

    # ③ decrypt 錯密碼:sentinel 是**送進去的那個**,容器卻是別的密碼加密的。
    foreign = tmp_path / "other.bin.qvt"
    vault.encrypt_file(other, foreign, PW)
    wrong = api_decrypt(server, foreign, dest, sentinel)
    responses.append(wrong)
    assert wrong.status == 422

    # ④ encrypt 409
    refused = api_encrypt(server, src, sentinel)
    responses.append(refused)
    assert refused.status == 409

    output = "".join(capfd.readouterr())
    assert sentinel not in output
    assert "passphrase" not in output.lower()
    assert "Traceback" not in output

    for res in responses:
        assert sentinel not in res.text
        assert sentinel not in str(res.headers)

    raw_sentinel = sentinel.encode("utf-8")
    for path in sorted(tmp_path.rglob("*")):
        if not path.is_file():
            continue
        blob = path.read_bytes()
        assert raw_sentinel not in blob, path
        if path.suffix != ".qvt":
            assert sentinel not in blob.decode("utf-8", "replace"), path


def test_error_bodies_echo_no_input_field_value_but_the_paths(server, tmp_path, fast_kdf):
    """AC(主管層裁定 3 的字面):錯誤回應不回顯**路徑類**欄位以外的輸入值。

    被回顯的只有**路徑類**欄位的值
    (`path` 與 `out_dir`),而且只出現在那幾句與 CLI **逐字相同**的訊息裡——
    `out_dir` 的那句(`output directory does not exist: …`)就是 CLI 自己也會
    印的那一行,訊息只有一本帳(`errors.MSG_OUT_DIR_MISSING`)就必然帶著它。
    除此之外**沒有任何**輸入值進得了 body:`passphrase` 的值、`force` 的值、
    未知的鍵與它們的值,一律不回顯;錯誤訊息只提欄位**名字**。
    """
    marker = f"leak-{uuid.uuid4().hex}"
    src = make_file(tmp_path, "a.txt", 16)
    nowhere = tmp_path / "nowhere"

    cases = [
        send(server, path=webui.API_ENCRYPT_PATH, payload={
            "path": str(src), "passphrase": marker, "force": marker}),
        send(server, path=webui.API_ENCRYPT_PATH, payload={
            "path": str(src), "passphrase": "", "nope": marker}),
        send(server, path=webui.API_ENCRYPT_PATH, payload={
            "path": str(tmp_path / "missing.txt"), "passphrase": marker}),
        send(server, path=webui.API_DECRYPT_PATH, payload={
            "path": str(src), "out_dir": str(nowhere), "passphrase": marker,
            "extra": marker}),
    ]
    for res in cases:
        assert 400 <= res.status < 500, res.text
        assert set(res.json()) == {"error"}
        assert marker not in res.text, res.text

    # `out_dir` 的值出現在最後那一列,而且**恰好**是共用常數那一句,不是回顯。
    assert cases[-1].json()["error"] == errors.MSG_OUT_DIR_MISSING.format(path=nowhere)


def test_the_access_log_of_the_new_endpoints_has_only_method_path_and_status(
    server, tmp_path, fast_kdf, capfd
):
    """決策 9:新端點的 access log 一樣只有 `<method> <path> <status>`。"""
    sentinel = f"pw-{uuid.uuid4()}"
    src = make_file(tmp_path, "a.txt", 32)
    dest = tmp_path / "out"
    dest.mkdir()
    capfd.readouterr()

    assert api_encrypt(server, src, sentinel).status == 200
    assert api_decrypt(server, tmp_path / "a.txt.qvt", dest, sentinel).status == 200
    assert api_encrypt(server, src, sentinel).status == 409

    output = "".join(capfd.readouterr())
    lines = [ln for ln in output.splitlines() if ln.strip()]

    # access log 的行**逐行**等於這三條(順序也算):這是「只記 method、path、
    # 狀態碼」的可觀察形式。比對前先濾掉不是 access log 的行(別的元件哪天在
    # stderr 上印一條 ResourceWarning,不該讓這條測試紅),但濾網是**格式**,
    # 不是內容——洩漏了 token 或 body 的那種行長得不像 access log,會被下面
    # 那三條斷言抓住。
    access_log = [ln for ln in lines if re.fullmatch(r"[A-Z]+ /\S* \d{3}", ln)]
    assert access_log == [
        "POST /api/encrypt 200",
        "POST /api/decrypt 200",
        "POST /api/encrypt 409",
    ]
    assert sentinel not in output
    assert "Authorization" not in output and "Bearer" not in output
    assert "Traceback" not in output


# ================================================================ 不可編碼的字元


#: 孤兒代理對(Windows argv / 某些輸入法產生得出來,JSON 也送得進來)。
#: 以 `chr(0xDC80)` 寫,不寫字面轉義:它在原始碼裡長得像個普通字串,
#: 而「長得不像」正是這類字元躲過審查的方式。
SURROGATE = chr(0xDC80)


def test_the_response_encoder_survives_an_unencodable_character():
    """`_dumps` 是唯一的回應編碼點,而不可編碼的字元**殺不掉它**。

    `"...".encode("utf-8")` 對孤兒代理對會拋 `UnicodeEncodeError`,而那個 encode
    發生在錯誤出口自己裡面——拋了就沒有人能回答,客戶端收到的是連線被關、
    連一個狀態碼都沒有(見下一條測試的實測記錄)。
    """
    body = webui._dumps({"error": f"input file does not exist: {SURROGATE}"})
    assert isinstance(body, bytes)
    assert json.loads(body.decode("utf-8"))["error"].endswith("?")
    assert SURROGATE not in body.decode("utf-8")


@pytest.mark.parametrize(
    "route,field",
    [
        (webui.API_INSPECT_PATH, "path"),
        (webui.API_ENCRYPT_PATH, "path"),
        (webui.API_DECRYPT_PATH, "path"),
        (webui.API_DECRYPT_PATH, "out_dir"),
    ],
)
def test_a_surrogate_in_a_path_field_is_a_clean_4xx(server, tmp_path, fast_kdf, route, field):
    """決策 14 的不變式:**任何**畸形輸入都收斂成 4xx,伺服器不倒。

    回歸測試:修前這三條路徑(含 #21 就在的 `/api/inspect`)會在錯誤出口裡拋
    `UnicodeEncodeError`,客戶端拿到的是 `RemoteDisconnected`——**沒有回應、
    沒有狀態碼**,比 `5xx` 更糟。`send()` 在那種情況下會直接拋,故這條測試
    光是跑完就已經是斷言的一部分。
    """
    src = make_file(tmp_path, "a.txt", 16)
    payload = {"path": str(src), "out_dir": str(tmp_path), "passphrase": PW}
    payload[field] = SURROGATE

    res = send(server, path=route, payload=payload)
    assert 400 <= res.status < 500, (route, field, res.status)
    assert set(res.json()) == {"error"}
    # 那個字元**不被回顯**——它可能是使用者密碼的一部分(鐵律 5)。
    assert SURROGATE not in res.text
    assert "dc80" not in res.text.lower()
    # 伺服器還活著(連線被 RST 掉的那種死法不會被上面的斷言抓到)。
    assert api_encrypt(server, src, PW).status == 200


# ================================================================ 形式與路由


def test_the_api_has_exactly_three_endpoints(server):
    """決策 7 的三條路徑,恰為這三條;其餘 `/api/*` 一律 `404`。

    #21 那條「#22 還沒來就不該有端點」的時序守門人已由人類側退役(刪除);
    本票交了端點之後,守的改成「**只有**這三個」。
    """
    assert set(webui._Handler._ENDPOINTS) == {
        "/api/inspect",
        "/api/encrypt",
        "/api/decrypt",
    }
    assert webui.API_ENCRYPT_PATH == "/api/encrypt"
    assert webui.API_DECRYPT_PATH == "/api/decrypt"
    for route in ("/api/nope", "/api/encrypt/x", "/api/", "/api/Encrypt"):
        assert send(server, path=route, payload={"path": "/x"}).status == 404


@pytest.mark.parametrize("route", [webui.API_ENCRYPT_PATH, webui.API_DECRYPT_PATH])
@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_the_new_endpoints_only_take_post(server, route, method):
    """門 2 對新端點同樣成立(六道門在路由**之前**跑完)。"""
    res = send(server, method, route, payload=None)
    assert res.status == 405


@pytest.mark.parametrize("route", [webui.API_ENCRYPT_PATH, webui.API_DECRYPT_PATH])
def test_the_new_endpoints_are_behind_the_token(server, tmp_path, fast_kdf, route):
    """門 6:沒 token 就打不進來,**而且什麼都沒發生**(檔案沒被動過)。"""
    src = make_file(tmp_path, "a.txt", 16)
    res = send(
        server,
        path=route,
        payload={"path": str(src), "out_dir": str(tmp_path), "passphrase": PW},
        token=None,
    )
    assert res.status == 401
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt"]


@pytest.mark.parametrize("route", [webui.API_ENCRYPT_PATH, webui.API_DECRYPT_PATH])
def test_the_new_endpoints_are_behind_the_host_check(server, tmp_path, fast_kdf, route):
    """門 1:`Host` 不符 → `403`,檔案一樣沒被動過(擋 DNS rebinding)。"""
    src = make_file(tmp_path, "a.txt", 16)
    res = send(
        server,
        path=route,
        payload={"path": str(src), "out_dir": str(tmp_path), "passphrase": PW},
        host="evil.example",
    )
    assert res.status == 403
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.txt"]


def test_several_requests_on_one_keep_alive_connection(server, tmp_path, fast_kdf):
    """一條 TCP 連線上連續打三個端點——瀏覽器就是這樣用的(#23 的頁面會重用連線)。

    這件事成立的理由是**每個回應都帶 `Content-Length`**、而且 body 在正常流程裡
    被讀乾淨;任一條漏掉,下一個請求就會被接到上一個的剩餘位元組上(request
    smuggling,或在好的情況下只是整個 UI 掛住)。`send()` 每次開一條新連線,
    故這條是唯一會發現那種回歸的測試。
    """
    sources = [make_file(tmp_path, f"f{index}.txt", 32 + index) for index in range(2)]
    dest = tmp_path / "out"
    dest.mkdir()

    conn = http.client.HTTPConnection(webui.LOOPBACK, server.port, timeout=10)

    def one(route: str, payload: dict) -> Response:
        body = json.dumps(payload).encode("utf-8")
        conn.putrequest("POST", route, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", server.expected_host)
        conn.putheader("Content-Type", webui.JSON_MEDIA_TYPE)
        conn.putheader("Authorization", f"Bearer {server.token}")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        raw = conn.getresponse()
        result = Response(raw.status, raw.getheaders(), raw.read())
        # `will_close` 為真就表示這條連線到此為止——成功回應不該宣告 close。
        assert raw.will_close is False, route
        assert result.header("Content-Length") is not None, route
        return result

    try:
        first = one(webui.API_ENCRYPT_PATH, {"path": str(sources[0]), "passphrase": PW})
        assert first.status == 200, first.text
        qvt = first.json()["out"]

        header = one(webui.API_INSPECT_PATH, {"path": qvt})
        assert header.status == 200
        assert header.json()["version"] == 1

        restored = one(
            webui.API_DECRYPT_PATH,
            {"path": qvt, "out_dir": str(dest), "passphrase": PW},
        )
        assert restored.status == 200
        assert pathlib.Path(restored.json()["out"]).read_bytes() == sources[0].read_bytes()

        second = one(webui.API_ENCRYPT_PATH, {"path": str(sources[1]), "passphrase": PW})
        assert second.status == 200
    finally:
        conn.close()


def test_the_suffix_is_the_same_one_the_cli_uses():
    """輸出檔名的規則只有一條(決策 2:「輸出與 CLI 同為同目錄 `<name>.qvt`」)。"""
    assert webui.QVT_SUFFIX == cli.QVT_SUFFIX == ".qvt"


def test_success_bodies_carry_only_the_written_path(server, tmp_path, fast_kdf):
    """決策 2:成功回應**只回**寫出的路徑——不回原始大小、不回任何中繼資料。"""
    src = make_file(tmp_path, "a.txt", 200)
    enc = api_encrypt(server, src, PW)
    assert set(enc.json()) == {"out"} == set(webui.RESULT_KEYS)

    dest = tmp_path / "out"
    dest.mkdir()
    dec = api_decrypt(server, enc.json()["out"], dest, PW)
    assert set(dec.json()) == {"out"}
    # 200 的 body 只有一個鍵,故「原始大小」這個決策 9 保護的中繼資料不在裡面。
    assert json.loads(dec.body)["out"] == str(dest / "a.txt")


# ================================================================ #30 獨立複審補洞(人類側)


@pytest.mark.parametrize("op", ["encrypt", "decrypt"])
def test_two_concurrent_writes_to_the_same_target_cannot_both_win(
    server, tmp_path, fast_kdf, monkeypatch, op
):
    """複審 M5:同一個目標的兩個並行請求,**只能有一個** `200`,另一個 `409`。

    `vault` 自己是「先查存在 → 整檔加解密 → `os.replace`」,而 `os.replace` 會
    覆寫:兩個請求若都在對方 replace 之前查過「不存在」,就都會回 `200`——
    encrypt 的檔案只解得開後寫的那一把密碼,decrypt 的明文互蓋。

    `os.replace` 在目標上設一個 barrier:兩個請求都走到 replace 才同時放行。
    沒有序列化時兩邊都會到,兩個 `200`(紅);有序列化時第二個進不了臨界區,
    先到的那個在 barrier 上等到逾時後照常 replace,第二個進來時目標已存在 → `409`。
    """
    barrier = threading.Barrier(2, timeout=2)
    real_replace = os.replace
    if op == "encrypt":
        src = make_file(tmp_path, "same.bin", 256)
        target_name = "same.bin.qvt"
    else:
        src = make_file(tmp_path, "same.bin", 256)
        qvt = tmp_path / "same.bin.qvt"
        vault.encrypt_file(src, qvt, PW)
        dest = tmp_path / "out"
        dest.mkdir()
        target_name = "same.bin"

    def rendezvous(a, b, *args, **kwargs):
        if os.path.basename(os.fspath(b)) == target_name:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
        return real_replace(a, b, *args, **kwargs)

    monkeypatch.setattr(vault.os, "replace", rendezvous)
    results: dict[int, Response] = {}

    def worker(index: int) -> None:
        if op == "encrypt":
            results[index] = api_encrypt(server, src, f"{PW}-{index}")
        else:
            results[index] = api_decrypt(server, qvt, dest, PW)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    statuses = sorted(res.status for res in results.values())
    assert statuses == [200, 409], [(r.status, r.text) for r in results.values()]
    if op == "encrypt":
        winner = next(i for i, r in results.items() if r.status == 200)
        back = tmp_path / "back"
        back.mkdir()
        restored = vault.decrypt_file(tmp_path / target_name, back, f"{PW}-{winner}")
        assert restored.read_bytes() == src.read_bytes()


def test_forced_decrypt_that_fails_keeps_the_original(server, container):
    """複審 M4:`force=True` 而解密失敗(錯密碼 / 竄改)→ `422`,既有檔原封不動。"""
    dest = container["dest"]
    target = dest / "payload.bin"
    target.write_bytes(b"keep")
    raw = bytearray(container["qvt"].read_bytes())
    raw[-1] ^= 0x01
    bad = dest.parent / "bad.qvt"
    bad.write_bytes(bytes(raw))
    for path, pw in ((container["qvt"], WRONG_PW), (bad, PW)):
        res = api_decrypt(server, path, dest, pw, force=True)
        assert res.status == 422, res.text
        assert target.read_bytes() == b"keep"
        assert sorted(os.listdir(dest)) == ["payload.bin"]


def test_tamper_in_a_later_data_chunk_is_422_and_leaves_nothing(server, tmp_path, fast_kdf):
    """複審 L7:≥ 3 個資料塊的容器,在**非首塊**改一個 byte → `422`,訊息與錯密碼
    完全相同,`out_dir` 裡什麼都沒留下(前面幾塊已驗過也不能先寫出去)。"""
    src = make_file(tmp_path, "big.bin", 3 * 65536 + 1)
    qvt = tmp_path / "big.bin.qvt"
    vault.encrypt_file(src, qvt, PW)
    raw = bytearray(qvt.read_bytes())
    raw[len(raw) // 2] ^= 0x01  # 第二個資料塊的中段
    qvt.write_bytes(bytes(raw))
    dest = tmp_path / "out"
    dest.mkdir()
    wrong = api_decrypt(server, qvt, dest, WRONG_PW)
    tampered = api_decrypt(server, qvt, dest, PW)
    assert tampered.status == wrong.status == 422
    assert tampered.body == wrong.body
    assert os.listdir(dest) == []


def test_decrypt_with_an_empty_out_dir_is_400(server, container, monkeypatch, tmp_path):
    """複審 L4:`out_dir: ""` 在 `Path` 裡等於 `.`——UI 看不見伺服器的 cwd,明文
    會落在一個使用者不知道的地方。CLI 的 `.` 是看得見的預設值;API 要求明說。"""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    res = api_decrypt(server, container["qvt"], "", PW)
    assert res.status == 400, res.text
    assert "out_dir" in res.json()["error"]
    assert os.listdir(cwd) == []


def test_decrypt_checks_out_dir_before_the_passphrase_like_the_cli(
    server, container, tmp_path, ask, capsys
):
    """複審 L8:`out_dir` 不存在**且**密碼為空 → 回的是 out_dir 那一句(CLI 先查
    out_dir 才問密碼),兩端對同一個錯誤組合說同一句話。"""
    missing = tmp_path / "nope"
    res = api_decrypt(server, container["qvt"], missing, "")
    assert res.status == 400
    assert res.json()["error"] == MSG_OUT_DIR_MISSING.format(path=missing)


def test_encrypt_checks_the_target_before_the_passphrase_like_the_cli(
    server, tmp_path, fast_kdf, ask, capsys
):
    """複審第 2 輪 N2:目標已存在(無 force)**且**密碼為空 → 回的是 409 那一句
    (CLI 先查 `--force` 與目標才問密碼),兩端對同一個錯誤組合說同一句話。"""
    src = make_file(tmp_path, "a.txt", 10)
    assert api_encrypt(server, src, PW).status == 200
    res = api_encrypt(server, src, "")
    assert res.status == 409, res.text
    assert res.json()["error"] == errors.MSG_REFUSE_OVERWRITE.format(path=tmp_path / "a.txt.qvt")
