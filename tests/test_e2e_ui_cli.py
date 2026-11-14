"""V5:UI 路徑與 CLI 路徑**互解**(#25,ADR-002 決策 13、14)。

這一檔是整個專案的端到端裁判之一:它不問「每一層自己對不對」(那是
`tests/test_vault.py` / `tests/test_cli.py` / `tests/test_webui_crypto.py` 的事),
只問**兩條路徑說的是不是同一件事**:

1. API encrypt 的容器,CLI 解得開;CLI encrypt 的容器,API 解得開(雙向互解)。
2. 同一個 golden 向量,API decrypt / CLI decrypt / `vault.decrypt_file` 三路還原的
   bytes 完全相同(三路同值)。
3. 同一個容器,`cli.main(["inspect", …])` 與 `POST /api/inspect` **逐欄相等**。

差異測試的價值在**不共用實作**:兩邊各自組輸出路徑、各自讀密碼、各自做白名單。
任何一邊偷偷漂掉(換後綴、換 KDF 參數、多吐一欄),這裡就紅——而這是上面那三個
單層測試檔**結構上看不到**的一類 bug。

## 為什麼不吃 `fast_kdf`

`tests/test_cli.py` / `tests/test_vault.py` 的 `fast_kdf` 把 `kek._scrypt` 換成便宜
派生,讓單層測試不必燒 80ms。本檔刻意**不**這麼做:這裡要證的是「兩條路徑可以互
解彼此真正寫出來的檔」,而「真正」包含真 scrypt(15/8/1)。全檔總共 8 次派生,
約 0.7 秒,值得。

## getpass 的答案由本檔自己的夾具餵

`cli.main(["decrypt", …])` 是 in-process 跑的,所以 `getpass.getpass` 要被接管。
`tests/test_cli.py` 有一個同樣用途的 `ask` 夾具,但**共同範圍條款禁止修改既有測試**
(裁判凍結),而測試檔也不得 import 另一個測試檔(AGENTS.md 的 gate 規則:那是
F401 + F811)。於是本檔**複寫一份**最小的 `ask`——三行的假 `getpass`,不搬動
`tests/test_cli.py` 的任何一個 byte。
"""

from __future__ import annotations

import pathlib
import random

import pytest

from qvault_core import cli, vault, webui
from tests.webui_client import send

PW = "differential test passphrase"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"
GOLDEN_PW = "correct horse"

#: AC 寫死的大小:跨 4 個 65,536 byte 的塊,而且最後一塊**不滿**(200001 = 3×65536
#: + 3393)。整數塊與非整數塊是 STREAM 式分塊 AEAD 兩條不同的收尾路徑。
SIZE = 200_001

#: ADR-001 的正規 KDF 參數與塊大小(AC 點名要在 `inspect` 的輸出裡看到這四個數)。
EXPECTED_KDF_LOG2N = 15
EXPECTED_KDF_R = 8
EXPECTED_KDF_P = 1
EXPECTED_CHUNK_SIZE = 65536


class _Prompter:
    """假的 `getpass`:依序吐出測試預先餵的答案,多問一次就 `AssertionError`。"""

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
    """接管 `getpass.getpass`;測試用 `ask.feed(...)` 排隊答案。"""
    prompter = _Prompter()
    monkeypatch.setattr(cli.getpass, "getpass", prompter)
    return prompter


@pytest.fixture
def payload_file(tmp_path):
    """`x.bin`:200,001 bytes,固定 seed 的亂數(重現得出來,但逐位置相異)。"""
    src = tmp_path / "x.bin"
    src.write_bytes(random.Random(25).randbytes(SIZE))
    return src


def api_encrypt(server, path: pathlib.Path, passphrase: str = PW) -> pathlib.Path:
    res = send(
        server,
        path=webui.API_ENCRYPT_PATH,
        payload={"path": str(path), "passphrase": passphrase},
        token=f"Bearer {server.token}",
        host=server.expected_host,
    )
    assert res.status == 200, (res.status, res.text)
    assert sorted(res.json()) == sorted(webui.RESULT_KEYS)
    return pathlib.Path(res.json()["out"])


def api_decrypt(
    server, path: pathlib.Path, out_dir: pathlib.Path, passphrase: str = PW
) -> pathlib.Path:
    res = send(
        server,
        path=webui.API_DECRYPT_PATH,
        payload={
            "path": str(path),
            "out_dir": str(out_dir),
            "passphrase": passphrase,
        },
        token=f"Bearer {server.token}",
        host=server.expected_host,
    )
    assert res.status == 200, (res.status, res.text)
    return pathlib.Path(res.json()["out"])


def api_inspect(server, path: pathlib.Path) -> dict:
    res = send(
        server,
        path=webui.API_INSPECT_PATH,
        payload={"path": str(path)},
        token=f"Bearer {server.token}",
        host=server.expected_host,
    )
    assert res.status == 200, (res.status, res.text)
    return res.json()


def cli_encrypt(ask, path: pathlib.Path, passphrase: str = PW) -> pathlib.Path:
    ask.feed(passphrase, passphrase)
    assert cli.main(["encrypt", str(path)]) == 0
    out = path.with_name(path.name + webui.QVT_SUFFIX)
    assert out.is_file(), f"CLI encrypt 沒有產生 {out}"
    return out


def cli_decrypt(
    ask, path: pathlib.Path, out_dir: pathlib.Path, passphrase: str = PW
) -> pathlib.Path:
    before = {p.name for p in out_dir.iterdir()}
    ask.feed(passphrase)
    assert cli.main(["decrypt", str(path), "--out-dir", str(out_dir)]) == 0
    written = {p.name for p in out_dir.iterdir()} - before
    assert len(written) == 1, f"CLI decrypt 寫出的檔不只一個:{written}"
    return out_dir / written.pop()


# ================================================================ 雙向互解


def test_api_and_cli_decrypt_each_others_containers(server, tmp_path, ask, payload_file):
    """AC:① API encrypt → CLI decrypt、② CLI encrypt → API decrypt,兩邊都還原 `x.bin`。

    兩個方向各自在自己的目錄裡跑(`encrypt` 的輸出路徑是「同目錄、同名加
    `.qvt`」,兩邊同規則,放一起會互撞),最後把兩份還原的 bytes 與原檔三方比對。

    順便釘住一件事:兩個容器的 **bytes 不相等**。salt 與 DEK 每次都是新的隨機值,
    所以「互解」不可能是因為兩邊湊巧產出同一個檔——它是真的各解各的。
    """
    original = payload_file.read_bytes()
    assert len(original) == SIZE

    # ① API encrypt → CLI decrypt(in-process `cli.main`,getpass 由本檔的夾具餵)
    api_dir = tmp_path / "api_made"
    api_dir.mkdir()
    api_src = api_dir / payload_file.name
    api_src.write_bytes(original)
    api_qvt = api_encrypt(server, api_src)
    assert api_qvt == api_src.with_name(api_src.name + webui.QVT_SUFFIX)
    restored_by_cli_dir = tmp_path / "restored_by_cli"
    restored_by_cli_dir.mkdir()
    restored_by_cli = cli_decrypt(ask, api_qvt, restored_by_cli_dir)

    # ② CLI encrypt → API decrypt
    cli_dir = tmp_path / "cli_made"
    cli_dir.mkdir()
    cli_src = cli_dir / payload_file.name
    cli_src.write_bytes(original)
    cli_qvt = cli_encrypt(ask, cli_src)
    restored_by_api_dir = tmp_path / "restored_by_api"
    restored_by_api_dir.mkdir()
    restored_by_api = api_decrypt(server, cli_qvt, restored_by_api_dir)

    # Then:兩條路徑還原的 bytes 都等於 `x.bin`。
    assert restored_by_cli.read_bytes() == original
    assert restored_by_api.read_bytes() == original
    # 檔名也一起還原(名字加密進 chunk 0,ADR-001 決策 17)。
    assert restored_by_cli.name == payload_file.name
    assert restored_by_api.name == payload_file.name
    # 原檔沒被動到,而兩個容器確實是兩個不同的檔。
    assert api_src.read_bytes() == original
    assert cli_src.read_bytes() == original
    assert api_qvt.read_bytes() != cli_qvt.read_bytes()


def test_the_two_paths_agree_on_the_container_name(server, tmp_path, ask):
    """兩邊的輸出路徑規則逐字相同:同目錄、**加**(不是取代)`.qvt`。

    這條不碰密碼學,只釘命名——`QVT_SUFFIX` 哪一天在一邊變成「取代副檔名」,
    上面那條互解測試會以一個難讀的 `FileNotFoundError` 失敗,這條會直說是名字漂了。
    """
    both = {}
    for label, directory in (("api", tmp_path / "a"), ("cli", tmp_path / "b")):
        directory.mkdir()
        src = directory / "x.bin"
        src.write_bytes(b"x")
        out = (
            api_encrypt(server, src)
            if label == "api"
            else cli_encrypt(ask, src)
        )
        both[label] = out.relative_to(directory)
    assert both["api"] == both["cli"] == pathlib.Path("x.bin.qvt")


# ================================================================ golden 三路同值


def test_golden_restores_identically_through_three_paths(server, tmp_path, ask):
    """AC:`golden_v1.qvt` 經 API decrypt / CLI decrypt / `vault.decrypt_file` 三路還原同值。

    三路**各自**一個 out_dir:`decrypt_file` 的還原檔名來自 chunk 0,三路會寫出
    同一個名字,共用目錄會撞上「目標已存在」。比的是 bytes 與檔名兩樣。

    走真 scrypt:golden 向量就是用正規參數封的,換掉 KDF 等於不在測它。
    """
    assert GOLDEN.is_file(), f"golden 向量不在:{GOLDEN}"
    dirs = {}
    for name in ("via_api", "via_cli", "via_lib"):
        dirs[name] = tmp_path / name
        dirs[name].mkdir()

    via_api = api_decrypt(server, GOLDEN, dirs["via_api"], GOLDEN_PW)
    via_cli = cli_decrypt(ask, GOLDEN, dirs["via_cli"], GOLDEN_PW)
    via_lib = vault.decrypt_file(GOLDEN, dirs["via_lib"], GOLDEN_PW)

    names = {via_api.name, via_cli.name, via_lib.name}
    assert len(names) == 1, f"三路還原出不同的檔名:{names}"
    blobs = {p.read_bytes() for p in (via_api, via_cli, via_lib)}
    assert len(blobs) == 1, "三路還原的 bytes 不完全相同"
    # 三路都真的寫出了東西(`len(blobs) == 1` 對三個空檔也成立)。
    assert via_api.is_file() and via_cli.is_file() and via_lib.is_file()
    # golden 自己沒被動到(decrypt 只讀輸入)。
    assert GOLDEN.is_file()


# ================================================================ inspect 逐欄相等


def cli_inspect_rows(path: pathlib.Path, capsys) -> dict[str, str]:
    """跑 `cli.main(["inspect", …])` 並把它印出來的對齊表解回 `{標籤: 值}`。"""
    capsys.readouterr()
    assert cli.main(["inspect", str(path)]) == 0
    captured = capsys.readouterr()
    assert captured.err == "", captured.err
    rows = {}
    for line in captured.out.splitlines():
        if not line.strip():
            continue
        label, _, value = line.partition(":")
        rows[label.strip()] = value.strip()
    return rows


def test_inspect_agrees_field_by_field_between_the_cli_and_the_api(
    server, tmp_path, capsys
):
    """AC:同一個 API encrypt 產出的 `.qvt`,CLI 與 API 的 `inspect` 逐欄相等。

    兩邊的白名單是**兩張表**(決策 13 不准 `webui` import `cli`),而且形狀刻意
    不同:CLI 印給人看,所以 id 與名字黏成一欄(`kdf_id: 1 (scrypt)`);API 回給
    JSON 吃,所以拆成 `kdf_id: 1` + `kdf_name: "scrypt"`。「逐欄相等」因此是
    **折疊之後**逐欄相等——這個折疊規則寫在下面這張表裡,它同時也是「兩邊各有
    哪些欄」的那份帳:任一邊多一欄、少一欄、或名字漂一個字,`assert` 就紅。
    """
    src = tmp_path / "x.bin"
    src.write_bytes(b"inspect me" * 10)
    qvt = api_encrypt(server, src)

    api = api_inspect(server, qvt)
    rows = cli_inspect_rows(qvt, capsys)

    # API 回的鍵恰為宣告的那些(模組常數自己的帳,順手一起釘)。
    assert sorted(api) == sorted(webui.INSPECT_KEYS)

    #: CLI 的標籤 → 「同一件事在 API 的回應裡怎麼表達」。
    folded = {
        "version": str(api["version"]),
        "kdf_id": f"{api['kdf_id']} ({api['kdf_name']})",
        "aead_id": f"{api['aead_id']} ({api['aead_name']})",
        "kem_id": f"{api['kem_id']} ({api['kem_name']})",
        "kdf_log2n": str(api["kdf_log2n"]),
        "kdf_r": str(api["kdf_r"]),
        "kdf_p": str(api["kdf_p"]),
        "chunk_size": str(api["chunk_size"]),
        "file_size": f"{api['file_size']} bytes",
    }
    assert rows == folded

    # 兩邊的欄位集合互相覆蓋:CLI 的每一欄都在表裡,API 的每一欄都被表用到。
    assert set(rows) == set(folded)
    used = {"version", "kdf_id", "kdf_name", "aead_id", "aead_name", "kem_id",
            "kem_name", "kdf_log2n", "kdf_r", "kdf_p", "chunk_size", "file_size"}
    assert set(api) == used

    # AC 點名的四個數字(兩邊都要看得到同一組)。
    assert api["kdf_log2n"] == EXPECTED_KDF_LOG2N
    assert api["kdf_r"] == EXPECTED_KDF_R
    assert api["kdf_p"] == EXPECTED_KDF_P
    assert api["chunk_size"] == EXPECTED_CHUNK_SIZE
    assert rows["kdf_log2n"] == str(EXPECTED_KDF_LOG2N)
    assert rows["kdf_r"] == str(EXPECTED_KDF_R)
    assert rows["kdf_p"] == str(EXPECTED_KDF_P)
    assert rows["chunk_size"] == str(EXPECTED_CHUNK_SIZE)
    assert api["file_size"] == qvt.stat().st_size


def test_inspect_agrees_on_the_golden_vector_too(server, capsys):
    """同一條,換成 golden:兩邊對一個**不是本機剛產出**的容器也說同一句話。

    `golden_v1.qvt` 是跨實作契約(ADR-001 的測試向量),它的 header 不會隨
    `encrypt` 的隨機數改變,所以這條的期望值寫得出常數——真正的回歸守門。
    """
    api = api_inspect(server, GOLDEN)
    rows = cli_inspect_rows(GOLDEN, capsys)
    assert rows == {
        "version": "1",
        "kdf_id": "1 (scrypt)",
        "aead_id": "1 (AES-256-GCM)",
        "kem_id": "1 (scrypt-KEK)",
        "kdf_log2n": str(EXPECTED_KDF_LOG2N),
        "kdf_r": str(EXPECTED_KDF_R),
        "kdf_p": str(EXPECTED_KDF_P),
        "chunk_size": str(EXPECTED_CHUNK_SIZE),
        "file_size": f"{GOLDEN.stat().st_size} bytes",
    }
    assert api == {
        "version": 1,
        "kdf_id": 1,
        "kdf_name": "scrypt",
        "aead_id": 1,
        "aead_name": "AES-256-GCM",
        "kem_id": 1,
        "kem_name": "scrypt-KEK",
        "kdf_log2n": EXPECTED_KDF_LOG2N,
        "kdf_r": EXPECTED_KDF_R,
        "kdf_p": EXPECTED_KDF_P,
        "chunk_size": EXPECTED_CHUNK_SIZE,
        "file_size": GOLDEN.stat().st_size,
    }
