"""`qvault_core/webui.py` 的測試(#21;設計見 `docs/adr/ADR-002-local-web-ui.md`)。

一律以 **`http.client`** 打真 socket(AC「測試形式」):沒有第三方 client、沒有
`requests`、也不走 `WSGI` 之類的假管線——要測的東西有一半在 HTTP 層本身
(`Host` 標頭、`Content-Length`、狀態碼、回應標頭),用假管線就等於不測。

伺服器一律 `port=0`(由 OS 配埠,平行跑不撞)、起在 `threading.Thread(daemon=True)`
裡、每個測試結束 `shutdown()`(見 `server` 夾具)。

三類測試(AGENTS.md 鐵律 4)在 HTTP 層的對應:
  round-trip → `test_inspect_*`(golden 向量進去、白名單欄位出來,與 CLI 逐欄對)
  tamper     → `test_inspect_rejects_*`(壞 magic / 截斷 / 非容器 → 422,訊息同 CLI)
  邊界       → 六道門各自的拒絕碼、65,537 byte body、空 body、非物件 JSON、
               缺檔 / 目錄、未預期例外 → 500
"""

from __future__ import annotations

import ast
import inspect as inspect_mod
import json
import pathlib
import random
import re
import socket
import uuid

import pytest

from qvault_core import cli, webui
from qvault_core.container import FIELD_LAYOUT, HEADER_SIZE_KEM1
from tests.webui_client import _DEFAULT, send

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"
WEBUI_PATH = REPO_ROOT / "qvault_core" / "webui.py"
WEBUI_SOURCE = WEBUI_PATH.read_text(encoding="utf-8")

#: [M7] 一個 byte 都不准出現在 `/api/inspect` 回應裡的 header 欄位。
SECRET_FIELDS = ("salt", "nonce_prefix", "wrapped_dek")

#: AC「JSON 鍵恰為」那一行,寫死在測試裡(不從 `webui` 讀,否則表被改掉這裡
#: 會跟著漂)。
EXPECTED_INSPECT_KEYS = {
    "version",
    "kdf_id",
    "kdf_name",
    "aead_id",
    "aead_name",
    "kem_id",
    "kem_name",
    "kdf_log2n",
    "kdf_r",
    "kdf_p",
    "chunk_size",
    "file_size",
}

# ---------------------------------------------------------------- 夾具與工具

def cli_inspect_rows(capsys) -> dict[str, str]:
    """`cli.main(["inspect", golden])` 印出來的「標籤 → 值」。"""
    capsys.readouterr()
    assert cli.main(["inspect", str(GOLDEN)]) == 0
    rows = {}
    for line in capsys.readouterr().out.splitlines():
        if not line.strip():
            continue
        label, _, value = line.partition(":")
        rows[label.strip()] = value.strip()
    return rows


def cli_error(capsys, path) -> str:
    """CLI 對同一個檔案印出的那一行,**去掉 `qvault: ` 前綴**。"""
    capsys.readouterr()
    assert cli.main(["inspect", str(path)]) != 0
    err = capsys.readouterr().err.strip()
    assert err.startswith("qvault: "), err
    return err[len("qvault: ") :]


def field_bytes(raw: bytes, name: str) -> bytes:
    for field, offset, size in FIELD_LAYOUT:
        if field == name:
            return raw[offset : offset + size]
    raise AssertionError(f"FIELD_LAYOUT 沒有 {name}")


def hex_windows(raw: bytes, width: int = 4) -> set[str]:
    """`raw` 的所有 ≥`width` 位元組連續片段的 hex(含大小寫)——「任一段」的意思。

    與 `tests/test_cli.py` 的同名工具同一招:hex 截斷也不行,wrapped DEK 的
    任何一段進了瀏覽器或工單,攻擊者不需要那個檔案就能離線爆密碼。
    """
    text = raw.hex()
    windows = set()
    for start in range(0, len(text) - 2 * width + 1, 2):
        for end in range(start + 2 * width, len(text) + 1, 2):
            windows.add(text[start:end])
    return windows | {w.upper() for w in windows}


def garbage_file(tmp_path, name: str = "not-a-container.bin") -> pathlib.Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04this is definitely not a .qvt container" * 4)
    return path


# ================================================================ 模組與啟動


def test_make_server_returns_a_bound_loopback_server(server):
    """AC:`.port`(≠0)、`.token`、`.url`、`serve_forever` / `shutdown`。"""
    import http.server as http_server

    assert isinstance(server, webui.WebUIServer)
    assert isinstance(server, http_server.ThreadingHTTPServer)
    assert isinstance(server.port, int) and server.port != 0
    assert server.server_address[0] == webui.LOOPBACK == "127.0.0.1"
    assert server.server_address[1] == server.port
    assert server.url == f"http://127.0.0.1:{server.port}/#{server.token}"
    assert callable(server.serve_forever) and callable(server.shutdown)


def test_token_is_a_fresh_urlsafe_32_byte_secret():
    """AC:`.token` 是 `secrets.token_urlsafe(32)` 的值——每次啟動一把新的。"""
    assert "secrets.token_urlsafe(32)" in WEBUI_SOURCE
    first, second = webui.make_server(), webui.make_server()
    try:
        for srv in (first, second):
            assert len(srv.token) == 43  # 32 bytes 的 urlsafe base64
            assert re.fullmatch(r"[A-Za-z0-9_-]+", srv.token)
        assert first.token != second.token
        assert first.port != second.port
    finally:
        first.server_close()
        second.server_close()


def test_make_server_has_no_way_to_change_the_bind_address():
    """AC(決策 4):簽章只有 `port`——「不能改綁定位址」在型別層面成立。"""
    params = inspect_mod.signature(webui.make_server).parameters
    assert list(params) == ["port"]
    assert params["port"].default == 0
    # 建構子本身也不給後門(`make_server` 只是薄封裝,繞過它一樣綁 loopback)。
    ctor = inspect_mod.signature(webui.WebUIServer.__init__).parameters
    assert [p for p in ctor if p != "self"] == ["port"]
    for banned in ("host", "bind", "address", "interface", "iface"):
        assert banned not in params
        assert banned not in ctor


def test_bind_address_is_a_literal_not_a_setting():
    """位址是模組常數,不從環境 / 參數來(決策 4 的「不是靠文件」)。"""
    tree = ast.parse(WEBUI_SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert ast.unparse(node) not in ("os.environ", "os.getenv")
        if isinstance(node, ast.Call):
            assert ast.unparse(node.func) not in ("os.getenv", "os.environ.get")
    # 字串常數裡只有 `127.0.0.1` 這一個位址,沒有 `0.0.0.0` / `::1` / 空字串綁法。
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for banned in ("0.0.0.0", "::1", "::", "localhost", "[::]"):
        assert banned not in literals, banned
    assert "127.0.0.1" in literals
    assert "AF_INET6" not in WEBUI_SOURCE


# ================================================================ 鑑權(決策 5)


def test_missing_authorization_header_is_401(server):
    """AC:無 `Authorization` → `401`,body 為 JSON `{"error": ...}`。"""
    res = send(server, payload={"path": str(GOLDEN)}, token=None)
    assert res.status == 401
    assert set(res.json()) == {"error"}
    assert isinstance(res.json()["error"], str)
    assert res.header("Content-Type").startswith("application/json")


def test_wrong_token_of_the_same_length_is_401(server):
    """AC:同長度、只差一個字元的 token → `401`;正確的 → 不是 401。"""
    real = server.token
    flipped = ("a" if real[0] != "a" else "b") + real[1:]
    assert len(flipped) == len(real) and flipped != real

    res = send(server, payload={"path": str(GOLDEN)}, token=f"Bearer {flipped}")
    assert res.status == 401

    ok = send(server, payload={"path": str(GOLDEN)})
    assert ok.status != 401
    assert ok.status == 200


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "bearer {token}",  # scheme 大小寫不含糊:照 RFC 的字面要求
        "Basic {token}",
        "{token}",  # 沒有 scheme
        "Bearer {token} extra",
    ],
)
def test_malformed_authorization_headers_are_401(server, header):
    res = send(
        server,
        payload={"path": str(GOLDEN)},
        token=header.format(token=server.token),
    )
    assert res.status == 401


def test_token_comparison_goes_through_compare_digest():
    """AC:token 比對經 `hmac.compare_digest`,原始碼裡沒有任何 `token` 的 `==`。

    `==` 一比到不同的 byte 就回來,而這個伺服器就在攻擊者的瀏覽器打得到的地方:
    可量測的時間差會把 token 一個 byte 一個 byte 地交出去。
    """
    assert "compare_digest" in WEBUI_SOURCE
    assert "== token" not in WEBUI_SOURCE
    assert "token ==" not in WEBUI_SOURCE

    tree = ast.parse(WEBUI_SOURCE)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for sub in ast.walk(node):
            named = (
                sub.id
                if isinstance(sub, ast.Name)
                else sub.attr if isinstance(sub, ast.Attribute) else ""
            )
            if "token" in named.lower():
                offenders.append(ast.unparse(node))
    assert offenders == [], offenders


# ================================================================ Host / Origin / 形式


@pytest.mark.parametrize("method, path", [("GET", "/"), ("POST", webui.API_INSPECT_PATH)])
@pytest.mark.parametrize(
    "bad_host",
    ["localhost:{port}", "evil.example:{port}", "127.0.0.1", "", "[::1]:{port}",
     "127.0.0.1:{port}.evil.example", "127.0.0.2:{port}"],
)
def test_unexpected_host_is_403_for_any_request(server, method, path, bad_host):
    """AC(決策 6):`Host` 不是 `127.0.0.1:<port>` → `403`,**任何**請求都一樣。

    `localhost` 也不收:它解析成誰由 OS 的 hosts 檔決定(DNS rebinding 的入口)。
    """
    res = send(
        server,
        method,
        path,
        payload={"path": str(GOLDEN)} if method == "POST" else _DEFAULT,
        host=bad_host.format(port=server.port),
    )
    assert res.status == 403
    assert set(res.json()) == {"error"}


def test_absent_host_header_is_403(server):
    res = send(server, "GET", "/", host=None)
    assert res.status == 403


@pytest.mark.parametrize(
    "bad_origin",
    [
        "http://evil.example",
        "null",
        "http://localhost:{port}",
        "https://127.0.0.1:{port}",
        "http://127.0.0.1",
        "http://127.0.0.1:{port}/",
        "http://127.0.0.1:{port}.evil.example",
    ],
)
def test_cross_origin_post_is_403(server, bad_origin):
    """AC:`Origin` 存在且不等於 `http://127.0.0.1:<port>` → `403`(即使 token 正確)。"""
    res = send(
        server,
        payload={"path": str(GOLDEN)},
        origin=bad_origin.format(port=server.port),
    )
    assert res.status == 403


def test_matching_origin_is_allowed(server):
    res = send(server, payload={"path": str(GOLDEN)}, origin=server.expected_origin)
    assert res.status == 200


def test_absent_origin_is_allowed(server):
    """缺席代表非瀏覽器客戶端(瀏覽器對跨來源 POST 一定送 Origin)→ 放行。"""
    res = send(server, payload={"path": str(GOLDEN)}, origin=None)
    assert res.status == 200


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_api_only_takes_post(server, method):
    """AC:`GET /api/inspect` → `405`(其餘方法同理)。"""
    res = send(server, method, webui.API_INSPECT_PATH)
    assert res.status == 405


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "text/plain; charset=utf-8", "application/x-www-form-urlencoded",
     "multipart/form-data; boundary=x", "application/jsonx", ""],
)
def test_non_json_content_type_is_415(server, content_type):
    """AC:`Content-Type` 不是 `application/json`(或缺)→ `415`。

    表單打得出來的三種型別(`text/plain` / urlencoded / multipart)正是無 JS 的
    跨來源 CSRF 唯一能用的型別,擋掉它們就擋掉了那條路。
    """
    res = send(server, payload={"path": str(GOLDEN)}, content_type=content_type)
    assert res.status == 415


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8",
                                          "APPLICATION/JSON", " application/json "])
def test_json_content_type_variants_are_accepted(server, content_type):
    res = send(server, payload={"path": str(GOLDEN)}, content_type=content_type)
    assert res.status == 200


def test_oversized_body_is_413(server):
    """AC:body 長度 65,537 bytes → `413`(上限 64 KiB,決策 6)。"""
    oversized = b"x" * (webui.MAX_BODY_BYTES + 1)
    assert len(oversized) == 65537
    res = send(server, raw_body=oversized)
    assert res.status == 413


def test_body_exactly_at_the_limit_is_not_413(server):
    """上限是**含**的:剛好 65,536 bytes 過得了門(然後才因為不是物件被 400)。"""
    padding = " " * (webui.MAX_BODY_BYTES - len(b'{"path": ""}'))
    body = ('{"path": ""}' + padding).encode("utf-8")
    assert len(body) == webui.MAX_BODY_BYTES
    res = send(server, raw_body=body)
    assert res.status != 413


def test_lying_content_length_is_413_before_the_body_is_read(server):
    """宣告 1 GB 的 body → `413`,而且伺服器**沒有**去讀那 1 GB。

    body 只送 4 byte:門若開在 `read()` 之後,這個請求會把伺服器掛在那裡等
    1 GB(測試的 10 秒 timeout 會爆);開在之前,它立刻回 413。
    """
    res = send(server, raw_body=b"{}", declared_length=1 << 30)
    assert res.status == 413


@pytest.mark.parametrize("raw", [b"[]", b'"x"', b"null", b"true", b"3", b"{", b"",
                                 b"{'path': 1}", b"\xff\xfe", b"{} {}"])
def test_body_that_is_not_a_json_object_is_400(server, raw):
    """AC:body 不是 JSON 物件(`[]`、`"x"`、壞 JSON、空)→ `400`。"""
    res = send(server, raw_body=raw)
    assert res.status == 400
    assert set(res.json()) == {"error"}


def test_entry_guards_run_before_the_body_is_parsed(server):
    """六道門的優先序:形式防線在 body 解析之前(決策 6「在讀 body 之前」)。

    同一個**壞 body**(`[]`,正常情況是 400)配上各自壞掉的門,出來的是門的碼
    而不是 400——證明判斷順序,不只是碼對。
    """
    bad = b"[]"
    assert send(server, raw_body=bad, host="evil.example").status == 403
    assert send(server, raw_body=bad, origin="http://evil.example").status == 403
    assert send(server, raw_body=bad, content_type="text/plain").status == 415
    assert send(server, raw_body=bad, declared_length=1 << 30).status == 413
    assert send(server, raw_body=bad, token=None).status == 401
    assert send(server, raw_body=bad).status == 400  # 門都過了才輪到它


# ================================================================ /api/inspect


def test_inspect_returns_exactly_the_whitelisted_keys(server):
    """AC(決策 7 / [M7]):JSON 鍵**恰為**那 12 個,一個不多一個不少。"""
    res = send(server, payload={"path": str(GOLDEN)})
    assert res.status == 200
    assert set(res.json()) == EXPECTED_INSPECT_KEYS
    assert set(webui.INSPECT_KEYS) == EXPECTED_INSPECT_KEYS


def test_inspect_matches_the_cli_field_by_field(server, capsys):
    """AC:每一欄的值與 `cli.main(["inspect", golden])` 印出來的逐欄一致。"""
    res = send(server, payload={"path": str(GOLDEN)})
    assert res.status == 200
    api = res.json()
    rows = cli_inspect_rows(capsys)

    assert api["version"] == int(rows["version"]) == 1
    assert api["kdf_name"] == "scrypt"
    assert api["aead_name"] == "AES-256-GCM"
    assert api["kem_name"] == "scrypt-KEK"
    # CLI 把 id 與名字印在同一欄(`1 (scrypt)`),API 拆成 `kdf_id` / `kdf_name`。
    for prefix in ("kdf", "aead", "kem"):
        assert rows[f"{prefix}_id"] == f"{api[f'{prefix}_id']} ({api[f'{prefix}_name']})"
    for field in ("kdf_log2n", "kdf_r", "kdf_p", "chunk_size"):
        assert api[field] == int(rows[field])
    assert rows["file_size"] == f"{api['file_size']} bytes"
    assert api["file_size"] == GOLDEN.stat().st_size
    assert api["kdf_log2n"] == 15


def test_inspect_fields_match_the_cli_whitelist():
    """兩張白名單(`cli._INSPECT_FIELDS` / `webui._INSPECT_FIELDS`)逐項相等。

    決策 13 不准 `webui` import `cli`(相依方向是 `cli → webui`),故表是兩份;
    這條測試是那兩份之間唯一的繫繩——任一邊漂掉就當場失敗。
    """
    cli_labels = [label for label, _ in cli._INSPECT_FIELDS]
    webui_keys = [key for key, _ in webui._INSPECT_FIELDS]
    # `webui` 把 CLI 的 `kdf_id: 1 (scrypt)` 拆成 `kdf_id` + `kdf_name`。
    expanded = []
    for label in cli_labels:
        expanded.append(label)
        if label in ("kdf_id", "aead_id", "kem_id"):
            expanded.append(label.replace("_id", "_name"))
    assert webui_keys == expanded
    assert list(webui.INSPECT_KEYS) == expanded + ["file_size"]
    # 名字表的內容也要對得上(`scrypt` / `AES-256-GCM` / `scrypt-KEK`)。
    assert webui.KDF_NAMES == cli._KDF_NAMES
    assert webui.AEAD_NAMES == cli._AEAD_NAMES
    assert webui.KEM_NAMES == cli._KEM_NAMES


@pytest.mark.parametrize("field", SECRET_FIELDS)
def test_inspect_response_leaks_no_key_material(server, field):
    """AC:回應 body 不含 golden 的 salt / `nonce_prefix` / `wrapped_dek` 任一段 hex。

    「任一段」照字面測:取 header **原始 bytes** 的 ≥4 byte 連續切片的 hex,
    大小寫都算,逐段 `not in`。
    """
    res = send(server, payload={"path": str(GOLDEN)})
    assert res.status == 200
    raw_header = GOLDEN.read_bytes()[:HEADER_SIZE_KEM1]
    raw = field_bytes(raw_header, field)
    assert len(raw) >= 4
    body = res.text
    assert not any(window in body for window in hex_windows(raw))
    assert raw.hex() not in body
    assert raw.decode("latin-1") not in body


def test_inspect_response_leaks_neither_the_golden_salt_nor_the_nonce_prefix(server):
    """AC 寫死的那兩串(與 `tests/test_cli.py` 的同一條斷言對齊)。"""
    body = send(server, payload={"path": str(GOLDEN)}).text
    assert "0101010101010101" not in body
    assert "0202020202020202" not in body
    assert "0404040404040404" not in body


def test_webui_never_reads_the_secret_header_fields():
    """[M7] 結構性守門:`webui.py` 的**程式碼**裡沒有那三欄的取值。

    白名單靠 `_INSPECT_FIELDS` 一張表維持;這條擋的是「臨時 debug 回一下」
    留在樹上,或有人把白名單改寫成 `vars(header)` 迴圈。
    """
    tree = ast.parse(WEBUI_SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in SECRET_FIELDS, ast.unparse(node)
        if isinstance(node, ast.Name):
            assert node.id not in SECRET_FIELDS, node.id
    calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"vars", "asdict", "dataclasses.asdict", "repr", "serialize"}


def test_inspect_ignores_a_passphrase_field_entirely(server):
    """AC:body 多給 `passphrase` 欄也不讀——照常 `200`,回應不含它。

    `inspect` **不問密碼**(決策 7):白名單每一項都在明文 header 裡。
    """
    marker = f"never-read-{uuid.uuid4().hex}"
    res = send(
        server,
        payload={"path": str(GOLDEN), "passphrase": marker, "force": True, "nope": 1},
    )
    assert res.status == 200
    assert set(res.json()) == EXPECTED_INSPECT_KEYS
    assert marker not in res.text


def test_inspect_on_a_missing_path_is_404(server, tmp_path, capsys):
    missing = tmp_path / "nope.qvt"
    res = send(server, payload={"path": str(missing)})
    assert res.status == 404
    assert res.json()["error"] == cli_error(capsys, missing)


def test_inspect_on_a_directory_is_400(server, tmp_path, capsys):
    """AC「`404` 或 `400`(擇一並固定)」→ 本實作**固定 400**。

    目錄**存在**;`404` 會把「打錯路徑」和「選到資料夾」混成同一句話,而這兩種
    情況使用者的下一步完全不同(見 `.asp/pr/21.md` 的說明)。
    """
    res = send(server, payload={"path": str(tmp_path)})
    assert res.status == 400
    assert res.json()["error"] == cli_error(capsys, tmp_path)


def test_inspect_on_a_non_container_is_422_with_the_cli_message(server, tmp_path, capsys):
    """AC:magic 不是 `QVLT` → `422`,`error` **逐字**等於 CLI 去前綴的那一行。"""
    junk = garbage_file(tmp_path)
    res = send(server, payload={"path": str(junk)})
    assert res.status == 422
    assert res.json()["error"] == cli_error(capsys, junk)
    assert res.json()["error"] == "bad magic: not a .qvt container"


@pytest.mark.parametrize("payload_bytes", [b"", b"QVLT", b"QVLT\x01", b"QVLT\x63" + b"\x00" * 99])
def test_inspect_on_broken_containers_is_422_with_the_cli_message(
    server, tmp_path, capsys, payload_bytes
):
    """tamper / 截斷 / 未知 version:都是 `QVaultError` → `422`,訊息同 CLI。"""
    broken = tmp_path / "broken.qvt"
    broken.write_bytes(payload_bytes)
    res = send(server, payload={"path": str(broken)})
    assert res.status == 422
    assert res.json()["error"] == cli_error(capsys, broken)


def test_inspect_on_a_tampered_golden_is_422(server, tmp_path, capsys):
    """AGENTS.md 鐵律 4 的 tamper:改 magic 的一個 byte → 乾淨的 422。"""
    raw = bytearray(GOLDEN.read_bytes())
    raw[0] ^= 0x01
    tampered = tmp_path / "tampered.qvt"
    tampered.write_bytes(bytes(raw))
    res = send(server, payload={"path": str(tampered)})
    assert res.status == 422
    assert res.json()["error"] == cli_error(capsys, tampered)


@pytest.mark.parametrize("payload", [{}, {"path": None}, {"path": 1}, {"path": ["x"]},
                                     {"path": {"a": 1}}, {"paths": "x"}, {"PATH": "x"}])
def test_inspect_without_a_string_path_is_400(server, payload):
    """AC:`path` 欄缺席或非字串 → `400`。"""
    res = send(server, payload=payload)
    assert res.status == 400
    assert set(res.json()) == {"error"}


def test_inspect_reads_only_the_header(server, tmp_path):
    """只讀前 100 B:把 golden 的 body 全砍掉,它照樣答得出來(沒有偷解 chunk 0)。"""
    header_only = tmp_path / "header-only.qvt"
    header_only.write_bytes(GOLDEN.read_bytes()[:HEADER_SIZE_KEM1])
    res = send(server, payload={"path": str(header_only)})
    assert res.status == 200
    assert res.json()["file_size"] == HEADER_SIZE_KEM1


def test_inspect_does_not_leak_the_protected_metadata(server, tmp_path):
    """決策 9 保護的中繼資料(原始檔名、原始大小)不在回應裡。"""
    renamed = tmp_path / "payroll-2026.csv.qvt"
    renamed.write_bytes(GOLDEN.read_bytes())
    body = send(server, payload={"path": str(renamed)}).text
    assert "payroll" not in body
    assert set(json.loads(body)) == EXPECTED_INSPECT_KEYS


def test_unknown_api_route_is_404(server):
    res = send(server, path="/api/nope", payload={"path": str(GOLDEN)})
    assert res.status == 404


# ================================================================ 不外洩(決策 5、9)


def test_access_log_has_only_method_path_and_status(server, capfd, tmp_path):
    """AC:一整輪(401 / 403 / 200)之後,stdout+stderr 只有乾淨的 access log。

    不含 token、不含任何 request body 內容、每條只有 method、path(不含 query)、
    狀態碼。
    """
    marker = f"secret-body-{uuid.uuid4().hex}"
    probe = tmp_path / f"{marker}.qvt"
    probe.write_bytes(GOLDEN.read_bytes())
    capfd.readouterr()

    assert send(server, payload={"path": str(probe)}, token=None).status == 401
    assert send(server, payload={"path": str(probe)}, host="evil.example").status == 403
    assert send(server, payload={"path": str(probe)}).status == 200
    assert send(server, "GET", "/").status == 200
    assert send(server, "GET", "/api/inspect?token=" + server.token).status == 405

    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert server.token not in output
    assert marker not in output
    assert "Authorization" not in output and "Bearer" not in output
    assert "Traceback" not in output

    lines = [line for line in output.splitlines() if line.strip()]
    assert lines, "access log 一條都沒有?那 `log_message` 被整個關掉了"
    for line in lines:
        assert re.fullmatch(r"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|-) /\S* \d{3}", line), line
        assert "?" not in line  # query 不進 log(token 可能在裡面)
    assert "POST /api/inspect 401" in lines
    assert "POST /api/inspect 403" in lines
    assert "POST /api/inspect 200" in lines
    assert "GET / 200" in lines
    assert "GET /api/inspect 405" in lines


#: 一筆 log 都不准原封不動帶出去的字元(#39):C0 全族、DEL、C1 全族。
CONTROL_CHARS = [chr(c) for c in (*range(0x20), 0x7F, *range(0x80, 0xA0))]

#: `webui.py` 裡只有 `log_message` 可以碰終端——這些是「第三個洞」會長出來的樣子。
#:
#: 這張表是**逐字**比對 `ast.unparse(call.func)` 的,所以只認得寫法完全一樣的呼叫。
#: #42 F7 補進來的五族寫法有三族逐字比對不到(fd 號碼、`from … import` 之後的裸名、
#: `logging.getLogger(…)` 的鏈式呼叫),它們在 `terminal_writes` 裡另有判定——
#: 補在這裡的只有「逐字就認得出來」的那些。
TERMINAL_WRITERS = {
    "print",
    "sys.stderr.write",
    "sys.stdout.write",
    "sys.stderr.writelines",
    "sys.stdout.writelines",
    "traceback.print_exc",
    "traceback.print_exception",
    "traceback.print_stack",
    "logging.basicConfig",
    # #42 F7:`sys.stderr` 可以被 `monkeypatch` 換掉,`sys.__stderr__` 不會——
    # 它是直譯器啟動時那個真的終端,繞過 `log_message` 的最短路徑。
    "sys.__stderr__.write",
    "sys.__stdout__.write",
    "sys.__stderr__.writelines",
    "sys.__stdout__.writelines",
    # #42 F7:`warnings` 的預設 `showwarning` 寫 `sys.stderr`,而且它印的是
    # 「訊息 + 檔名 + 行號 + 原始碼那一行」——比 `print` 多吐三樣。
    "warnings.warn",
    "warnings.warn_explicit",
    "warnings.showwarning",
}

#: 寫檔案描述子的那一族(#42 F7)。`os.write` 本身不是罪:`os.write(fd, …)` 寫的
#: 是別的 fd 時與終端無關,所以判定在 `_writes_to_a_terminal_fd` 裡看第一個引數。
FD_WRITERS = {"os.write", "os.writev"}

#: 根名在這裡面的呼叫一律算碰終端(#42 F7)。
#:
#: 擋的是**整個 `logging`**,不只 `logging.StreamHandler(sys.stderr)`(票上留言 ②
#: 問的那個邊界):沒設過 handler 的 root logger 遇到 `logging.warning(…)` 會走
#: `lastResort`,而 `lastResort` 就是一個寫 `sys.stderr` 的 `StreamHandler`——
#: 「只擋明寫 stderr 的那一類」會剛好漏掉最常見的寫法。而 `webui.py` 沒有任何
#: 使用 `logging` 的理由(決策 9 只准 method / path / 狀態碼一行三欄,`log_message`
#: 已經是那個唯一出口),所以整族擋掉是守得住的線,不是過嚴。
TERMINAL_WRITER_ROOTS = {"logging"}


def _writes_to_a_terminal_fd(call: ast.Call) -> bool:
    """`os.write(2, …)` 這一族:**看不出寫到哪裡就當成寫到終端**(#42 F7)。

    `os.write(fd, …)` 的 `fd` 是個常數 1 / 2 時就是 stdout / stderr。不是常數時
    (變數、函式回傳值)靜態判不出來,所以回 `True`:掃描寧可多叫一次,也不要
    讓 `fd = 2` 這種一行的間接寫法穿過去。常數而且不是 1 / 2(寫自己開的檔)
    才放行。
    """
    if not call.args:
        return True
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, int):
        return first.value in (1, 2)
    return True


def _terminal_write_aliases(tree: ast.AST) -> tuple[set[str], set[str], set[str]]:
    """匯入段 → `(逐字算終端的名字, fd 寫入的名字, 根名算終端的名字)`(#42 F7)。

    逐字比對一張表掃不到三族寫法,而它們都只是「換一個名字」:

    - `from sys import stderr` 之後的 `stderr.write(…)`(表上寫的是 `sys.stderr.write`);
    - `import logging as lg` 之後的 `lg.warning(…)`、以及
      `_LOG = logging.getLogger(__name__)` 之後的 `_LOG.error(…)`;
    - `from os import write` 之後的 `write(2, …)`。

    所以先把匯入段讀成一張別名表,再用它判呼叫。`import sys` / `import os` 的
    標準寫法不必在這裡登記(表上與 `FD_WRITERS` 已經是那個名字)。
    """
    names: set[str] = set()
    fd_writers: set[str] = set()
    roots: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not alias.asname:
                    continue                      # `import sys` → 表上已經有了
                if alias.name == "sys":
                    for stream in ("stderr", "stdout", "__stderr__", "__stdout__"):
                        names.update({
                            f"{alias.asname}.{stream}.write",
                            f"{alias.asname}.{stream}.writelines",
                        })
                elif alias.name == "os":
                    fd_writers.update({f"{alias.asname}.write", f"{alias.asname}.writev"})
                elif alias.name == "warnings":
                    names.update({f"{alias.asname}.warn", f"{alias.asname}.warn_explicit"})
                elif alias.name.split(".")[0] in TERMINAL_WRITER_ROOTS:
                    roots.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if node.module == "sys" and alias.name in (
                    "stderr", "stdout", "__stderr__", "__stdout__"
                ):
                    names.update({f"{bound}.write", f"{bound}.writelines"})
                elif node.module == "sys" and alias.name == "displayhook":
                    names.add(bound)
                elif node.module == "os" and alias.name in ("write", "writev"):
                    fd_writers.add(bound)
                elif node.module == "warnings" and alias.name in (
                    "warn", "warn_explicit", "showwarning"
                ):
                    names.add(bound)
                elif (node.module or "").split(".")[0] in TERMINAL_WRITER_ROOTS:
                    names.add(bound)                # `from logging import warning`
                    roots.add(bound)                # `from logging import getLogger`

    # `_LOG = logging.getLogger(…)` → `_LOG.error(…)` 也要算。只看模組層與類別層
    # 的指派:函式內的 logger 變數同樣會被下面的根名判定抓到(根名是 `logging`)。
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _root_name(ast.unparse(node.value.func)) not in (roots | TERMINAL_WRITER_ROOTS):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                roots.add(target.id)

    return names, fd_writers, roots


def _root_name(written: str) -> str:
    """`logging.getLogger(__name__).error` → `logging`(取呼叫鏈最前面那一節)。"""
    return written.split(".", 1)[0].split("(", 1)[0]


def terminal_writes(source: str) -> list[tuple[str, str]]:
    """`source` 裡每一個寫終端的呼叫 → `(所在函式名, 呼叫)`。

    `ast.walk` 不能直接用:它從外層函式也看得到內層函式的呼叫,同一個呼叫會被記
    兩次(所在函式還會記錯)。所以自己遞迴,進到 `def` 就換掉「目前所在函式」。

    判定分四條(#42 F7 把後三條補進來——原本只有第一條,於是 `os.write(2, …)`、
    `sys.__stderr__.write`、`from sys import stderr` 之後的 `stderr.write`、
    `warnings.warn`、`logging.*` 五族寫法全部穿得過去):

    1. 逐字命中 `TERMINAL_WRITERS`;
    2. 逐字命中匯入段算出來的別名(`_terminal_write_aliases`);
    3. `FD_WRITERS` 且第一個引數不是「某個不是 1 / 2 的常數」(`_writes_to_a_terminal_fd`);
    4. 呼叫鏈的根名在 `TERMINAL_WRITER_ROOTS`(或由匯入 / 指派綁到它的名字)。

    每一條都有一個記憶體內的突變樣本證明它載重,見
    `test_a_second_terminal_write_is_caught_whatever_shape_it_takes`。
    """
    found: list[tuple[str, str]] = []
    tree = ast.parse(source)
    aliases, fd_writers, roots = _terminal_write_aliases(tree)

    def writes_to_terminal(call: ast.Call) -> bool:
        written = ast.unparse(call.func)
        if written in TERMINAL_WRITERS or written in aliases:
            return True
        if written in FD_WRITERS or written in fd_writers:
            return _writes_to_a_terminal_fd(call)
        return _root_name(written) in (roots | TERMINAL_WRITER_ROOTS)

    def descend(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                descend(child, child.name)
                continue
            if isinstance(child, ast.Call) and writes_to_terminal(child):
                found.append((owner, ast.unparse(child.func)))
            descend(child, owner)

    descend(tree, "<module>")
    return found


def test_control_characters_in_the_request_line_are_escaped_in_the_log(server, capfd):
    r"""AC-1 / AC-2(#39):原始 socket 送帶 ESC 的請求行 → stderr 沒有原始控制字元。

    這個形態**不需要 token**,`Host` 也故意是錯的(403 一樣會經 `send_response`
    進 access log),所以同機的任何使用者都打得到——票文的重現指令照抄。

    斷言三件事,缺一條就擋不住這個洞:
      ① 輸出裡沒有 `\x1b`(拿掉 `log_message` 的跳脫即紅);
      ② 跳脫後的字面 `\x1b` 要**在**那一行裡——否則「把 path 整個從 log 裡刪掉」
         也能過 ①,而那會順手破壞決策 9 要求的 path 欄位;
      ③ 仍是一行:CR / LF 一起跳脫,攻擊者塞不進第二筆假的 access log。
    """
    capfd.readouterr()
    raw = socket.create_connection((webui.LOOPBACK, server.port), timeout=5)
    try:
        raw.sendall(
            b"GET /\x1b[2J\x1b[Hhttp://127.0.0.1:4444/#AAAA HTTP/1.1\r\n"
            b"Host: x\r\n\r\n"
        )
        status_line = raw.makefile("rb").readline()
    finally:
        raw.close()
    assert b"403" in status_line, status_line

    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert "\x1b" not in output, "原始 ESC 進了終端:控制字元跳脫被拿掉了"
    assert "\\x1b" in output, "path 欄位不見了?決策 9 要 method / path / 狀態碼三樣"
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    assert lines[0].startswith("GET /\\x1b[2J\\x1b[H"), lines[0]
    assert lines[0].endswith(" 403"), lines[0]
    assert "#" not in lines[0]  # fragment 照決策 5 不進 log


@pytest.mark.parametrize("char", CONTROL_CHARS, ids=lambda c: f"{ord(c):#04x}")
def test_log_message_escapes_every_control_character(char, capfd):
    """AC-1(#39):C0 / DEL / C1 每一個字元都跳脫,而且一筆 log 恆為一行。

    不經 socket:請求行送不出 CR / LF(它們就是請求行的結束),但 `log_message`
    的 `args` 未來可能從別處來,這條把「表有沒有缺洞」逐字元釘住。
    """
    capfd.readouterr()
    webui._Handler.log_message(None, "GET %s 403", f"/{char}x")

    captured = capfd.readouterr()
    output = captured.out + captured.err
    # 結尾那個 `\n` 是 log 自己的行尾,不算「原封不動帶出去」。
    assert char not in output.removesuffix("\n"), f"{ord(char):#04x} 沒被跳脫"
    assert output == f"GET /\\x{ord(char):02x}x 403\n", repr(output)


def test_log_message_escapes_the_backslash_itself(capfd):
    r"""`\x1b` 五個字面字元不可以與跳脫後的 ESC 同形,否則讀 log 的人分不出來。"""
    capfd.readouterr()
    webui._Handler.log_message(None, "GET %s 403", "/\\x1b")
    real = capfd.readouterr()
    webui._Handler.log_message(None, "GET %s 403", "/\x1b")
    escaped = capfd.readouterr()
    assert (real.out + real.err) != (escaped.out + escaped.err)


def test_log_error_writes_nothing_even_for_control_characters(capfd):
    """AC-1 的另一半:`log_error` 整個收掉,所以原始控制字元也出不去(決策 9)。"""
    capfd.readouterr()
    webui._Handler.log_error(None, "Bad request version (%r)", "\x1b[2J\x1b[H/#AAAA")
    captured = capfd.readouterr()
    assert captured.out == "" and captured.err == ""


def test_malformed_request_lines_never_reach_the_terminal_unescaped(server, capfd):
    """守的是「**這條路沒有可注入的輸出**」,不是 #39 那次的跳脫修正(#42 F5)。

    畸形請求行走基底類別的 `send_error` → `log_error`,而本層的 `log_error` 整個
    收掉(決策 9):這條路寫出的那一行不含請求行的任何位元組,所以**沒有東西可以
    被注入**。標準庫的 `send_error` 另外會經 `send_response` → `log_request` 寫出
    一行 `- - <code>`(請求行還沒解析成功,故 method 與 path 都是 `-`)——有輸出,
    但裡面沒有一個 byte 來自攻擊者。它因此
    對 `_escaped` 不敏感——把跳脫整個拿掉,這條照樣綠(真正在守跳脫的是
    `test_control_characters_in_the_request_line_are_escaped_in_the_log` 與
    `test_log_message_escapes_every_control_character`)。

    這個分工要寫明,否則下一個人拿這條當跳脫的回歸測試、順手刪掉上面那兩條,
    而刪完這條還是綠的。
    """
    capfd.readouterr()
    for payload in (
        b"GET /\x1b[2J HTTP/9.9\r\nHost: x\r\n\r\n",  # 版本不對 → log_error
        b"\x1b[2J\x1b[H\r\n\r\n",  # 連 method 都不是 → 畸形請求行
        b"GET\x1b/\x1b\x1b HTTP/1.1\r\nHost: x\r\n\r\n",
    ):
        raw = socket.create_connection((webui.LOOPBACK, server.port), timeout=5)
        try:
            raw.sendall(payload)
            raw.makefile("rb").readline()
        finally:
            raw.close()

    captured = capfd.readouterr()
    output = captured.out + captured.err
    for char in CONTROL_CHARS:
        if char in "\r\n":
            continue  # 換行是 log 的行分隔,不是注入
        assert char not in output, (f"{ord(char):#04x} 原封不動進了終端", output)


def test_webui_has_no_second_path_that_writes_to_the_terminal():
    """只有 `log_message` 可以碰終端(#39 的掃描式斷言)。

    這次把跳脫補回 `log_message`,但下次有人在例外處理裡 `print(exc)` 就又漏了。
    所以守的不是「跳脫對不對」,是「終端只有一個出口」——出口只有一個,跳脫才
    只需要在一個地方對。
    """
    assert terminal_writes(WEBUI_SOURCE) == [("log_message", "sys.stderr.write")]


#: `_route` 的第一行——F7 的突變注入錨。寫死在這裡是故意的:`webui.py` 哪天改了
#: 這一行,下面的突變測試會當場失敗,而不是靜靜地注入到一個不存在的地方、讓
#: 「掃描抓得到」變成一條沒有證據的宣稱。
ROUTE_ANCHOR = '        path = getattr(self, "path", "") or ""'

#: `webui.py` 現況:終端只有一個出口。突變樣本要與它不同才算被點名。
BASELINE_TERMINAL_WRITES = [("log_message", "sys.stderr.write")]

#: F7 點名的五族寫法,每一族至少一個突變樣本 → `(注入的那一行, 要補的匯入)`。
#:
#: 五族依次是:`os.write(2, …)`、`sys.__stderr__.write`、`from sys import stderr`
#: 之後的 `stderr.write`、`warnings.warn`、`logging.*`。另外幾格是同族的變形
#: (間接的 fd、別名匯入、`getLogger` 鏈、模組層 logger),它們是逐字比對最容易
#: 漏掉的形狀。`import os` / `import sys` 在 `webui.py` 裡已經有了,故匯入欄為空。
TERMINAL_WRITE_MUTANTS = {
    "os.write-fd-2": ('os.write(2, b"boom")', ""),
    "os.write-fd-1": ('os.write(1, b"boom")', ""),
    "os.write-indirect-fd": ('os.write(self.server.fileno(), b"boom")', ""),
    "sys.__stderr__.write": ('sys.__stderr__.write("boom")', ""),
    "from-sys-import-stderr": ('stderr.write("boom")', "from sys import stderr"),
    "from-sys-import-stderr-aliased": ('err.write("boom")', "from sys import stderr as err"),
    "warnings.warn": ('warnings.warn("boom")', "import warnings"),
    "from-warnings-import-warn": ('warn("boom")', "from warnings import warn"),
    "logging.warning": ('logging.warning("boom")', "import logging"),
    "logging.getLogger-chain": (
        'logging.getLogger(__name__).error("boom")',
        "import logging",
    ),
    "logging.StreamHandler": (
        'logging.StreamHandler(sys.stderr).handle("boom")',
        "import logging",
    ),
    "logging-aliased": ('lg.warning("boom")', "import logging as lg"),
    "from-logging-import-warning": ('warning("boom")', "from logging import warning"),
    "module-level-logger": (
        '_LOG.error("boom")',
        "import logging\n_LOG = logging.getLogger(__name__)",
    ),
}


def _mutate_route(injection: str, imports: str) -> str:
    """把 `injection` 插進 `_route` 的第一行之後(**只在記憶體裡**)。

    `qvault_core/webui.py` 一個 byte 都不會被改:突變的是 `WEBUI_SOURCE` 的一份
    字串複本,掃描吃的也只是那個字串。
    """
    assert WEBUI_SOURCE.count(ROUTE_ANCHOR) == 1, "`_route` 的注入錨漂掉了"
    mutant = WEBUI_SOURCE.replace(ROUTE_ANCHOR, f"{ROUTE_ANCHOR}\n        {injection}")
    if imports:
        import_anchor = "import threading\n"
        assert mutant.count(import_anchor) == 1, "匯入段的錨漂掉了"
        mutant = mutant.replace(import_anchor, f"{import_anchor}{imports}\n")
    ast.parse(mutant)  # 樣本本身要是合法 Python,否則它證明不了任何事
    return mutant


@pytest.mark.parametrize(
    ("injection", "imports"),
    list(TERMINAL_WRITE_MUTANTS.values()),
    ids=list(TERMINAL_WRITE_MUTANTS),
)
def test_a_second_terminal_write_is_caught_whatever_shape_it_takes(injection, imports):
    """F7:「終端只有一個出口」那條掃描**真的**掃得到這些寫法。

    上面那條 `test_webui_has_no_second_path_that_writes_to_the_terminal` 是逐字
    比對一張表,而 #42 F7 點名的五族寫法原本一個都不在表上:掃描照樣綠,洞照樣
    開著。這條把每一族各注入一次(在記憶體裡),要求掃描結果與現況不同、而且
    點得出注入落在 `_route`——否則「補進掃描」只會被驗成「清單變長」。

    未注入時全綠由那條本身負責(它斷言結果恰為
    `[("log_message", "sys.stderr.write")]`)。
    """
    hits = terminal_writes(_mutate_route(injection, imports))
    assert hits != BASELINE_TERMINAL_WRITES, f"注入 `{injection}` 之後掃描還是綠的"
    assert any(owner == "_route" for owner, _ in hits), hits
    assert BASELINE_TERMINAL_WRITES[0] in hits, ("原本那一個出口不該消失", hits)


def test_writing_to_a_file_descriptor_that_is_not_the_terminal_is_not_a_hit():
    """`FD_WRITERS` 的邊界寫明:`os.write(3, …)` 不算碰終端。

    擋的是終端,不是 `os.write` 這個名字——`vault` 式的「寫 `.part` 檔再
    `os.replace`」哪天搬進這一層的話,它寫的是自己開的 fd。常數而且不是
    1 / 2 才放行;看不出來的一律算(見 `_writes_to_a_terminal_fd`)。
    """
    assert terminal_writes(_mutate_route('os.write(3, b"ok")', "")) == (
        BASELINE_TERMINAL_WRITES
    )


def test_the_control_char_table_covers_c0_c1_and_del():
    """表不是從標準庫的私有屬性借來的,所以它的覆蓋範圍要自己釘住。"""
    table = webui._CONTROL_CHAR_TABLE
    for char in CONTROL_CHARS:
        assert table.get(ord(char)) == f"\\x{ord(char):02x}", hex(ord(char))
    assert table.get(ord("\\")) == "\\x5c"
    # 可印字元一個都不准動:path 欄位要還讀得出來。
    for char in " /.-_~%?azAZ09":
        assert ord(char) not in table, char
    # 標準庫的私有名不碰(提到它的只有註解),也不委派 `super().log_message()`
    # ——那會把 client ip 與時間戳前綴進每一行,決策 9 不准。
    tree = ast.parse(WEBUI_SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr != "_control_char_table", ast.unparse(node)
        if isinstance(node, ast.Call):
            assert ast.unparse(node.func) != "super().log_message", ast.unparse(node)


def test_unexpected_exception_is_500_with_only_the_type_name(
    server, capfd, monkeypatch
):
    """AC:handler 內部拋未預期例外 → `500`、body 只有型別名、輸出無訊息無 traceback。"""
    marker = f"boom-{uuid.uuid4()}"

    def explode(*args, **kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(webui, "deserialize", explode)
    capfd.readouterr()

    res = send(server, payload={"path": str(GOLDEN)})
    assert res.status == 500
    assert res.json() == {"error": "RuntimeError"}

    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert marker not in output
    assert "Traceback" not in output
    assert "RuntimeError" not in output  # 連型別名都不印到終端;它只在回應裡


def test_error_responses_never_echo_a_traceback(server, tmp_path):
    """任何錯誤 body 都是一行 JSON,不含 traceback 的痕跡。"""
    junk = garbage_file(tmp_path)
    for res in (
        send(server, payload={"path": str(GOLDEN)}, token=None),
        send(server, payload={"path": str(GOLDEN)}, host="evil.example"),
        send(server, raw_body=b"["),
        send(server, payload={"path": str(junk)}),
        send(server, payload={"path": str(tmp_path / "nope")}),
    ):
        body = res.text
        assert set(res.json()) == {"error"}
        assert "Traceback" not in body
        assert "File \"" not in body
        assert "\n" not in res.json()["error"]  # 「一行訊息」照字面


# ================================================================ 頁面與標頭(決策 10)


def test_root_page_is_html_with_all_five_headers(server):
    """AC:`GET /` → `200` + `text/html; charset=utf-8` + CSP + 三個安全標頭。"""
    res = send(server, "GET", "/")
    assert res.status == 200
    assert res.header("Content-Type") == "text/html; charset=utf-8"
    assert res.header("Content-Security-Policy") == (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    assert res.header("Cache-Control") == "no-store"
    assert res.header("X-Content-Type-Options") == "nosniff"
    assert res.header("Referrer-Policy") == "no-referrer"
    assert b"<!DOCTYPE html>" in res.body


def test_csp_constant_matches_adr_002():
    """決策 10 那一串是 ADR 的字,不是這裡的字:直接拿 ADR 原文對。

    (supervisor 留言 ③ 的擔憂:ADR 改字而常數靜默跟著漂。這條讓它漂不動。)
    """
    adr = (REPO_ROOT / "docs" / "adr" / "ADR-002-local-web-ui.md").read_text("utf-8")
    assert f"Content-Security-Policy: {webui.CONTENT_SECURITY_POLICY}" in adr


@pytest.mark.parametrize("path", ["/anything-else", "/index.html", "/favicon.ico",
                                  "/static/x", "/ui", "/api", "/."])
def test_any_other_path_is_404(server, path):
    """AC:`GET /anything-else` → `404`。"""
    res = send(server, "GET", path)
    assert res.status == 404
    assert set(res.json()) == {"error"}


def test_api_responses_carry_the_three_security_headers(server, tmp_path):
    """AC:「API 回應同樣帶後三個標頭」——成功與每一種失敗都要帶。"""
    cases = [
        send(server, payload={"path": str(GOLDEN)}),
        send(server, payload={"path": str(GOLDEN)}, token=None),
        send(server, payload={"path": str(GOLDEN)}, host="evil.example"),
        send(server, "GET", webui.API_INSPECT_PATH),
        send(server, payload={"path": str(GOLDEN)}, content_type="text/plain"),
        send(server, raw_body=b"x" * (webui.MAX_BODY_BYTES + 1)),
        send(server, raw_body=b"[]"),
        send(server, payload={"path": str(tmp_path / "nope")}),
        send(server, payload={"path": str(garbage_file(tmp_path))}),
        send(server, "GET", "/anything-else"),
    ]
    for res in cases:
        assert res.header("Cache-Control") == "no-store", res.status
        assert res.header("X-Content-Type-Options") == "nosniff", res.status
        assert res.header("Referrer-Policy") == "no-referrer", res.status


def test_server_header_does_not_leak_the_python_version(server):
    assert "Python" not in (send(server, "GET", "/").header("Server") or "")


# ================================================================ 相依方向(決策 13)


def _relative_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            modules.add(node.module or ".")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("qvault_core."):
                    modules.add(alias.name.split(".", 1)[1])
    return modules


def test_webui_only_imports_the_allowed_core_modules():
    """AC(決策 13):`webui` 的 `qvault_core` import ⊆ {vault, container, errors}。

    不得 import `aead` / `kek`:UI 層不碰密碼原語,也不碰 KEK——那是 `vault`
    的事,而 `vault` 的介面就是 `encrypt_file` / `decrypt_file`。
    """
    assert _relative_imports(WEBUI_PATH) <= {"vault", "container", "errors"}
    assert not _relative_imports(WEBUI_PATH) & {"aead", "kek", "cli"}


@pytest.mark.parametrize("name", ["aead.py", "kek.py", "container.py", "vault.py"])
def test_the_core_four_do_not_import_webui(name):
    """AC:核心四檔無一 import `webui`。

    相依方向是 `cli → webui → {vault, container, errors}`;反向一條都不能有,
    否則 `import qvault_core` 就會把一個 HTTP 伺服器拖進每一個使用情境。

    `cli.py` 那一格由 **#24 的主管層裁定(2026-11-08,#27 獨立複審 M1)刪除**:
    它斷言的是「`cli.py` 不含 `webui` 字串」,與 ADR-002 決策 13 要的 `cli → webui`
    直接矛盾,而那條邊正是 #24 要落的。裁定只開了這一格,其餘仍是裁判。
    「不把伺服器拖進每一個使用情境」這個**理由**沒有被放掉,換了守的人:
    `tests/test_cli_ui.py::test_importing_the_package_still_does_not_drag_in_a_server`
    驗 `import qvault_core` 的 `sys.modules` 裡沒有 `webui`。
    """
    path = REPO_ROOT / "qvault_core" / name
    source = path.read_text(encoding="utf-8")
    assert "webui" not in _relative_imports(path)
    assert "webui" not in source


def test_webui_is_stdlib_only_besides_the_core():
    """相依不變(共同範圍條款):只用 Python 3.12 標準庫,零新套件。"""
    tree = ast.parse(WEBUI_SOURCE)
    third_party = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            third_party.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            third_party.add((node.module or "").split(".")[0])
    assert third_party <= {
        "__future__", "hmac", "json", "os", "secrets", "sys", "http", "pathlib",
        "threading",  # #30 複審 M5:同一寫入目標的鎖(標準庫,相依不變)
    }, third_party
    assert "cryptography" not in third_party  # UI 層不碰密碼原語(鐵律 1 的方向)


# ================================================================ V2:形式 fuzz(決策 14)


def test_fuzzed_requests_never_5xx_and_never_traceback(server, capfd):
    """決策 14 的 V2,縮小版:固定 seed 的亂數請求打 HTTP 層。

    要的不是覆蓋率,是**一條不變式**:任何畸形輸入都收斂成 4xx,沒有 `5xx`、
    沒有 traceback、伺服器不倒。決策 14 寫的 10,000 筆是人側 / CI 另跑的規模
    (每筆一條 TCP 連線);這裡 2,000 筆守回歸,約 1 秒。
    """
    rng = random.Random(20261108)
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"]
    paths = ["/", "/api/inspect", "/api/encrypt", "/x", "/api/", "/%2e%2e/"]
    bodies = [b"", b"{}", b"[]", b"null", b'{"path":', b'{"path": 1}',
              b'{"path": "/nonexistent-' + b"a" * 300 + b'"}',
              b'{"path": "/etc"}', b'{"path": "\\u0000"}', b"\xff" * 32,
              b'{"path": "' + b"/" * 2000 + b'"}']
    content_types = [None, "application/json", "text/plain", "application/json; q=1"]
    capfd.readouterr()

    for _ in range(2000):
        res = send(
            server,
            rng.choice(methods),
            rng.choice(paths),
            raw_body=rng.choice(bodies),
            token=_DEFAULT if rng.random() < 0.7 else "Bearer nope",
            host=_DEFAULT if rng.random() < 0.9 else "evil.example",
            origin=None if rng.random() < 0.7 else "http://evil.example",
            content_type=rng.choice(content_types),
        )
        assert 200 <= res.status < 500, (res.status, res.text)

    output = capfd.readouterr()
    assert "Traceback" not in output.out + output.err
    # 伺服器還活著。
    assert send(server, payload={"path": str(GOLDEN)}).status == 200


def test_server_survives_a_connection_that_hangs_up_mid_request(server):
    """半截的請求不該讓伺服器倒,也不該印 traceback。"""
    raw = socket.create_connection((webui.LOOPBACK, server.port), timeout=5)
    raw.sendall(b"POST /api/inspect HTTP/1.1\r\nHost: ")
    raw.close()
    assert send(server, payload={"path": str(GOLDEN)}).status == 200
