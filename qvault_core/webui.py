"""本機 Web UI 的 HTTP 伺服器骨架(ADR-002,決策 4–10、13)。

設計的唯一事實源 = `docs/adr/ADR-002-local-web-ui.md`(Accepted)。本檔是那份
決策的可執行轉錄:只綁 IPv4 loopback、一次性 bearer token、`Host` / `Origin` /
方法 / 型別 / 大小 / JSON 形式六道入口防線、`/api/inspect`、佔位頁與安全標頭。

本票(#21)只到這裡:`encrypt` / `decrypt` 端點在 #22,真正的頁面在 #23,
`qvault ui` 子命令在 #24。故本檔**一次也沒有碰到密碼**——連讀 `passphrase`
這個欄位的程式碼都還不存在。

## 新增的攻擊面與六道門(決策 5、6)

本模組讓本機多了一個會接受 HTTP 請求的程序,要防的是「使用者瀏覽器裡的其他
網頁」把它當跳板。每個請求依序過:

    1. Host     必須恰等於 `127.0.0.1:<port>`      違者 403  ← 擋 DNS rebinding
    2. method   `/api/*` 只收 POST                 違者 405
    3. Origin   若存在必須恰等於 `http://127.0.0.1:<port>`  違者 403
    4. 型別     `Content-Type: application/json`   違者 415
    5. 大小     `Content-Length` ≤ 64 KiB          違者 413
    6. token    `Authorization: Bearer <token>`    缺或錯 401

**前五道在讀 body 之前就判完**(決策 6),第六道也在 `rfile.read()` 之前——
一個 65,537 byte 的請求不會先被收進記憶體才被拒絕。順序照決策 6 的行文
(「一個不知道 token 的網頁**即使過得了這些**也打不進來」):形式防線是外門、
token 是內門,**兩道各自獨立**,任一道單獨成立就足以擋住跨來源的網頁。

`localhost` 刻意**不收**:它解析成什麼由 OS 的 hosts 檔決定,而那不是我們能
保證的東西(決策 6)。token 走網址的 **fragment**(`/#<token>`),瀏覽器不會把
fragment 送到伺服器,故它不進 access log、不進 `Referer`(決策 5)。

## 兩條在本層才成立的規矩

1. **不能改綁定位址,要在型別層面成立**(決策 4):`make_server` 的簽章只有
   `port`,沒有 `host` / `bind` / `address`。位址是模組常數 `LOOPBACK`,不是
   參數——「不能改」靠的不是文件,是**沒有那個參數可以傳**。
2. **什麼都不記、什麼都不吐**(決策 8、9):`log_message` 的每一行只有 method、
   path(不含 query)、狀態碼;`log_error` 整個收掉(它的訊息會轉述請求行);
   未預期例外只回**型別名**,永不 traceback——frame 裡躺著密碼與 DEK(鐵律 5)。

## `inspect` 走白名單,而且是具名白名單([M7])

`_INSPECT_FIELDS` 與 `cli._INSPECT_FIELDS` 是**兩張表**,因為決策 13 不准 `webui`
import `cli`(相依方向是 `cli → webui`)。兩張表逐項相等由
`tests/test_webui_server.py::test_inspect_fields_match_the_cli_whitelist` 釘住:
它拿 `cli._INSPECT_FIELDS` 與本檔的表對照,任一邊漂掉就當場失敗。

表是「(鍵, 取值函式)」而不是 `dataclasses.asdict` / `vars()` / `FIELD_LAYOUT`
迴圈:差別在**新增欄位時的預設行為**。迴圈式的寫法會讓 header 未來多出來的欄位
(P1 的 ML-KEM 會加 `kem_pub` 之類的東西)**自動**被 JSON 吐出去;具名白名單的
預設是「不吐」,要多一欄得有人動手改表,程式碼審查看得見。`salt` /
`nonce_prefix` / `wrapped_dek` 因此在本檔的**程式碼裡一次都沒有被取值**
(只有這段說明文字提到它們,`tests/test_webui_server.py` 掃 AST 守著)。
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .container import (
    AEAD_ID_AES256GCM,
    HEADER_SIZE_KEM1,
    KDF_ID_SCRYPT,
    KEM_ID_SCRYPT,
    deserialize,
)
from .errors import QVaultError

__all__ = [
    "LOOPBACK",
    "MAX_BODY_BYTES",
    "JSON_MEDIA_TYPE",
    "HTML_CONTENT_TYPE",
    "CONTENT_SECURITY_POLICY",
    "SECURITY_HEADERS",
    "INSPECT_KEYS",
    "API_INSPECT_PATH",
    "WebUIServer",
    "make_server",
]

#: 唯一的綁定位址(決策 4)。**不是**參數、不從環境讀、沒有任何覆寫路徑:
#: IPv4 loopback 寫死在這裡,`::1` 也不綁(多一個位址就是多一個面)。
LOOPBACK = "127.0.0.1"

#: body 上限 64 KiB(決策 6)。路徑模式(決策 2)下 body 只有路徑與密碼,
#: 連這個都用不到十分之一;上限的用途是讓一個大 POST 在**讀進記憶體之前**被拒。
MAX_BODY_BYTES = 64 * 1024

JSON_MEDIA_TYPE = "application/json"
JSON_CONTENT_TYPE = "application/json; charset=utf-8"
HTML_CONTENT_TYPE = "text/html; charset=utf-8"

#: 錯誤回應後的 lingering close 上限(見 `_Handler._drain_request_body`)。
DRAIN_LIMIT_BYTES = 1 << 20
DRAIN_TIMEOUT_SECONDS = 1.0

BEARER_SCHEME = "Bearer"
API_PREFIX = "/api/"
API_INSPECT_PATH = "/api/inspect"
PAGE_PATH = "/"

#: 決策 10 的 CSP,逐字。`default-src 'none'` 起手,故前端**沒有** inline
#: script / inline style / `on*` 屬性 / 外部資源,一個都不能有。
#: `tests/test_webui_server.py::test_csp_constant_matches_adr_002` 拿 ADR 原文對,
#: ADR 改字而這裡沒跟上就當場失敗(反之亦然)。
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)

#: 決策 10:**所有**回應都帶這三個。由 `_Handler.end_headers` 統一注入,
#: 故連基底類別自己發的錯誤回應(畸形請求行之類)也帶得上——漏一條路徑的
#: 可能性因此是零。
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)

#: 演算法 id → 人看得懂的名字(與 `cli._KDF_NAMES` 等三張表同內容,見模組
#: docstring 為何是兩份)。純顯示用;id 的合法性由 `container.deserialize` 把關。
KDF_NAMES = {KDF_ID_SCRYPT: "scrypt"}
AEAD_NAMES = {AEAD_ID_AES256GCM: "AES-256-GCM"}
KEM_NAMES = {KEM_ID_SCRYPT: "scrypt-KEK"}
UNKNOWN_NAME = "unknown"

#: [M7] `/api/inspect` 的白名單:(JSON 鍵, 取值函式)。見模組 docstring。
#: `file_size` 不在這張表裡——它來自 `fstat`,不是 header 欄位。
_INSPECT_FIELDS: tuple[tuple[str, object], ...] = (
    ("version", lambda h: h.version),
    ("kdf_id", lambda h: h.kdf_id),
    ("kdf_name", lambda h: KDF_NAMES.get(h.kdf_id, UNKNOWN_NAME)),
    ("aead_id", lambda h: h.aead_id),
    ("aead_name", lambda h: AEAD_NAMES.get(h.aead_id, UNKNOWN_NAME)),
    ("kem_id", lambda h: h.kem_id),
    ("kem_name", lambda h: KEM_NAMES.get(h.kem_id, UNKNOWN_NAME)),
    ("kdf_log2n", lambda h: h.kdf_log2n),
    ("kdf_r", lambda h: h.kdf_r),
    ("kdf_p", lambda h: h.kdf_p),
    ("chunk_size", lambda h: h.chunk_size),
)

#: `/api/inspect` 回應的鍵,恰為這些(決策 7)。
INSPECT_KEYS: tuple[str, ...] = tuple(key for key, _ in _INSPECT_FIELDS) + (
    "file_size",
)

#: 佔位頁(決策 10 / #23 才上真頁面)。CSP 是 `default-src 'none'`,故這裡
#: 連一個 `<style>` 都不放:inline style 會被 CSP 擋掉,而「被擋掉的樣式」
#: 是個每次改版都要重新發現一次的坑。真頁面的 HTML/JS/CSS 在 #23。
PLACEHOLDER_PAGE = """<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QVault</title>
</head>
<body>
<h1>QVault</h1>
<p>本機 Web UI 的伺服器骨架已就緒。表單與互動在後續交付;目前只有
<code>POST /api/inspect</code> 可用,且需要啟動時印出的一次性 token。</p>
</body>
</html>
"""


class _Reject(Exception):
    """入口防線或使用錯誤:一個狀態碼 + 一行訊息,收斂成 JSON `{"error": ...}`。

    只裝**訊息**,不裝原例外——`__cause__` 一旦帶上,任何一個手滑的 `raise` 都
    可能把底層例外(與它 frame 裡的東西)帶進回應。同 `cli._CleanExit` 的理由。
    """

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _oserror_message(exc: OSError) -> str:
    """`OSError` → 一行訊息,格式與 `cli.main` 的 `OSError` 分支逐字相同。

    不吐 `[Errno 2] ...` 這種噪音;沒有 `strerror` 的(由 `vault` 自己 raise 的
    `FileExistsError` 等)走 `str()`。
    """
    if exc.strerror:
        path = exc.filename or ""
        return f"{exc.strerror}: {path}" if path else exc.strerror
    return str(exc)


class _Handler(BaseHTTPRequestHandler):
    """一個請求一次六道門(見模組 docstring 的表)。

    所有方法都走同一個 `_dispatch`:`Host` 的檢查因此對**任何**方法都成立,
    不只 GET / POST——「任何請求」照字面做,免得哪天多一個 `do_*` 就漏一道門。
    """

    #: 不吐 Python 版本(預設的 `sys_version` 會把它寫進 `Server` 標頭:
    #: 那是免費送給攻擊者的版本指紋,而本機 UI 沒有任何理由需要它)。
    server_version = "qvault-webui"
    sys_version = ""

    #: HTTP/1.1 + 每個回應都帶 `Content-Length`(見 `_respond`)。錯誤回應一律
    #: 附 `Connection: close`:被擋下的請求我們**沒有讀它的 body**,那些位元組
    #: 還在 socket 裡,連線不關就會被下一個請求當成請求行(request smuggling)。
    protocol_version = "HTTP/1.1"

    #: keep-alive 的閒置連線不會永遠佔著一條執行緒(測試的 `shutdown()` 也因此
    #: 不必等任何人)。
    timeout = 10

    # ------------------------------------------------------------ 路由

    def _dispatch(self) -> None:
        """唯一的入口。三類出口:正常、`_Reject`、以及我們自己的 bug。"""
        self._body_consumed = False
        try:
            self._handle()
        except _Reject as rejected:
            self._error(rejected.status, rejected.message)
        except Exception as exc:  # noqa: BLE001 —— 見下
            # 決策 8:`5xx` 的 body **只有例外型別名**,永不訊息、永不 traceback。
            # 例外訊息會轉述輸入(路徑、甚至密碼),traceback 的 frame 裡躺著
            # 密碼與 DEK(鐵律 5)。型別名足夠讓人開票,而且不含任何輸入。
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, type(exc).__name__)

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch

    def _handle(self) -> None:
        # 門 1:Host(決策 6)。在路由之前,故 `GET /` 也過這道門。
        if self.headers.get("Host", "") != self.server.expected_host:
            raise _Reject(HTTPStatus.FORBIDDEN, "unexpected Host header")

        route = self._route()
        if route.startswith(API_PREFIX):
            self._handle_api(route)
            return

        # 頁面只收 GET / HEAD。
        if self.command not in ("GET", "HEAD"):
            raise _Reject(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
        if route == PAGE_PATH:
            self._page()
            return
        raise _Reject(HTTPStatus.NOT_FOUND, "not found")

    def _route(self) -> str:
        """請求路徑,**去掉 query 與 fragment**。

        去 query 不只是為了路由:`_log_line` 記的是同一個值,而 token 若被某個
        客戶端塞進 `?token=`(Jupyter 式,決策的否決清單裡那條),去掉 query 就是
        它不會進 access log 的理由。
        """
        path = getattr(self, "path", "") or ""
        return path.split("?", 1)[0].split("#", 1)[0]

    def _handle_api(self, route: str) -> None:
        """`/api/*`:門 2–6 跑完才碰 body。"""
        # 門 2:方法。
        if self.command != "POST":
            raise _Reject(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

        # 門 3:Origin。缺席代表非瀏覽器客戶端(瀏覽器對跨來源 POST 一定送
        # Origin),放行;`null` 是個**字串**,不等於缺席,故照樣擋(決策 6)。
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.expected_origin:
            raise _Reject(HTTPStatus.FORBIDDEN, "unexpected Origin header")

        # 門 4:型別。`application/json; charset=utf-8` 算合格,`text/plain` 與
        # 缺席不算——表單的 `text/plain` / `multipart` 正是跨來源 POST 打得出來的
        # 三種型別,擋掉它們等於擋掉無 JS 的 CSRF 表單。
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if media_type.strip().lower() != JSON_MEDIA_TYPE:
            raise _Reject(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                f"Content-Type must be {JSON_MEDIA_TYPE}",
            )

        # 門 5:大小。在 `read()` 之前,故超標的 body 一個 byte 都不進記憶體。
        length = self._content_length()

        # 門 6:token(決策 5)。仍在 `read()` 之前。
        if not self._authorized():
            raise _Reject(HTTPStatus.UNAUTHORIZED, "missing or invalid bearer token")

        if route != API_INSPECT_PATH:
            raise _Reject(HTTPStatus.NOT_FOUND, "not found")

        self._api_inspect(self._read_json(length))

    # ------------------------------------------------------------ 門的實作

    def _content_length(self) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            length = int(raw)
        except ValueError:
            raise _Reject(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from None
        if length < 0:
            raise _Reject(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise _Reject(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"request body must be at most {MAX_BODY_BYTES} bytes",
            )
        return length

    def _authorized(self) -> bool:
        """`Authorization: Bearer <token>`,比對走 `hmac.compare_digest`(決策 5)。

        **不是** `==`:字串的 `==` 一比到不同的 byte 就回來,而這個伺服器就在
        攻擊者的瀏覽器打得到的地方——可量測的時間差會把 token 一個 byte 一個
        byte 地交出去。長度不同時 `compare_digest` 也不洩內容。

        標頭值由 `http.client` / 瀏覽器以 iso-8859-1 解碼,`latin-1` 編回去就是
        線上的原始 bytes;token 自己是 urlsafe base64(純 ASCII),兩邊同碼。
        """
        scheme, _, presented = self.headers.get("Authorization", "").partition(" ")
        if scheme != BEARER_SCHEME:
            return False
        return hmac.compare_digest(
            presented.encode("latin-1"), self.server.token.encode("latin-1")
        )

    def _read_json(self, length: int) -> dict:
        """讀 body 並解成 **JSON 物件**;其餘一律 `400`(決策 8)。

        `[]` / `"x"` / 壞 JSON / 空 body 都不是物件,四種同一個碼:回應不區分
        「你送了陣列」與「你送了半個 JSON」——錯誤訊息的顆粒度就是攻擊者的
        探測工具,而這裡沒有任何需要被區分的使用情境。
        """
        raw = bytearray()
        self._body_consumed = True
        while len(raw) < length:
            chunk = self.rfile.read(length - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        try:
            payload = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _Reject(
                HTTPStatus.BAD_REQUEST, "request body must be a JSON object"
            ) from None
        if not isinstance(payload, dict):
            raise _Reject(HTTPStatus.BAD_REQUEST, "request body must be a JSON object")
        return payload

    # ------------------------------------------------------------ 端點

    def _api_inspect(self, payload: dict) -> None:
        """`POST /api/inspect {"path"}` → 白名單欄位(決策 7 / [M7])。

        **不問密碼、也不讀密碼**:白名單的每一項都在明文 header 裡,而需要密碼
        才拿得到的兩樣東西(原始檔名、`orig_size`)正是決策 9 要保護的中繼資料。
        body 多給一個 `passphrase` 欄不會改變任何行為——本函式連看它一眼的
        程式碼都沒有(未知的鍵一律忽略)。
        """
        raw_path = payload.get("path")
        if not isinstance(raw_path, str):
            raise _Reject(HTTPStatus.BAD_REQUEST, "path must be a string")
        target = Path(raw_path)

        # 不是普通檔案的三種情況分開講,因為使用者的下一步不一樣(同
        # `cli._require_file`);訊息逐字相同,故 UI 與 CLI 不會各說一套。
        try:
            exists, is_dir, is_file = (
                target.exists(),
                target.is_dir(),
                target.is_file(),
            )
        except (OSError, ValueError):
            # 名字長到 `ENAMETOOLONG`、含 NUL…… 是使用錯誤,不是我們的 bug。
            raise _Reject(HTTPStatus.BAD_REQUEST, "path is not a usable file name") from None
        if not exists:
            raise _Reject(
                HTTPStatus.NOT_FOUND, f"input file does not exist: {target}"
            )
        if is_dir:
            # 目錄固定 `400`(AC 的「擇一並固定」):它**存在**,`404` 會讓前端
            # 與 #22–#25 的差異測試把「打錯路徑」和「選到資料夾」混成一句話。
            raise _Reject(
                HTTPStatus.BAD_REQUEST, f"input is a directory, not a file: {target}"
            )
        if not is_file:
            raise _Reject(
                HTTPStatus.BAD_REQUEST, f"input is not a regular file: {target}"
            )

        try:
            with open(target, "rb") as fh:
                size = os.fstat(fh.fileno()).st_size
                header, _ = deserialize(fh.read(HEADER_SIZE_KEM1))
        except QVaultError as exc:
            # 決策 8:`QVaultError` → `422`,訊息**逐字轉述**(一個字都不加),
            # 故 UI 與 CLI 對同一個壞檔說同一句話(保證④)。
            raise _Reject(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)) from None
        except FileNotFoundError as exc:
            raise _Reject(HTTPStatus.NOT_FOUND, _oserror_message(exc)) from None
        except (OSError, ValueError) as exc:
            message = _oserror_message(exc) if isinstance(exc, OSError) else "cannot read path"
            raise _Reject(HTTPStatus.BAD_REQUEST, message) from None

        result = {key: get(header) for key, get in _INSPECT_FIELDS}
        result["file_size"] = size
        self._json(HTTPStatus.OK, result)

    def _page(self) -> None:
        """佔位頁 + 決策 10 的五個標頭(CSP 在此,另三個由 `end_headers` 注入)。"""
        self._respond(
            HTTPStatus.OK,
            PLACEHOLDER_PAGE.encode("utf-8"),
            HTML_CONTENT_TYPE,
            (("Content-Security-Policy", CONTENT_SECURITY_POLICY),),
        )

    # ------------------------------------------------------------ 回應

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=False).encode("utf-8")
        self._respond(status, body, JSON_CONTENT_TYPE)

    def _error(self, status: HTTPStatus, message: str) -> None:
        """錯誤的唯一出口:JSON `{"error": "<一行>"}` + 關連線(決策 8)。"""
        self._respond(
            status,
            json.dumps({"error": message}, ensure_ascii=False).encode("utf-8"),
            JSON_CONTENT_TYPE,
            (("Connection", "close"),),
        )
        self._drain_request_body()

    def _drain_request_body(self) -> None:
        """lingering close:錯誤回應**寫完之後**,把對方宣告的 body 讀掉再關。

        這不是「讀 body 來做判斷」——六道門全部在 `_respond` 之前就判完了
        (`_body_consumed` 為真表示 body 是正常流程讀的,這裡不碰)。這是 TCP
        層的收尾:socket 裡還有沒讀完的位元組時關連線,核心發的是 **RST** 而不是
        FIN,而對方收到 RST 會把**連我們剛寫好的那個回應一起丟掉**——「413 偶發
        ConnectionReset」就是這麼來的。

        上限 1 MiB / 1 秒:只陪對方送到這裡,絕不無限奉陪。超過就直接關,寧可讓
        對方吃 RST——一個宣告 1 GB body 的客戶端不值得我們讀 1 GB。
        """
        if self._body_consumed:
            return
        headers = getattr(self, "headers", None)
        declared = headers.get("Content-Length") if headers else None
        try:
            remaining = min(int(declared), DRAIN_LIMIT_BYTES)
        except (TypeError, ValueError):
            return
        try:
            self.connection.settimeout(DRAIN_TIMEOUT_SECONDS)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _respond(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def end_headers(self) -> None:
        """決策 10 的三個標頭在**這裡**注入——每個回應一條不漏。

        放在 `_respond` 裡就只覆蓋我們自己發的回應;基底類別的 `send_error`
        (畸形請求行、請求行過長之類)會繞過它,而那些回應一樣是這個伺服器
        說出口的話。
        """
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    # ------------------------------------------------------------ log(決策 9)

    def log_request(self, code: object = "-", size: object = "-") -> None:
        """access log 的唯一格式:`<method> <path> <status>`。

        基底類別記的是 `self.requestline`——那是**原始請求行**,含 query 與 HTTP
        版本。query 可能帶 token,故這裡自己組:method、去掉 query 的 path、
        狀態碼,就這三樣。不記 headers、不記 body、不記 `size`。

        `code` 在 `send_error` 路徑上可能是 `HTTPStatus`;`path` 在請求行還沒
        解析成功時根本不存在(`_route` 的 `getattr` 顧到了)。
        """
        status = int(code) if isinstance(code, (int, HTTPStatus)) else code
        self.log_message("%s %s %s", self.command or "-", self._route() or "-", status)

    def log_message(self, fmt: str, *args: object) -> None:
        """寫一行到 stderr。`flush` 不能省:伺服器跑在別的執行緒,而測試要讀得到。"""
        sys.stderr.write((fmt % args) + "\n")
        sys.stderr.flush()

    def log_error(self, fmt: str, *args: object) -> None:
        """整個收掉(決策 9)。

        基底類別用它記 `send_error` 的訊息,而那些訊息會轉述請求行
        (`Bad request version ('…')`)——請求行是攻擊者寫的,不該被我們代為
        印到使用者的終端上。狀態碼本身已經由 `log_request` 記過一次。
        """


class WebUIServer(ThreadingHTTPServer):
    """只綁 loopback 的 `ThreadingHTTPServer` + 一把一次性 token(決策 4、5)。

    `__init__` 的參數只有 `port`,**而且不可以有別的**:位址是模組常數
    `LOOPBACK`。決策 4 要的「不能改綁定位址」因此在型別層面成立——不是文件說
    不要改,是沒有那個參數可以傳。
    """

    #: 連線執行緒是 daemon:`shutdown()` 不會被一條 keep-alive 連線卡住。
    daemon_threads = True

    def __init__(self, port: int = 0) -> None:
        super().__init__((LOOPBACK, port), _Handler)
        #: 每次啟動一把,32 bytes 的熵(決策 5)。不寫檔、不進 cookie /
        #: `localStorage` / `sessionStorage`、不進網址的 query——只經
        #: `self.url` 的 fragment 到瀏覽器。
        self.token = secrets.token_urlsafe(32)

    @property
    def port(self) -> int:
        """**實際**綁到的埠。`port=0` 時由 OS 配,故不能回傳建構子收到的那個值。"""
        return self.server_address[1]

    @property
    def url(self) -> str:
        """啟動時要印出來的那一行:token 在 **fragment**(決策 5)。

        fragment 不會被瀏覽器送到伺服器,故 token 不進 access log、不進
        `Referer`;頁面載入後由 JS 讀 `location.hash` 進記憶體並
        `history.replaceState` 清掉網址列(那段在 #23)。
        """
        return f"http://{LOOPBACK}:{self.port}/#{self.token}"

    @property
    def expected_host(self) -> str:
        """`Host` 必須恰等於這個(決策 6)。`localhost:<port>` 不算。"""
        return f"{LOOPBACK}:{self.port}"

    @property
    def expected_origin(self) -> str:
        """`Origin` 若存在必須恰等於這個(決策 6)。"""
        return f"http://{LOOPBACK}:{self.port}"

    def handle_error(self, request: object, client_address: object) -> None:
        """不印 traceback(決策 9 / 鐵律 5:frame 裡有密碼與 DEK)。

        `_Handler._dispatch` 已經把每個請求包起來了,所以這裡理論上到不了;
        留著是因為「理論上到不了」在 socket 層面從來不是保證,而預設行為是
        把整個 traceback 印到 stderr。
        """


def make_server(port: int = 0) -> WebUIServer:
    """建一個已綁好 `127.0.0.1:<port>` 的伺服器(還沒開始服務)。

    `port=0` → 由 OS 配一個空埠(測試一律用這個,免得撞)。回傳值的
    `serve_forever()` / `shutdown()` 是 `socketserver` 的原物。

    **簽章只有 `port`**:沒有 `host`、`bind`、`address`(決策 4)。要改這一點
    得改 `LOOPBACK` 這個模組常數,而那是一個 code review 看得見的 diff,不是
    一個使用者打得出來的命令列參數。

    埠被占 → `OSError` 原樣往上拋;翻成一行乾淨錯誤是 `qvault ui` 的事(#24)。
    """
    return WebUIServer(port)
