"""Web UI 測試的 HTTP 用戶端工具(#21 起用,#22 起由兩個測試檔共用)。

從 `tests/test_webui_server.py` **原樣**搬出(#30 複審 M1):共用工具住在一個非測試模組,
兩個測試檔都 import 這裡,而不是一個測試檔 import 另一個測試檔。夾具 `server` 在
`tests/conftest.py`(pytest 自動發現,不需 import)。
"""

from __future__ import annotations

import http.client
import json

from qvault_core import webui

_DEFAULT = object()


class Response:
    """一次請求的結果:狀態碼、標頭、body(bytes)。"""

    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))


def send(
    srv,
    method: str = "POST",
    path: str = webui.API_INSPECT_PATH,
    *,
    payload=_DEFAULT,
    raw_body: bytes | None = None,
    declared_length: int | None = None,
    token=_DEFAULT,
    host=_DEFAULT,
    origin: str | None = None,
    content_type=_DEFAULT,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> Response:
    """以 `http.client` 發一個請求,每一道門都可以單獨拆掉。

    `_DEFAULT` = 「送正確的那個值」;`None` = 「整個標頭不送」。預設是一個
    **完全合格**的請求,故每條測試只動它要測的那一樣東西。
    """
    body = b""
    if raw_body is not None:
        body = raw_body
    elif payload is not _DEFAULT:
        body = json.dumps(payload).encode("utf-8")

    conn = http.client.HTTPConnection(webui.LOOPBACK, srv.port, timeout=10)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host is _DEFAULT:
            conn.putheader("Host", srv.expected_host)
        elif host is not None:
            conn.putheader("Host", host)
        if origin is not None:
            conn.putheader("Origin", origin)
        if content_type is _DEFAULT:
            if method == "POST":
                conn.putheader("Content-Type", webui.JSON_MEDIA_TYPE)
        elif content_type is not None:
            conn.putheader("Content-Type", content_type)
        if token is _DEFAULT:
            conn.putheader("Authorization", f"Bearer {srv.token}")
        elif token is not None:
            conn.putheader("Authorization", token)
        length = declared_length if declared_length is not None else len(body)
        conn.putheader("Content-Length", str(length))
        for name, value in extra_headers:
            conn.putheader(name, value)
        conn.endheaders(body if body else None)
        raw = conn.getresponse()
        return Response(raw.status, raw.getheaders(), raw.read())
    finally:
        conn.close()
