"""#28 的兩條硬化:請求形式的 fail-closed 分支(L1)與基底類別錯誤路徑的形式(L2)。

#27(複審 #21)留下的 low:**程式路徑本來就 fail-closed,但沒有測試釘住、或回應
形式與本層其餘部分不一致**。主管層 2026-11-14 的裁定把 L3(access log 去控制字元,
#39 / PR #41 已交付)與 fuzz 的 10,000 筆(#25 已落地)關掉,故本檔只有兩組:

  **L1 請求形式**(`tests/test_webui_server.py` 的六道門之外的那幾個分支)
      `Content-Length` 的每一個 `int()` 收得下而 RFC 不承認的形(`+12` / `1_000` /
      尾隨空白)、空字串 `Origin`、`Transfer-Encoding` 無 `Content-Length`、
      以及 `path` 指向 FIFO / 字元裝置這類**目錄以外的非普通檔**。

  **L2 回應形式**
      請求行還沒解析成功就被拒的那些錯誤(畸形請求行、`HTTP/9.9`、請求行超長)
      走的是基底類別的 `BaseHTTPRequestHandler.send_error`,一行本層的程式碼都不
      經過。ADR-002 決策 8 說「錯誤一律 JSON」、決策 10 說「所有回應都帶那三個
      安全標頭」,而它預設吐的是 HTML——裁定 2 選的是**覆寫**
      (`error_message_format` / `error_content_type`),故本檔驗的是覆寫後的形式。

一律**裸 socket**:要測的東西是線上的那幾個 byte(畸形的 `Content-Length` 值、
不帶 `Content-Length` 的 chunked 請求、壞版本的請求行),而 `http.client` 的
`putrequest` / `putheader` 會替我們把它們改正或當場拋 `InvalidURL`——用它就等於
測不到。回應以 `http.client.HTTPResponse` 解(標準庫,解狀態行與標頭),body 自己
`json.loads`。能用 `tests/webui_client.py` 的 `send`(一個**完全合格**的請求)
的地方就用它:不回歸的那幾條(普通檔仍 `200`)不需要控制到 byte。

伺服器一律 `port=0`、起在 daemon thread、測試結束 `shutdown()`——夾具 `server` 在
`tests/conftest.py`(共同範圍條款)。
"""

from __future__ import annotations

import ast
import http.client
import json
import os
import pathlib
import socket
import stat
import time

import pytest

from qvault_core import webui
from tests.webui_client import send

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"

#: 決策 10 的三個安全標頭,**寫死在測試裡**(不從 `webui.SECURITY_HEADERS` 讀:
#: 那張表被改掉時這裡要紅,不是跟著漂)。
THREE_SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)

#: 一個**剛好 12 byte** 的 JSON body。畸形 `Content-Length` 的那幾條都送它:
#: 宣告的數字(`+12` / `1_000` / `12 `)與實際送出的位元組無關,但送一份真的 body
#: 讓 `_drain_request_body` 的收尾有東西可讀、不必等到連線關閉。
TWELVE_BYTES = b'{"path": ""}'


class Reply:
    """一次裸 socket 交換的結果:狀態碼、reason phrase、標頭、body。"""

    def __init__(self, status: int, reason: str, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def json(self):
        return json.loads(self.body.decode("utf-8"))


def exchange(srv, request: bytes, timeout: float = 10.0) -> Reply:
    """把 `request` 的每一個 byte **原樣**送上去,回傳解好的回應。

    `http.client.HTTPResponse` 只負責解(狀態行 + 標頭 + 依 `Content-Length` 讀
    body);送的那一半刻意不經過任何客戶端程式庫——本檔要測的畸形形式有一半是
    `http.client` 自己會改掉的。
    """
    sock = socket.create_connection((webui.LOOPBACK, srv.port), timeout=timeout)
    try:
        sock.sendall(request)
        reply = http.client.HTTPResponse(sock, method="GET")
        reply.begin()
        try:
            return Reply(reply.status, reply.reason, reply.getheaders(), reply.read())
        finally:
            reply.close()
    finally:
        sock.close()


def api_request(srv, *, content_length: str, body: bytes = TWELVE_BYTES) -> bytes:
    """一個**除了 `Content-Length` 以外完全合格**的 `POST /api/inspect`。

    `Content-Length` 的值以字串原樣拼進請求——這正是要測的那一個 byte 序列。
    """
    return (
        f"POST {webui.API_INSPECT_PATH} HTTP/1.1\r\n"
        f"Host: {srv.expected_host}\r\n"
        f"Content-Type: {webui.JSON_MEDIA_TYPE}\r\n"
        f"Authorization: Bearer {srv.token}\r\n"
        f"Content-Length:{content_length}\r\n"
        "\r\n"
    ).encode("latin-1") + body


# ================================================================ L1:Content-Length 的形


def test_int_accepts_three_forms_the_rfc_does_not():
    """下面那幾條的**前提**:`int()` 收得下 `+12` / `1_000` / 尾隨空白。

    這條不碰伺服器,它釘的是「為什麼不能用 `int()`」。RFC 9110 §8.6 的文法是
    `1*DIGIT`,而 `int()` 多收三種形:正號、底線分隔、兩側空白。前提哪天在新的
    CPython 上不成立了(`int("1_000")` 開始拋),這條會先紅,而不是讓下面那幾條
    變成沒有理由的斷言。
    """
    assert int("+12") == 12
    assert int("1_000") == 1000
    assert int(" 12 ") == 12
    assert int("-1") == -1
    with pytest.raises(ValueError):
        int("abc")


@pytest.mark.parametrize(
    "value",
    [
        " -1",  # 負數:`int()` 收,長度不可能是負的
        " abc",  # 根本不是數字
        " +12",  # 正號:`int("+12")` → 12
        " 1_000",  # 底線分隔:`int("1_000")` → 1000
        "  12 ",  # 兩側空白:`int(" 12 ")` → 12
    ],
    ids=["minus-one", "abc", "plus-twelve", "underscored", "surrounding-space"],
)
def test_a_content_length_that_is_not_all_digits_is_400(server, value):
    """AC L1:`Content-Length` 不合 `^[0-9]+$` → `400`,**逐形各一條**(裁定 4 ①)。

    逐形而不是一條「隨便給個壞值」:只多擋一個 `-` 的實作(修正前的
    `int()` + `length < 0`)擋得住 `-1` 與 `abc`,但 `+12` / `1_000` / `12 ` 三形
    照樣放行,而那三形正是「伺服器與下一個解析者對同一個標頭算出不同長度」的
    原料(request smuggling)。

    `"  12 "` 這一形在線上是 `Content-Length:  12 `,而到得了 `_content_length`
    的值是 **`'12 '`**:標頭解析(`email` 的 feedparser)會把值的**前導**空白
    normalize 掉,尾隨的留著。所以「兩側空白」這一形真正承重的那一半是尾隨的
    那個空格——前導的那一半在我們看到之前就已經不存在,擋不擋得住不由本層決定。
    """
    reply = exchange(server, api_request(server, content_length=value))
    assert reply.status == 400, (value, reply.status, reply.body)
    assert reply.json() == {"error": "invalid Content-Length"}
    assert reply.header("Content-Type") == webui.JSON_CONTENT_TYPE


def test_an_empty_content_length_is_400(server):
    """`Content-Length:`(空值)也不合 `^[0-9]+$`——`+` 是「一個以上」。

    `int("")` 本來就拋,所以這一形修正前後都是 `400`;釘它是因為集合判定若寫成
    `issubset` 的方向錯了(空字串是任何集合的子集),空值會變成「合法」而
    `int("")` 當場拋 `ValueError` → 走到 `_dispatch` 的未預期例外 → `500`。
    """
    reply = exchange(server, api_request(server, content_length=" "))
    assert reply.status == 400
    assert reply.json() == {"error": "invalid Content-Length"}


def test_a_plain_digit_content_length_still_works(server):
    """不回歸:純數字的 `Content-Length` 照舊過門(golden 容器 → `200`)。"""
    body = json.dumps({"path": str(GOLDEN)}).encode("utf-8")
    request = (
        f"POST {webui.API_INSPECT_PATH} HTTP/1.1\r\n"
        f"Host: {server.expected_host}\r\n"
        f"Content-Type: {webui.JSON_MEDIA_TYPE}\r\n"
        f"Authorization: Bearer {server.token}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("latin-1") + body
    reply = exchange(server, request)
    assert reply.status == 200, reply.body
    assert "version" in reply.json()


def test_the_size_gate_still_answers_413_not_400(server):
    """門 5 的兩個碼沒有被混在一起:形式合法而**超標**的長度仍是 `413`。

    `1 << 30` 是一串純數字,所以它過得了形式判定,然後才撞上 64 KiB 的上限。
    改用正則最容易踩的回歸就是把這一條也變成 `400`(於是
    `tests/test_webui_server.py::test_lying_content_length_is_413_before_the_body_is_read`
    紅),這條在本檔這一側也釘一次。
    """
    reply = exchange(server, api_request(server, content_length=f" {1 << 30}"))
    assert reply.status == 413


# ================================================================ L1:空字串 Origin


def test_an_empty_origin_header_is_403(server):
    """AC L1:`Origin: `(空字串)→ `403`,即使 token 與 `Host` 都是對的。

    空字串**不等於缺席**:缺席(整個標頭不送)代表非瀏覽器客戶端,決策 6 放行;
    而 `Origin: ` 是有人送了這個標頭、值是空的——瀏覽器對 `data:` / sandbox 之類
    的不透明來源就是這麼送的(規範寫 `null`,但中間層與非瀏覽器客戶端送得出空
    字串),它不是「沒有跨來源的問題」,是「來源不可辨識」,故照樣擋。

    `_handle_api` 的判定是 `origin is not None and origin != expected`,空字串走
    的是第二個條件;修正前後行為相同,這條是把它**釘住**——有人把它寫成
    `if origin and origin != expected`(很容易,因為看起來更 Pythonic)就當場紅。
    """
    body = json.dumps({"path": str(GOLDEN)}).encode("utf-8")
    request = (
        f"POST {webui.API_INSPECT_PATH} HTTP/1.1\r\n"
        f"Host: {server.expected_host}\r\n"
        "Origin: \r\n"
        f"Content-Type: {webui.JSON_MEDIA_TYPE}\r\n"
        f"Authorization: Bearer {server.token}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("latin-1") + body
    reply = exchange(server, request)
    assert reply.status == 403
    assert reply.json() == {"error": "unexpected Origin header"}


# ================================================================ L1:framing(chunked)


def test_chunked_without_a_content_length_is_400_and_closes(server):
    """AC L1:`Transfer-Encoding: chunked` 且無 `Content-Length` → `400` + `Connection: close`。

    標準庫的 `BaseHTTPRequestHandler` **不支援** chunked 請求:它只看
    `Content-Length`,所以修正前這個請求會被當成「body 長度 0」→ `_read_json`
    拿到空 body → `400`。碼對了,但線上那串 chunk(`2\\r\\n{}\\r\\n0\\r\\n\\r\\n`)
    **還留在 socket 裡**,而 `/api/*` 的 `400` 會關連線所以看不出來;打到靜態
    路由的同一種請求就會把殘留的位元組交給 `handle_one_request` 當成下一個請求行
    (`.asp/pr/25.md` 記的那條「已知殘留」)。

    修正後它在門 1.2 就被擋掉,兩個斷言合起來才是 AC:`400` 說我們拒了,
    `Connection: close` 說那串我們讀不懂框的位元組不會被當成第二個請求。
    """
    request = (
        f"POST {webui.API_INSPECT_PATH} HTTP/1.1\r\n"
        f"Host: {server.expected_host}\r\n"
        f"Content-Type: {webui.JSON_MEDIA_TYPE}\r\n"
        f"Authorization: Bearer {server.token}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "2\r\n{}\r\n0\r\n\r\n"
    ).encode("latin-1")
    reply = exchange(server, request)
    assert reply.status == 400
    assert reply.json() == {"error": "Transfer-Encoding is not supported"}
    assert reply.header("Connection") == "close"


def test_chunked_together_with_a_content_length_is_also_400(server):
    """兩個都給也是 `400`:RFC 9110 §6.1 要拒的正是這一種(兩個解析者框出兩個訊息)。

    門 1.2 擋的是**整個標頭**而不是只擋「沒有 `Content-Length` 的 chunked」,
    理由在這裡看得見:同時給兩個是最經典的 smuggling 形,而「哪一個為準」沒有
    一個雙方一定同意的答案。fail-closed 就是不選。
    """
    reply = exchange(
        server,
        (
            f"POST {webui.API_INSPECT_PATH} HTTP/1.1\r\n"
            f"Host: {server.expected_host}\r\n"
            f"Content-Type: {webui.JSON_MEDIA_TYPE}\r\n"
            f"Authorization: Bearer {server.token}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 12\r\n"
            "\r\n"
        ).encode("latin-1")
        + TWELVE_BYTES,
    )
    assert reply.status == 400
    assert reply.json() == {"error": "Transfer-Encoding is not supported"}
    assert reply.header("Connection") == "close"


def test_a_chunked_get_on_a_static_route_is_400_too(server):
    """門 1.2 在**路由之前**,故靜態路由也受管(#25 的那條已知殘留因此關掉)。

    修正前:`GET /` + chunked → `200` + keep-alive,而線上那串 chunk 一個 byte
    都沒被讀掉 → 下一輪 `handle_one_request` 把它當請求行。現在整個請求在門 1.2
    就結束,連 `_STATIC_RESPONSES` 都查不到。
    """
    reply = exchange(
        server,
        (
            f"GET {webui.PAGE_PATH} HTTP/1.1\r\n"
            f"Host: {server.expected_host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n"
        ).encode("latin-1"),
    )
    assert reply.status == 400
    assert reply.json() == {"error": "Transfer-Encoding is not supported"}
    assert reply.header("Connection") == "close"


# ================================================================ L1:非普通檔的 path


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="`os.mkfifo` 是 POSIX 專屬")
def test_a_fifo_path_is_400_and_answers_within_a_second(server, tmp_path):
    """AC L1:`path` 指向 FIFO → `400`,而且請求 **1 秒內**回(不阻塞)。

    `open(fifo, "rb")` 會**阻塞**到有人從另一端寫入為止,而那一端由攻擊者決定:
    一個 `os.mkfifo` 的路徑就能把一條伺服器執行緒(以及 `qvault ui` 退出路徑的
    `wait_until_idle`)釘在那裡。`_input_file` 的型別判定(`Path.is_file()` =
    `os.stat` + `S_ISREG`)在 `open()` **之前**,所以這裡回的是
    `MSG_INPUT_NOT_REGULAR`。

    時間上限只是**症狀的量尺**,保證在型別判定那一側(裁定 4:「不得靠逾時」):
    靠逾時的實作交不出 1 秒——`_Handler.timeout` 是 10 秒,而 `open()` 的阻塞沒有
    任何逾時可言。1 秒對一個不開檔、只 `stat` 一次的路徑是三個數量級的餘裕。
    """
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert stat.S_ISFIFO(os.stat(fifo).st_mode)

    started = time.monotonic()
    res = send(server, payload={"path": str(fifo)})
    elapsed = time.monotonic() - started

    assert res.status == 400, res.body
    assert res.json() == {"error": f"input is not a regular file: {fifo}"}
    assert elapsed < 1.0, f"請求花了 {elapsed:.3f} 秒——判定跑到 open() 後面去了"


@pytest.mark.skipif(
    not os.path.exists("/dev/zero"), reason="沒有 `/dev/zero` 這個字元裝置可用"
)
def test_a_character_device_path_is_400(server):
    """AC L1:**目錄以外**的其他非普通檔也是 `400`(`/dev/zero`,字元裝置)。

    選 `/dev/zero` 而不是 `/dev/null`:前者讀起來是無窮多個 `\\x00`,所以「有沒有
    在判型別之前就開檔」兩者的差別看得見——真的開下去會讀到一個永遠填不滿的
    header。同一句訊息、同一個碼:本層不區分 FIFO / 字元裝置 / socket,它們對
    使用者的意義是同一句「這不是一個普通檔」。
    """
    res = send(server, payload={"path": "/dev/zero"})
    assert res.status == 400
    assert res.json() == {"error": "input is not a regular file: /dev/zero"}


def test_a_regular_file_is_still_accepted(server):
    """不回歸:普通檔(golden 向量)照舊 `200`。"""
    res = send(server, payload={"path": str(GOLDEN)})
    assert res.status == 200
    assert res.json()["version"] == 1


def _function_body(name: str) -> ast.FunctionDef:
    """`webui.py` 裡那個函式的 AST 節點(找不到就讓測試自己紅)。"""
    tree = ast.parse((REPO_ROOT / "qvault_core" / "webui.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"webui.py 沒有 {name}——它被改名或搬走了")


def _calls(node: ast.AST) -> list[str]:
    """`node` 底下每一個呼叫的**可讀名字**(`open`、`target.is_file`、…)。"""
    names = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            names.append(ast.unparse(child.func))
    return names


def test_the_input_file_check_stats_before_it_opens():
    """「不阻塞」的**結構面**證人:型別判定寫在 `open()` 之前,不是靠時間。

    掃的是 AST 而不是原始碼文字:這兩個函式的 docstring 裡**說明**「`open(fifo)`
    會阻塞」的那幾句本身就含 `open(` 的字樣,掃文字會把說明當成實作
    (同 `tests/test_webui_page.py` 掃 `importlib` 的那一條的理由)。

    兩件事:`_input_file` 自己**不開檔**(它只 `stat`,回一個已經確認是普通檔的
    `Path`);`_api_inspect` 的 `open()` 在 `_input_file()` **之後**。上面那條
    FIFO 的 1 秒是症狀,這條是原因——有人把 `open()` 搬到型別判定前面,它會紅。
    """
    in_input_file = _calls(_function_body("_input_file"))
    assert "open" not in in_input_file, (
        "`_input_file` 自己開了檔——型別判定就不在開檔之前了",
        in_input_file,
    )
    assert any(call.endswith(".is_file") for call in in_input_file), (
        "`_input_file` 不再判 S_ISREG(`Path.is_file()`)了",
        in_input_file,
    )

    in_inspect = _calls(_function_body("_api_inspect"))
    assert "open" in in_inspect, in_inspect
    assert in_inspect.index("self._input_file") < in_inspect.index("open"), in_inspect


# ================================================================ L2:基底類別的錯誤路徑


#: 三種**請求行還沒解析成功**就被拒的請求,它們都走基底類別的 `send_error`:
#: 本層的 `_dispatch` / `_error` 一行都不經過。
BASE_CLASS_ERRORS = {
    "bad-version": b"GET / HTTP/9.9\r\nHost: x\r\n\r\n",
    "bad-syntax": b"\x1b[2J\x1b[H\r\n\r\n",
    "over-long-request-line": b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\nHost: x\r\n\r\n",
}


@pytest.mark.parametrize("name", sorted(BASE_CLASS_ERRORS))
def test_the_base_class_error_path_answers_json(server, name):
    """AC L2:`send_error` 的 body 是 `{"error": …}`、型別是 `application/json`。

    覆寫前這條路吐的是 `DEFAULT_ERROR_MESSAGE` 那份 **HTML**
    (`error_content_type` 預設 `text/html;charset=utf-8`),於是決策 8
    「錯誤一律 JSON」有一個例外,而那個例外正好是攻擊者最容易打到的那條路
    (畸形請求行不需要 token、不需要對的 `Host`)。

    三種形各自的狀態碼不同(`HTTP/9.9` → `505`、畸形請求行 → `400`、
    請求行 > 65,536 bytes → `414`),而本條不管狀態碼:AC 要的是**形式**。
    """
    reply = exchange(server, BASE_CLASS_ERRORS[name])
    assert reply.header("Content-Type") == webui.JSON_CONTENT_TYPE
    assert set(reply.json()) == {"error"}, reply.body
    assert isinstance(reply.json()["error"], str)


@pytest.mark.parametrize("name", sorted(BASE_CLASS_ERRORS))
def test_the_base_class_error_path_carries_the_three_security_headers(server, name):
    """AC L2:三個安全標頭在那條路上也都在(決策 10「所有回應」)。

    標頭是 `end_headers` 注入的,而基底類別的 `send_error` 會呼叫它——**前提是
    它發得出標頭**。`parse_request` 先把 `request_version` 設成
    `default_request_version` 才去解版本欄,而基底類別的 `send_header` /
    `end_headers` 整段包在 `if self.request_version != 'HTTP/0.9'` 裡:預設值是
    `HTTP/0.9`,於是 `GET / HTTP/9.9` 的回應**一個標頭都沒有**,線上只有一份裸
    body。`_Handler.default_request_version = "HTTP/1.1"` 是補這個洞的那一行,
    這條測試是它的證人。
    """
    reply = exchange(server, BASE_CLASS_ERRORS[name])
    for header, value in THREE_SECURITY_HEADERS:
        assert reply.header(header) == value, (name, header, reply.headers)


@pytest.mark.parametrize("name", sorted(BASE_CLASS_ERRORS))
def test_the_base_class_error_path_closes_the_connection(server, name):
    """同一條路也不留連線:`send_error` 自己加 `Connection: close`。

    請求行解析失敗時我們連「這個請求到哪裡結束」都不知道,所以那條連線上的
    下一個 byte 不該被當成請求。
    """
    reply = exchange(server, BASE_CLASS_ERRORS[name])
    assert reply.header("Connection") == "close"


def test_the_over_long_request_line_is_414(server):
    """跨票對帳(裁定 4):請求行 > 65,536 bytes 在標準庫是 **414**。

    `414` **不在** `tests/test_webui_fuzz.py::ALLOWED_STATUS`
    ({200,400,401,403,404,405,409,413,415,422})裡。今天不衝突:那份語料以
    `http.client` 發請求,path 最長 64 個字元,打不出一個 65,537 byte 的請求行。
    本票不改 #25 的測試(裁判凍結),這條把事實釘在這裡——哪天有人把 fuzz 的
    path 長度放寬,他會先在這條測試看到 `414` 這個碼的存在。
    """
    reply = exchange(server, BASE_CLASS_ERRORS["over-long-request-line"])
    assert reply.status == 414


def test_the_bad_version_request_line_is_505_with_full_headers(server):
    """`GET / HTTP/9.9`:狀態碼是 `505`,而且狀態行與標頭都真的發出來了。

    AC 點名的就是這一筆。它是三種形裡唯一會踩到 `default_request_version` 那個
    洞的——另外兩種(畸形請求行、請求行超長)在 `send_error` 之前就已經把
    `request_version` 設成 `''`(不等於 `'HTTP/0.9'`),所以它們本來就發得出標頭。
    `505` 也因此是「覆寫有沒有真的生效」最便宜的一個證人。
    """
    reply = exchange(server, BASE_CLASS_ERRORS["bad-version"])
    assert reply.status == 505
    assert reply.json() == {"error": "request rejected (HTTP 505)"}


def test_the_error_body_never_echoes_the_request_line(server):
    """決策 9 的另一半:那份 JSON 裡**沒有**攻擊者寫的任何一個 byte。

    基底類別給 `send_error` 的 `message` 轉述請求行
    (`Bad request syntax ('…')`、`Invalid HTTP version (9.9)`),而
    `error_message_format` 裡刻意沒有 `%(message)s`:
    - 回顯攻擊者的字串本來就是 `log_error` 整個收掉要防的那件事,換個出口不會
      變成另一件事;
    - 基底類別對它做的是 `html.escape(message, quote=False)`——`"` 不會被處理,
      所以一個帶引號的請求行就能把這份 JSON 折斷,`json.loads` 當場失敗。
      決策 8 的「錯誤一律 JSON」會被一個畸形請求行打掉。

    所以這條送一個**帶引號與反斜線**的請求行,斷言 body 解得開、而且那串字元
    一個都不在裡面(狀態行的 reason phrase 同理,見下一條)。
    """
    marker = 'SENTINEL"\\x'
    reply = exchange(server, f"GET /{marker} HTTP/9.9\r\nHost: x\r\n\r\n".encode("latin-1"))
    assert reply.json() == {"error": "request rejected (HTTP 505)"}
    assert "SENTINEL" not in reply.body.decode("utf-8")


def test_the_status_line_never_echoes_the_request_line(server):
    """reason phrase 一律用標準短語(`send_response` 的覆寫),不用請求行。

    `send_error` 把它的 `message` 當 reason phrase 傳給 `send_response`,於是
    攻擊者的字串會出現在我們說出口的**第一行**。這條釘住它不會:
    `505` 的 reason 是標準短語 `HTTP Version Not Supported`。

    順帶守住一個壞掉的出口:`Invalid HTTP version (%s)` 用的是 `%s`,而版本欄的
    合法性只靠 `str.isdigit()`——那對 `'٩'`(U+0669,阿拉伯-印度數字)是真。
    狀態行以 `latin-1`、`strict` 編碼,所以修正前 `GET / HTTP/٩.٩` 會在送回應
    的途中拋 `UnicodeEncodeError`:連線被丟掉,客戶端連一個狀態碼都收不到。
    """
    reply = exchange(server, BASE_CLASS_ERRORS["bad-version"])
    assert reply.reason == "HTTP Version Not Supported"
    assert "9.9" not in reply.reason

    # `²`(U+00B2)是 latin-1 裡 `isdigit()` 為真的三個非 ASCII 字元之一,所以它
    # 進得了版本欄的 isdigit 檢查(然後 `int()` 收不下 → `400`)。修正前那個 `400`
    # 的 reason phrase 是 `Bad request version ('HTTP/².²')`——請求行原封不動進了
    # 狀態行;修正後是標準短語。
    superscript = exchange(server, b"GET / HTTP/\xb2.\xb2\r\nHost: x\r\n\r\n")
    assert superscript.status == 400
    assert superscript.reason == "Bad Request"
    assert superscript.json() == {"error": "request rejected (HTTP 400)"}


def test_the_error_format_is_valid_json_for_every_status_it_can_carry(server):
    """`error_message_format` 本身:插值後**必定**是合法 JSON,且不含請求行。

    基底類別的插值是 `fmt % {"code": …, "message": …, "explain": …}`,所以格式裡
    多一個 `%(message)s`(或一個裸 `%`)就會讓這份 body 隨輸入而變。這條直接對
    格式本身斷言,不經過伺服器:每一個本層發得出來的狀態碼都插一次,`json.loads`
    都要成功、鍵都恰為 `{"error"}`。
    """
    fmt = webui._Handler.error_message_format
    assert "%(message)s" not in fmt and "%(explain)s" not in fmt
    for code in (400, 404, 405, 413, 414, 500, 501, 505):
        body = fmt % {"code": code, "message": 'x"x\\x', "explain": "<b>"}
        assert set(json.loads(body)) == {"error"}, body
    assert webui._Handler.error_content_type == webui.JSON_CONTENT_TYPE


def test_the_base_class_error_path_writes_no_traceback(server, capfd):
    """那條路不吐 traceback、也不吐請求行(決策 8 / 9;`log_error` 整個收掉)。

    access log 只有 `log_request` 那一行(method / path 解析不出來時是 `-`),
    而本條順便釘住「那一行沒有把請求行帶進終端」。
    """
    capfd.readouterr()
    for request in BASE_CLASS_ERRORS.values():
        exchange(server, request)
    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert "Traceback" not in output, output
    assert "Bad request" not in output, output
    assert "Invalid HTTP version" not in output, output
    assert "a" * 100 not in output, output[:400]


def test_the_error_docstring_states_that_it_is_not_the_only_outlet():
    """AC L2 的措辭那一半:`_error` 的「唯一出口」要照實修(裁定 2)。

    修正前它寫「錯誤的唯一出口」,而基底類別的 `send_error` 是**第二個**出口
    (那時還吐 HTML)。docstring 說錯的代價是下一個人讀完以為「所有錯誤都經過
    `_error`」,於是在那裡加一道檢查、以為蓋住了全部的錯誤回應。

    斷言的是那幾個**關鍵事實**在不在(第二個出口的名字、它為什麼同形),不是逐字
    比對整段話——後者只會讓任何潤稿都變成紅燈(同
    `tests/test_webui_log_premise.py::test_the_escaped_docstring_states_the_premise`)。
    """
    doc = webui._Handler._error.__doc__ or ""
    for fact in ("send_error", "error_message_format", "「唯一」限定在"):
        assert fact in doc, f"`_error` 的 docstring 沒寫到 {fact}"
    # 修正前的第一句是「錯誤的唯一出口」,沒有任何限定詞;現在那個「唯一」必須
    # 帶著「本層自己判出來的」這個限定一起出現。
    first_line = doc.splitlines()[0]
    assert "本層自己判出來的" in first_line, first_line
