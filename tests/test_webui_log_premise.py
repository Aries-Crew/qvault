"""access log 跳脫表的**前提**守衛(#42 F6;表本身的覆蓋範圍在 `test_webui_server.py`)。

`qvault_core/webui.py` 的 `_CONTROL_CHAR_TABLE` 到 U+009F 封頂,而它「夠用」是
**有前提的**:到得了 `log_message` 的 path 來自
`BaseHTTPRequestHandler.parse_request` 的
`requestline = str(self.raw_requestline, "iso-8859-1")`,解得出來的字元恰好是
U+0000–U+00FF,所以 C0 / DEL / C1 一張表蓋得住所有到得了那一層的控制字元。

缺口只在有人補上**百分號解碼**時才開:`unquote("%E2%80%AE")` 是真的 U+202E
(`Cf`,雙向覆寫),它不在表上,會原封不動落到使用者的終端,把 access log 那一行
的 path 視覺上反轉。`_escaped` 的 docstring 寫了這個前提,但 docstring 不是承重的
那一半——**本檔是**:

  `test_the_request_line_path_never_percent_decodes`  以 `ast` 掃 `webui.py`,
      請求行處理路徑上出現任何 `unquote` 家族的呼叫或匯入即紅;
  `test_injecting_a_percent_decoder_turns_the_guard_red`  反過來證明上面那條
      掃描真的載重:五種寫法各注入一次(**在記憶體裡**改 source,不碰
      `webui.py`),每一種都要被點名——否則「掃描」只是一條永遠綠的斷言;
  `test_a_percent_encoded_bidi_override_stays_percent_encoded_in_the_log`
      同一件事的行為面證人:`%E2%80%AE` 打進去,log 裡還是那九個可印字元。

本檔不 import 任何測試檔(AGENTS.md:gate 的 ruff 以 `--ignore-noqa` 判
F401 / F811);要讀 `tests/test_webui_server.py` 的 docstring 時讀的是它的
**原始碼文字**,不是模組。
"""

from __future__ import annotations

import ast
import pathlib
import socket

import pytest

from qvault_core import webui

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBUI_PATH = REPO_ROOT / "qvault_core" / "webui.py"
WEBUI_SOURCE = WEBUI_PATH.read_text(encoding="utf-8")
SERVER_TESTS_PATH = REPO_ROOT / "tests" / "test_webui_server.py"

#: 百分號解碼的每一個入口(`urllib.parse` 的全部三個;`quote` 不算——它只會
#: 讓字元更安全)。裸名、`urllib.parse.` 前綴、`as` 別名三種寫法都要認得。
PERCENT_DECODERS = ("unquote", "unquote_plus", "unquote_to_bytes")

#: `_route` 裡那一行(注入點的錨)。寫死在這裡是故意的:`webui.py` 哪天改了
#: 這一行,下面的突變測試會當場失敗,而不是靜靜地注入到一個不存在的地方、
#: 讓「掃描抓得到」變成一條沒有證據的宣稱。
ROUTE_ANCHOR = '        path = getattr(self, "path", "") or ""'


def percent_decoding_sites(source: str) -> list[tuple[str, str]]:
    """`source` 裡每一個百分號解碼的**呼叫或匯入** → `(所在函式名, 寫法)`。

    與 `test_webui_server.py::terminal_writes` 同一套遞迴法(`ast.walk` 會讓外層
    函式也看到內層的呼叫,同一個呼叫記兩次、所在函式還記錯),另外多認兩件事:

    - **匯入也算一個點**:`from urllib.parse import unquote` 即使這一輪沒被呼叫,
      也已經是「這條路上有人想解碼」的證據,而且下一個 commit 只要加一個呼叫
      就成立——匯入記成 `("<import>", …)`。
    - **別名**:`from urllib.parse import unquote as _u` 之後的 `_u(path)` 從
      呼叫端看不出是解碼,所以先收集匯入表,再用它判呼叫。
    """
    tree = ast.parse(source)

    aliases: dict[str, str] = {}
    sites: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in PERCENT_DECODERS:
                    aliases[alias.asname or alias.name] = alias.name
                    sites.append(("<import>", f"from {node.module} import {alias.name}"))

    def descend(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                descend(child, child.name)
                continue
            if isinstance(child, ast.Call):
                written = ast.unparse(child.func)
                # `urllib.parse.unquote` / `parse.unquote` / 裸名 一律看最後一節;
                # 別名走上面收集的匯入表。
                if written.rsplit(".", 1)[-1] in PERCENT_DECODERS or written in aliases:
                    sites.append((owner, written))
            descend(child, owner)

    descend(tree, "<module>")
    return sites


def _mutate_route(injection: str, *, imports: str = "") -> str:
    """把 `injection` 插進 `_route` 的第一行之後(**只在記憶體裡**)。

    `imports` 補在 `from __future__` 之後那一段的結尾,讓突變樣本長得像真的
    有人改了這個檔,而不是一句語法上孤立的呼叫。
    """
    assert WEBUI_SOURCE.count(ROUTE_ANCHOR) == 1, "`_route` 的注入錨漂掉了"
    mutant = WEBUI_SOURCE.replace(ROUTE_ANCHOR, f"{ROUTE_ANCHOR}\n        {injection}")
    if imports:
        anchor = "import threading\n"
        assert mutant.count(anchor) == 1, "匯入段的錨漂掉了"
        mutant = mutant.replace(anchor, f"{anchor}{imports}\n")
    ast.parse(mutant)  # 樣本本身要是合法 Python,否則證明不了任何事
    return mutant


#: F6 的突變樣本:五種把百分號解碼接回請求行路徑的寫法。
PERCENT_DECODE_MUTANTS = {
    "urllib.parse.unquote": (
        "path = urllib.parse.unquote(path)",
        "import urllib.parse",
    ),
    "bare-unquote": (
        "path = unquote(path)",
        "from urllib.parse import unquote",
    ),
    "unquote_plus": (
        "path = unquote_plus(path)",
        "from urllib.parse import unquote_plus",
    ),
    "aliased": (
        "path = _u(path)",
        "from urllib.parse import unquote as _u",
    ),
    "unquote_to_bytes": (
        'path = urllib.parse.unquote_to_bytes(path).decode("utf-8", "replace")',
        "import urllib.parse",
    ),
}


def test_the_request_line_path_never_percent_decodes():
    """F6:`webui.py` 一個百分號解碼都沒有——跳脫表的前提因此成立。

    掃的是**整個檔案**而不是只有 `_route`:解碼放在 `log_request`、`do_GET`、
    或任何一個把 `self.path` 傳下去的地方,效果完全一樣(落到 `_escaped` 的
    字串裡就會有 U+009F 以上的字元)。整檔零命中是一條好守的線,而 `webui.py`
    本來就沒有任何需要解碼 path 的理由:路由是逐字比對的常數路徑。
    """
    assert percent_decoding_sites(WEBUI_SOURCE) == []


@pytest.mark.parametrize(
    ("injection", "imports"),
    list(PERCENT_DECODE_MUTANTS.values()),
    ids=list(PERCENT_DECODE_MUTANTS),
)
def test_injecting_a_percent_decoder_turns_the_guard_red(injection, imports):
    """上面那條掃描**真的載重**:五種寫法各注入一次,每一種都要被點名。

    突變只發生在記憶體裡的一份 source 複本上——`qvault_core/webui.py` 一個 byte
    都沒被改。沒有這條的話「掃描式斷言」可以是一條永遠綠的擺設(本 repo 從
    `.asp/pr/1.md` 起就用突變實測證明測試載重)。
    """
    sites = percent_decoding_sites(_mutate_route(injection, imports=imports))
    assert sites, f"注入 `{injection}` 之後掃描還是綠的"
    assert any(owner == "_route" for owner, _ in sites), sites


def test_the_escaped_docstring_states_the_premise():
    """F6 的另一半:前提寫在 `_escaped` 的 docstring 裡,讀碼的人看得到。

    斷言的是**那幾個關鍵事實**在不在(解碼方式、上緣、以及「不得百分號解碼」
    這個前提),不是逐字比對整段話——後者只會讓任何潤稿都變成紅燈。
    """
    doc = webui._escaped.__doc__ or ""
    for fact in ("iso-8859-1", "U+00FF", "U+009F", "百分號解碼", "unquote"):
        assert fact in doc, f"`_escaped` 的 docstring 沒寫到 {fact}"


def test_the_malformed_request_line_test_says_what_it_guards():
    """F5:那條測試的 docstring 要寫明它守的是「這條路沒有可注入的輸出」。

    它走的是基底類別的 `send_error` → `log_error`,而 `log_error` 整個收掉:
    所以它**對跳脫表不敏感**(把 `_escaped` 整個拿掉它照樣綠),守的是「這條路
    不出聲」。docstring 說錯的代價是下一個人拿它當跳脫的回歸測試,然後刪掉
    真正在守跳脫的那幾條。

    讀的是 `tests/test_webui_server.py` 的**原始碼文字**:測試檔不得 import
    另一個測試檔(AGENTS.md)。
    """
    tree = ast.parse(SERVER_TESTS_PATH.read_text(encoding="utf-8"))
    docs = {
        node.name: ast.get_docstring(node) or ""
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    name = "test_malformed_request_lines_never_reach_the_terminal_unescaped"
    assert name in docs, "那條測試被改名或搬走了"
    assert "這條路沒有可注入的輸出" in docs[name], docs[name]


def test_a_percent_encoded_bidi_override_stays_percent_encoded_in_the_log(server, capfd):
    """前提的**行為面**證人:`%E2%80%AE` 進得去,U+202E 出不來。

    `Host` 故意是錯的(403 一樣會經 `send_response` 進 access log),所以這條
    不需要 token。有人補上 `unquote` 的那一天,這條與上面的 AST 掃描會一起紅:
    log 裡會出現真的 U+202E——它不在 C0/C1 的表上,所以跳脫不了它。
    """
    capfd.readouterr()
    raw = socket.create_connection((webui.LOOPBACK, server.port), timeout=5)
    try:
        raw.sendall(b"GET /%E2%80%AEx HTTP/1.1\r\nHost: x\r\n\r\n")
        status_line = raw.makefile("rb").readline()
    finally:
        raw.close()
    assert b"403" in status_line, status_line

    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert "\u202e" not in output, "請求行被百分號解碼了:跳脫表的上緣成了缺口"
    lines = [line for line in output.splitlines() if line.strip()]
    assert lines == ["GET /%E2%80%AEx 403"], lines
