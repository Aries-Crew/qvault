"""`qvault ui` 的測試(#24;設計見 `docs/adr/ADR-002-local-web-ui.md` 決策 4、12)。

本檔的測試分三種層級,刻意不混在一起:

- **子程序層級**(AC 1–4):`subprocess.Popen(..., stdout=PIPE, stderr=PIPE, text=True)`
  跑真的 `python -m qvault_core.cli ui`,讀 stdout 第一行、對那個網址打真的
  HTTP、送真的 `SIGINT` / `SIGTERM`。印網址與乾淨退出這兩件事**只有**在真行程
  裡才算證明:緩衝(不 `flush` 的那一行要等行程結束才出來)與 signal
  (in-process 收不到)兩者都是 in-process 測試看不見的坑。
- **in-process 層級**(AC 5):`cli.main(["ui", ...])` + 接管 `serve_forever` 與
  `webbrowser.open`——「開瀏覽器開的是印出來的那個網址」這條在子程序裡驗不了
  (worker 沒有瀏覽器,ADR-002 決策 14 明列)。
- **參數 / 文件層級**(AC 6–8):`argparse` 的選項字串、兩份 `--help`、README。

`webbrowser.open` 一律打 **`cli.webbrowser.open`**(模組屬性),不是
`cli.open`——實作用 `import webbrowser`、呼叫點寫 `webbrowser.open(...)`,
`from webbrowser import open` 那種綁名擋不住(`.asp/pr/1.md` 記過同一個坑),
故另有一條 `ast` 測試把 import 形式釘死。

HTTP 用戶端取自 `tests/webui_client.py`(與 #21–#23 共用同一份);子程序裡的
伺服器以 `_Remote` 這個替身交給它,**不**另寫一份請求組裝。
"""

from __future__ import annotations

import ast
import contextlib
import http.client
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

from qvault_core import cli, webui

# `send` 是工具,住在非測試模組 `tests/webui_client.py`(AGENTS.md:測試檔不得
# import 另一個測試檔)。
from tests.webui_client import send

# ---------------------------------------------------------------- 夾具與工具

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_PATH = REPO_ROOT / "qvault_core" / "cli.py"
README_PATH = REPO_ROOT / "README.md"
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"

#: AC 第 1 條的正則,**逐字**照抄:`token_urlsafe(32)` = 43 個 base64url 字元。
URL_RE = re.compile(r"^http://127\.0\.0\.1:\d+/#[A-Za-z0-9_-]{43}$")

#: 同一條網址,但把 port 與 token 抓出來給後面的 HTTP 與斷言用。
URL_PARTS_RE = re.compile(r"^http://(127\.0\.0\.1):(\d+)/#([A-Za-z0-9_-]{43})$")

#: AC:讀第一行逾時 10 秒即失敗並 kill。
READ_TIMEOUT = 10.0

#: AC:收到 signal 後 5 秒內要結束。
EXIT_TIMEOUT = 5.0

#: Windows 的 `send_signal` 不送 POSIX signal(`SIGTERM` → `TerminateProcess`,
#: `SIGINT` 根本不支援),故 signal 那一組只在 POSIX 上跑。乾淨退出的**行為**
#: 在 Windows 上由 Ctrl-C 的 `KeyboardInterrupt` 那條 in-process 測試守著。
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="send_signal 在 Windows 上不是 POSIX signal"
)


def _env() -> dict[str, str]:
    """子程序的環境:`PYTHONPATH` 指到 repo(同 `tests/test_cli.py::run_module`)。"""
    return dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONIOENCODING="utf-8")


@contextlib.contextmanager
def ui_process(*argv: str):
    """跑 `python -m qvault_core.cli ui <argv>`;離開時保證行程不留在樹上。"""
    proc = subprocess.Popen(
        [sys.executable, "-m", "qvault_core.cli", "ui", *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
        cwd=str(REPO_ROOT),
    )
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=EXIT_TIMEOUT)
        proc.stdout.close()
        proc.stderr.close()


def first_line(proc: subprocess.Popen, timeout: float = READ_TIMEOUT) -> str:
    """stdout 的第一行;逾時即 **kill + 失敗**(AC 的測試形式)。

    `readline()` 會無限期阻塞,所以讀它的是一條 daemon thread,主執行緒只等
    `timeout`:伺服器忘了 `flush` 或根本沒印,這裡要在 10 秒內紅掉,而不是把
    整個測試回合吊死。
    """
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.append(proc.stdout.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive() or not lines or not lines[0].strip():
        proc.kill()
        proc.wait(timeout=EXIT_TIMEOUT)
        raise AssertionError(f"{timeout} 秒內沒讀到 stdout 的第一行:{lines!r}")
    return lines[0].rstrip("\n")


class _Remote:
    """子程序裡那個伺服器的替身,給 `tests/webui_client.send` 用。

    `send` 只摸 `port` / `token` / `expected_host` 三個屬性,所以「in-process 的
    伺服器」與「子程序裡的伺服器」可以共用同一份用戶端——AC 第 2 條要的是子程序
    層級的 E2E,不是另寫一套請求組裝(兩套會漂,而漂掉的是六道門的斷言)。
    """

    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.token = token

    @property
    def expected_host(self) -> str:
        return f"{webui.LOOPBACK}:{self.port}"


@contextlib.contextmanager
def running_ui(*argv: str):
    """起一個 `--no-browser --port 0` 的 `ui`,yield `(proc, url, _Remote)`。"""
    with ui_process("--no-browser", "--port", "0", *argv) as proc:
        url = first_line(proc)
        parts = URL_PARTS_RE.match(url)
        assert parts, f"stdout 第一行不是 AC 要的那條網址:{url!r}"
        yield proc, url, _Remote(int(parts.group(2)), parts.group(3))


def occupied_port() -> tuple[socket.socket, int]:
    """自己 bind + listen 一個埠,回 `(socket, port)`——呼叫端負責關。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((webui.LOOPBACK, 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


def clean_failure(done: subprocess.CompletedProcess) -> str:
    """斷言「非零 exit + stderr 恰一行 `qvault: …` + 無 traceback」,回那一行。

    與 `tests/test_cli.py::clean_failure` 同一條規矩(那個吃 capsys,這個吃真
    行程的輸出),故 `ui` 的失敗出口與其他三個子命令長得一模一樣。
    """
    assert done.returncode != 0, "失敗的操作必須以非零 exit 收場"
    assert "Traceback" not in done.stderr
    assert "Traceback" not in done.stdout
    assert done.stdout == "", f"失敗的 `ui` 不該印出任何網址:{done.stdout!r}"
    lines = [line for line in done.stderr.splitlines() if line]
    assert len(lines) == 1, f"錯誤輸出不是一行:{lines!r}"
    assert lines[0].startswith("qvault: "), lines[0]
    return lines[0]


@pytest.fixture
def opened(monkeypatch):
    """接管 `cli.webbrowser.open`(模組屬性),記下每一次呼叫的網址。"""
    calls: list[str] = []

    def fake_open(url, *args, **kwargs):
        calls.append(url)
        return True

    monkeypatch.setattr(cli.webbrowser, "open", fake_open)
    return calls


@pytest.fixture
def serve_forever(monkeypatch):
    """回一個 `install(body=None)`:把 `WebUIServer.serve_forever` 換掉。

    回傳的 list 會收到**每一個**被服務的伺服器實例(故「有沒有真的開始服務」
    與「服務完有沒有被關掉」都驗得到);`body` 是在「服務中」那一刻要做的事
    (丟 `KeyboardInterrupt`、呼叫已安裝的 `SIGTERM` handler…)。
    """

    def install(body=None):
        served: list[webui.WebUIServer] = []

        def fake_serve_forever(self, *args, **kwargs):
            served.append(self)
            if body is not None:
                body()

        monkeypatch.setattr(webui.WebUIServer, "serve_forever", fake_serve_forever)
        return served

    return install


# ================================================================ AC 1:印出來的那一行


@posix_only
def test_the_first_stdout_line_is_the_url_and_it_is_printed_once():
    """AC 1:stdout 第一行恰為 `http://127.0.0.1:<port>/#<token>`,且只印一次。

    「只印一次」驗的是**整個 stdout**:第一行讀掉之後,送 `SIGINT` 再把剩下的
    讀到 EOF,必須是空的——重印一次(例如開瀏覽器前後各印一次)或補一句告別詞
    都會在這裡紅掉。stdout 只有這一行,`qvault ui | head -1` 才接得動。
    """
    with ui_process("--no-browser", "--port", "0") as proc:
        url = first_line(proc)
        assert URL_RE.match(url), f"不合 AC 的正則:{url!r}"
        proc.send_signal(signal.SIGINT)
        rest_out, err = proc.communicate(timeout=EXIT_TIMEOUT)
    assert rest_out == "", f"stdout 不只那一行:{rest_out!r}"
    assert err == "", f"乾淨退出不該吐任何 stderr:{err!r}"


def test_the_url_is_printed_before_the_server_starts_serving():
    """AC 1 的「什麼時候印」:在 `serve_forever` 之前,而且有 flush。

    `serve_forever` 一跑就不回來,所以「印在服務之後」= 永遠不印;而印了不
    `flush`(stdout 接管線時是區塊緩衝)= 要等行程結束才看得到,對一個「跑到
    你按 Ctrl-C」的命令來說也是永遠不印。這條讀到那一行的時候行程**還活著**,
    兩種坑一起擋掉。
    """
    with ui_process("--no-browser", "--port", "0") as proc:
        # 讀到了第一行,而行程**還在跑**——證明那一行是服務開始前就 flush 的。
        url = first_line(proc)
        assert URL_RE.match(url), url
        assert proc.poll() is None, "印完網址之後行程就結束了,它沒有在服務"


# ================================================================ AC 2:真行程的 E2E


def test_the_printed_url_and_token_answer_api_inspect_in_a_real_process():
    """AC 2:從那一行解析 port 與 token,`POST /api/inspect` golden → `200`。

    子程序層級的 E2E:證明「印出來的那個 port 真的在 listen」「印出來的那個
    token 真的是伺服器認的那一把」。in-process 測試驗不到這兩件事——它拿的是
    伺服器物件本身,而不是那一行文字。
    """
    with running_ui() as (_proc, _url, remote):
        res = send(remote, payload={"path": str(GOLDEN)})
    assert res.status == 200, res.text
    body = res.json()
    assert body["version"] == 1
    assert body["aead_name"] == "AES-256-GCM"
    # [M7]:白名單之外的東西一個都不准出現(與 CLI 的 `inspect` 同一條禁令)。
    for secret in ("salt", "nonce_prefix", "wrapped_dek"):
        assert secret not in body


def test_only_the_printed_token_gets_in():
    """AC 2 的反面:換一把 token → `401`(那一行不是裝飾,是鑑權)。

    token 是 43 個字元的 base64url;這裡換掉的是**內容**不是形狀,所以紅掉只
    可能是「伺服器其實沒在比對」。
    """
    with running_ui() as (_proc, _url, remote):
        res = send(remote, payload={"path": str(GOLDEN)}, token="Bearer " + "x" * 43)
    assert res.status == 401


# ================================================================ AC 3:乾淨退出


@posix_only
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_stops_it_within_five_seconds_with_exit_zero(sig):
    """AC 3:`SIGINT` / `SIGTERM` → 5 秒內結束、`returncode == 0`、無 traceback。

    `SIGINT` 走標準庫丟的 `KeyboardInterrupt`;`SIGTERM` 走 handler 自己裝的
    那個(預設沒有 handler,行程會以 `-15` 收場而不是 0,所以這兩格缺一不可)。
    5 秒由 `communicate(timeout=...)` 強制:逾時丟 `TimeoutExpired` = 測試紅。
    """
    with running_ui() as (proc, _url, _remote):
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
    assert proc.returncode == 0, f"{sig!r} 沒有乾淨退出:rc={proc.returncode} err={err!r}"
    assert "Traceback" not in err
    assert "Traceback" not in out
    assert err == "", f"乾淨退出不印任何東西到 stderr:{err!r}"


@posix_only
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_the_port_is_free_again_after_a_clean_exit(sig):
    """AC 3 的延伸:退出後那個埠真的綁得回來。

    驗的是「行程收乾淨了」這件事的使用者可見後果——下一次 `qvault ui --port N`
    不會撞到自己剛剛留下的那個。行程結束時 OS 也會回收 fd,所以這條**不是**
    `server_close()` 的守門人(那是
    `test_the_server_is_closed_before_main_returns` 的事,它驗的是 `main` 還沒
    回來之前就關掉了——`ui` 可能是一個跑很久的行程,不能靠行程結束來收)。
    """
    with running_ui() as (proc, _url, remote):
        port = remote.port
        proc.send_signal(sig)
        proc.communicate(timeout=EXIT_TIMEOUT)
    assert proc.returncode == 0
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((webui.LOOPBACK, port))
    finally:
        probe.close()


# ================================================================ AC 4:埠被占


def test_an_occupied_port_is_one_clean_line_on_stderr():
    """AC 4:`--port <已被占用>` → 一行 `qvault: …`、非零 exit、無 traceback。

    測試自己先 bind + listen 一個埠再把它交給 `ui`。訊息要認得出是「哪個位址
    綁不起來」:`Address already in use` 單獨一句看不出是誰占了什麼。
    """
    sock, port = occupied_port()
    try:
        done = subprocess.run(
            [sys.executable, "-m", "qvault_core.cli", "ui", "--no-browser", "--port", str(port)],
            capture_output=True,
            text=True,
            env=_env(),
            cwd=str(REPO_ROOT),
            timeout=READ_TIMEOUT,
        )
    finally:
        sock.close()
    line = clean_failure(done)
    assert f"{webui.LOOPBACK}:{port}" in line, line


def test_a_port_outside_the_range_is_one_clean_line_too():
    """AC 4 的鄰居:`--port 99999`。

    `bind` 對範圍外的埠丟的是 `OverflowError`(**不是** `OSError`),會掉進
    `main()` 的「internal error (…)」——那是「我們有 bug」的措辭,而使用者只是
    打錯了一個數字。故範圍在 handler 內先擋。
    """
    done = subprocess.run(
        [sys.executable, "-m", "qvault_core.cli", "ui", "--no-browser", "--port", "99999"],
        capture_output=True,
        text=True,
        env=_env(),
        cwd=str(REPO_ROOT),
        timeout=READ_TIMEOUT,
    )
    line = clean_failure(done)
    assert "internal error" not in line, line
    assert "--port" in line


def test_a_non_integer_port_is_an_argparse_usage_error(capsys):
    """`--port abc` → argparse 自己的 `SystemExit(2)`,不是我們的例外。"""
    with pytest.raises(SystemExit) as exc:
        cli.main(["ui", "--port", "abc"])
    assert exc.value.code != 0
    assert "Traceback" not in capsys.readouterr().err


# ================================================================ AC 5:開瀏覽器


def test_the_default_opens_the_browser_at_the_url_it_printed(opened, serve_forever, capsys):
    """AC 5:預設 → `webbrowser.open` **被呼叫一次**,參數等於印出的那個網址。

    「等於印出的那個」是重點:自己再組一次網址(或少了 fragment)會讓瀏覽器
    拿不到 token,而伺服器那邊完全正常——這種 bug 只有這條比得出來。
    """
    served = serve_forever()
    assert cli.main(["ui", "--port", "0"]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 1, printed
    assert URL_RE.match(printed[0]), printed[0]
    assert opened == [printed[0]]
    assert len(served) == 1, "沒有真的進到服務"


def test_no_browser_prints_the_url_and_opens_nothing(opened, serve_forever, capsys):
    """AC 5 的另一半:`--no-browser` → `webbrowser.open` 一次都不被呼叫。"""
    served = serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 1, printed
    assert URL_RE.match(printed[0]), printed[0]
    assert opened == []
    assert len(served) == 1


def test_the_browser_gets_the_url_of_the_socket_that_is_actually_bound(
    opened, serve_forever, capsys
):
    """`--port 0` 時印的是**實際**配到的埠,不是字面上的 `0`。

    `WebUIServer.port` 讀的是 `server_address`,但「印的是哪一個」是本層的事:
    印成 `0` 的話使用者與瀏覽器都連不上,而伺服器自己好得很。
    """
    served = serve_forever()
    assert cli.main(["ui", "--port", "0"]) == 0
    printed = capsys.readouterr().out.strip()
    assert len(served) == 1
    assert printed == f"http://{webui.LOOPBACK}:{served[0].port}/#{served[0].token}"
    assert ":0/" not in printed
    assert opened == [printed]


def test_the_server_is_closed_before_main_returns(serve_forever, capsys):
    """服務結束 → `server_close()`;不留 fd、不占著那個埠。"""
    served = serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == 0
    capsys.readouterr()
    assert served[0].socket.fileno() == -1, "listen socket 沒被關掉"


def test_the_handler_swallows_a_keyboard_interrupt_and_returns_exit_ok(serve_forever, capsys):
    """AC 3 的 in-process 釘子:`KeyboardInterrupt` 由 **`ui` 的 handler** 接掉。

    不能落到 `main()` 的共用出口——那條印 `qvault: interrupted` 並回 130
    (`tests/test_cli.py::test_interrupt_at_the_prompt_is_not_a_traceback` 把它
    凍成裁判),而決策 12 要 `ui` 的 Ctrl-C 是 exit 0 且什麼都不印。兩者不衝突
    的唯一做法就是在 handler 內接掉,所以這條守的是「有沒有在對的地方接」。
    """
    def interrupt():
        raise KeyboardInterrupt

    serve_forever(interrupt)
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.err == "", f"不該走共用的 `interrupted` 出口:{captured.err!r}"
    assert "interrupted" not in captured.out


@pytest.mark.parametrize("sig", cli._STOP_SIGNALS, ids=lambda s: s.name)
def test_each_stop_signal_is_handled_while_serving_and_restored_after(sig, serve_forever, capsys):
    """AC 3 的信號面:服務中每個停止信號都裝了 handler,離開時**還原**。

    不真的 `os.kill` 自己:若 handler 沒裝上,預設處置會把跑測試的這個行程殺掉
    (連報告都看不到)。改成取 `signal.getsignal` 拿到那個已安裝的 handler 並
    直接呼叫它——走的是同一條控制流(從 `serve_forever` 內部丟例外出來),但
    紅掉的時候只是一條測試紅。

    還原也要驗:`cli.main` 是函式庫呼叫端也會用的進入點,永久改掉行程的信號
    處置是副作用,不是功能。
    """
    before = signal.getsignal(sig)
    installed: list[object] = []

    def raise_it():
        handler = signal.getsignal(sig)
        installed.append(handler)
        assert callable(handler), f"服務中沒有裝 {sig!r} 的 handler:{handler!r}"
        handler(sig, None)
        raise AssertionError(f"{sig!r} 的 handler 沒有把控制流帶走")

    serve_forever(raise_it)
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.err == ""
    assert installed and installed[0] is not before
    assert signal.getsignal(sig) is before, "離開 `ui` 之後沒有還原 handler"


def test_sighup_is_in_the_stop_signals_so_closing_the_terminal_is_clean():
    """`SIGHUP` 也走乾淨退出——`--help` 與 README 都寫「關掉終端即失效」。

    預設處置下關終端是**被殺**(exit −1):在途的解密會留下明文片段,而那兩句
    文案就成了假話。POSIX 上這條驗 `SIGHUP` 在表裡;Windows 沒有這個信號,
    `_STOP_SIGNALS` 以 `getattr` 取,故那裡只會有 `SIGTERM`。
    """
    names = {sig.name for sig in cli._STOP_SIGNALS}
    assert "SIGTERM" in names
    if hasattr(signal, "SIGHUP"):
        assert "SIGHUP" in names
    # `SIGINT` 不該在表裡:標準庫預設就把它變成 `KeyboardInterrupt`,自己再裝一個
    # 等於把那條眾所周知的路徑換掉。
    assert "SIGINT" not in names


def test_a_handler_we_cannot_restore_becomes_sig_dfl(monkeypatch):
    """`signal.signal` 回 `None`(前一個 handler 不是從 Python 裝的)→ 還原成 `SIG_DFL`。

    QA 第 2 輪的 info:原本 `None` 一個值兼兩種意思(「沒裝上」與「拿不回原本
    那個」),後者會靜默跳過還原,把 `_stop_on_signal` **永久**留在行程上——
    之後每次收到 `SIGTERM`,都會從一個早就結束的 `ui` 裡丟出 `_Stopped`。
    `signal.signal(sig, None)` 自己會丟 `TypeError`,所以拿不回來時只能退成
    預設處置;這條把那個選擇釘住。
    """
    calls: list[tuple[object, object]] = []

    def fake_signal(sig, handler):
        calls.append((sig, handler))
        return None

    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    with cli._signals_as_exit():
        pass
    installs = calls[: len(cli._STOP_SIGNALS)]
    restores = calls[len(cli._STOP_SIGNALS) :]
    assert [sig for sig, _ in installs] == list(cli._STOP_SIGNALS)
    assert all(handler is cli._stop_on_signal for _, handler in installs)
    assert [sig for sig, _ in restores] == list(cli._STOP_SIGNALS)
    assert all(handler is signal.SIG_DFL for _, handler in restores), restores


def test_a_signal_we_could_not_install_is_not_restored(monkeypatch):
    """`signal.signal` 丟 `ValueError`(非主執行緒)→ 離開時**什麼都不做**。

    與上一條是同一個哨兵的另一半:沒裝上就沒有東西要還原,硬還原會把一個我們
    從來沒碰過的處置改掉。
    """
    calls: list[tuple[object, object]] = []

    def fake_signal(sig, handler):
        calls.append((sig, handler))
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    with cli._signals_as_exit():
        pass
    assert len(calls) == len(cli._STOP_SIGNALS), "還原了一個根本沒裝上的信號"


def test_serving_from_a_side_thread_still_works_without_a_handler(serve_forever, capsys):
    """非主執行緒裝不了 signal handler(`ValueError`)——那不是錯誤,照樣服務。

    `signal.signal` 只能在主執行緒呼叫。函式庫呼叫端把 `cli.main` 丟到 thread
    裡跑的時候,`ui` 要少掉 `SIGTERM` 這條捷徑而不是整個倒掉。
    """
    served = serve_forever()
    results: list[object] = []
    worker = threading.Thread(
        target=lambda: results.append(cli.main(["ui", "--no-browser", "--port", "0"]))
    )
    worker.start()
    worker.join(timeout=EXIT_TIMEOUT)
    capsys.readouterr()
    assert not worker.is_alive()
    assert results == [cli.EXIT_OK]
    assert len(served) == 1


def test_the_cli_imports_the_webbrowser_module_not_its_open():
    """`import webbrowser` + 呼叫 `webbrowser.open(...)`,**不是** from-import。

    `from webbrowser import open` 會把那個函式綁成 `cli` 的區域名字,monkeypatch
    模組屬性就擋不住它(`.asp/pr/1.md` 記過同一個坑),而 AC 5 的兩條測試正是
    打模組屬性。順手也擋掉 `import webbrowser as wb` 這種改名。
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    plain = [
        alias
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "webbrowser"
    ]
    assert len(plain) == 1, "cli.py 要恰好一個 `import webbrowser`"
    assert plain[0].asname is None, "不要改名,monkeypatch 打的是 `cli.webbrowser`"
    from_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "webbrowser"
    ]
    assert from_imports == []
    calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert "webbrowser.open" in calls


# ================================================================ QA 第 2 輪 F2 / F3:阻塞的瀏覽器


@pytest.fixture
def blocking_browser(tmp_path, monkeypatch):
    """一支**不回來**的假瀏覽器,經 `BROWSER` 交給 `webbrowser`。

    `lynx` / `w3m` 與任何 wrapper script 就是這個形狀:標準庫對不認得的
    `BROWSER` 走 `GenericBrowser.open` → `subprocess.Popen(...).wait()`,也就是
    瀏覽器關掉之前不回來。QA 第 2 輪用的也是這一招(F2 / F3 的重現方式)。

    腳本第一件事是 `exec >/dev/null 2>&1`:它會繼承 `ui` 子程序的 stdout /
    stderr 管線,不換掉的話測試端的 `communicate()` 會一直等到這支腳本死掉
    (QA 自己踩到的那個 64 秒)。
    """
    script = tmp_path / "blockbrowser.sh"
    script.write_text("#!/bin/sh\nexec >/dev/null 2>&1\nsleep 60\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("BROWSER", f"{script} %s")
    return script


@posix_only
def test_a_blocking_browser_does_not_keep_the_server_from_serving(blocking_browser):
    """F3:`webbrowser.open` 不回來時,伺服器照樣服務。

    修正前(QA 實測):`open` 在主執行緒上阻塞 → `serve_forever` 永遠輪不到 →
    對那個網址打 `/api/inspect` **逾時**,使用者拿到一個印了網址卻完全不回應的
    伺服器。修正後 `open` 跑在一條 daemon 執行緒上,服務不等它。
    """
    with ui_process("--port", "0") as proc:          # 刻意**不**給 --no-browser
        url = first_line(proc)
        parts = URL_PARTS_RE.match(url)
        assert parts, url
        remote = _Remote(int(parts.group(2)), parts.group(3))
        res = send(remote, payload={"path": str(GOLDEN)})
        assert res.status == 200, res.text
        assert proc.poll() is None, "伺服器在回應之後就死了"
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=EXIT_TIMEOUT)


@posix_only
@pytest.mark.parametrize("sig", cli._STOP_SIGNALS + (signal.SIGINT,), ids=lambda s: s.name)
def test_a_signal_during_a_blocking_browser_still_exits_zero(sig, blocking_browser):
    """F2:信號在「開瀏覽器」那段空窗期到達,仍然 exit 0。

    修正前 handler 裝在 `webbrowser.open` **之後**,而 `open` 可以不回來,於是
    那段空窗期裡(QA 實測):`SIGTERM` → `-15`(預設處置當場殺掉);
    `SIGINT` → `130` + `qvault: interrupted`(冒到 `main()` 的共用出口)。
    兩者都違反 AC 第 3 條的 `returncode == 0`。

    修正後信號處置包住**整個** `ui` 本體,所以這條在網址印出來之後**立刻**送
    信號——那時 `serve_forever` 還沒開始、瀏覽器執行緒還卡著。
    """
    with ui_process("--port", "0") as proc:
        first_line(proc)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
    assert proc.returncode == 0, f"{sig!r} 沒有乾淨退出:rc={proc.returncode} err={err!r}"
    assert "Traceback" not in err
    assert "interrupted" not in err, "走到了 `main()` 的共用出口"
    assert out == ""


# ================================================================ QA 第 2 輪 F1:在途的工作


def _slow_api_request(remote, seconds: float) -> tuple[int, bytes]:
    """送一個 `/api/inspect`,但 body **慢慢**送——請求在途 `seconds` 秒。

    不需要一個大到解密得花好幾秒的檔案:`_handle` 在讀 body **之前**就開始計數
    (在途 = 「這個請求還沒處理完」),所以把 body 拖慢就能造出一個長度可控、
    不佔磁碟的在途窗口。
    """
    body = json.dumps({"path": str(GOLDEN)}).encode("utf-8")
    conn = http.client.HTTPConnection(webui.LOOPBACK, remote.port, timeout=READ_TIMEOUT)
    try:
        conn.putrequest("POST", webui.API_INSPECT_PATH, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", remote.expected_host)
        conn.putheader("Content-Type", webui.JSON_MEDIA_TYPE)
        conn.putheader("Authorization", f"Bearer {remote.token}")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()                      # 標頭先到:伺服器開始處理這個請求
        time.sleep(seconds)                    # ……然後讓它等 body
        conn.send(body)
        res = conn.getresponse()
        return res.status, res.read()
    finally:
        conn.close()


@posix_only
def test_an_in_flight_request_is_finished_before_the_process_exits():
    """F1:退出前等在途的 `/api/*` 工作做完,不把它砍在半路。

    為什麼要緊:`vault` 的寫法是「寫 `.qvault-*.part` → `os.replace`」,而連線
    執行緒是 daemon——直譯器一結束就被砍掉、`finally` 不跑,於是中途被打斷的
    **解密**會把一個明文片段留在 `out_dir` 裡。純 CLI 沒有這個問題:那裡的解密
    跑在主執行緒上,Ctrl-C 會把堆疊解開、`finally` 清掉暫存檔。是 `ui` 這個
    生命週期把它變出來的,所以也由 `ui` 收掉。

    這條用「body 慢慢送」造在途窗口(見 `_slow_api_request`),信號在窗口中間
    送——請求必須仍然拿到 `200`,而行程仍然 exit 0。
    """
    with running_ui() as (proc, _url, remote):
        result: list[tuple[int, bytes]] = []
        caller = threading.Thread(target=lambda: result.append(_slow_api_request(remote, 0.6)))
        caller.start()
        time.sleep(0.2)                        # 請求已經在途
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        caller.join(timeout=EXIT_TIMEOUT)
    assert proc.returncode == 0, err
    assert result and result[0][0] == 200, f"在途的請求被砍掉了:{result!r}"
    assert "Traceback" not in err
    assert "gave up" not in err, "在預算內的工作不該觸發放棄等待的警告"
    assert out == ""


def test_the_server_knows_when_api_work_is_in_flight(server):
    """`wait_until_idle` 的語意:有在途工作時 `False`,做完變 `True`。

    這對計數器是 #24 為了 F1 加在 `webui.py` 上的唯一改動(`cli` 只呼叫
    `wait_until_idle`)。單獨驗它,好讓上面那條 e2e 紅掉時分得出是「計數錯」
    還是「退出路徑沒等」。
    """
    assert server.wait_until_idle(0) is True
    server.work_started()
    assert server.wait_until_idle(0.01) is False
    server.work_started()
    server.work_finished()
    assert server.wait_until_idle(0.01) is False, "兩個在途、只做完一個,還不算閒"
    server.work_finished()
    assert server.wait_until_idle(0.01) is True


def test_a_real_api_request_shows_up_as_in_flight(server):
    """同一條,但走真的 HTTP:`_handle` 真的有把 `/api/*` 包進計數裡。"""
    result: list[tuple[int, bytes]] = []
    remote = _Remote(server.port, server.token)
    caller = threading.Thread(target=lambda: result.append(_slow_api_request(remote, 0.4)))
    caller.start()
    try:
        time.sleep(0.15)
        assert server.wait_until_idle(0.01) is False, "在途的請求沒有被數到"
    finally:
        caller.join(timeout=EXIT_TIMEOUT)
    assert server.wait_until_idle(1.0) is True, "請求做完了卻還是不算閒"
    assert result and result[0][0] == 200


def test_a_static_request_is_not_counted_as_work(server):
    """只數 `/api/*`:頁面與靜態內容不寫檔,數它們只會讓退出路徑白等。

    這條也是 keep-alive 的那一刀:連線執行緒在兩個請求之間是**活著但閒著**的,
    若用「還有沒有活著的執行緒」當判準,每次 Ctrl-C 都要白等滿整個預算。
    """
    conn = http.client.HTTPConnection(webui.LOOPBACK, server.port, timeout=READ_TIMEOUT)
    try:
        conn.putrequest("GET", webui.PAGE_PATH, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", server.expected_host)
        conn.endheaders()
        assert conn.getresponse().status == 200
        # 連線**還開著**(HTTP/1.1 keep-alive),那條 handler 執行緒也還活著——
        # 但它沒有在做事,所以伺服器必須算「閒」。
        assert server.wait_until_idle(0.5) is True
    finally:
        conn.close()


def test_giving_up_on_a_long_request_says_so_and_still_exits_zero(serve_forever, capsys, monkeypatch):
    """等不到就放棄,但**要說一句話**:磁碟上可能留了一個明文片段。

    真的拖滿 `UI_DRAIN_SECONDS` 會讓測試白等三秒,所以這條把 `wait_until_idle`
    換成「永遠等不到」,只驗那條分支的輸出與 exit code。等待是**有界**的緩解,
    不是保證——這條就是那個界線被踩到的時候長什麼樣。
    """
    monkeypatch.setattr(webui.WebUIServer, "wait_until_idle", lambda self, timeout: False)
    serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, lines
    assert lines[0].startswith("qvault: gave up after 3s"), lines[0]
    assert ".qvault-*.part" in lines[0]
    assert "Traceback" not in captured.err


# ================================================================ AC 6:選項面


def _ui_parser():
    """`ui` 的那個子解析器(`argparse` 沒有公開的取法,只能走 `_actions`)。"""
    parser = cli._build_parser()
    for action in parser._actions:  # noqa: SLF001 —— 只有這條路能列舉子解析器
        choices = getattr(action, "choices", None) or {}
        if "ui" in choices:
            return choices["ui"]
    raise AssertionError("`ui` 不在任何子解析器裡")


def test_the_ui_subparser_has_no_host_and_no_bind():
    """AC 6:`ui` 的 option strings 不含 `--host` / `--bind`(決策 4)。

    「不能改綁定位址」在型別層面成立:`make_server` 沒有那個參數,CLI 也沒有
    那個選項。這條守的是「加個 `--host` 比較好測/比較方便」那種手滑——一旦有
    了它,`127.0.0.1` 就從保證降級成預設值。
    """
    options = {name for action in _ui_parser()._actions for name in action.option_strings}
    assert "--host" not in options
    assert "--bind" not in options
    assert options == {"-h", "--help", "--port", "--no-browser"}, options
    assert not any("host" in name or "bind" in name or "addr" in name for name in options)
    dests = {action.dest for action in _ui_parser()._actions}
    assert not any("host" in dest or "bind" in dest or "addr" in dest for dest in dests)


def test_the_ui_subparser_takes_no_passphrase():
    """共同範圍條款:`ui` 也沒有任何收密碼的選項。

    `tests/test_cli.py::test_no_option_anywhere_takes_a_passphrase` 已經掃過**所有**
    子解析器(含本票新增的這個);這條是同一條禁令在本檔的落點,好讓「`ui` 這一
    格有被看著」在本票的測試檔裡也看得見。Web UI 的密碼走 POST body
    (ADR-002 決策 7),一個字都不進 argv。
    """
    banned = ("pass", "pw", "secret", "key", "phrase")
    for action in _ui_parser()._actions:
        for name in [*action.option_strings, action.dest]:
            assert not any(b in name.lower() for b in banned), name


# ================================================================ AC 7:兩份 --help


def test_the_top_level_help_lists_ui(capsys):
    """AC 7:`qvault --help` 列出 `ui`。"""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert re.search(r"^\s+ui\s+\S", out, re.MULTILINE), out
    assert "127.0.0.1" in out  # 子命令那一行就說清楚它只綁 loopback


@pytest.mark.parametrize(
    "expected",
    [
        "127.0.0.1",                 # 只綁 loopback(決策 4)
        "There is no --host and no --bind",
        "one-time token",            # 網址含一次性 token(決策 5)
        "after the '#'",
        "Do not paste that URL",     # 不要貼給別人
        "dies with this command",    # 一次性:這個命令停掉就退役
        "writes it to a file",       # (never) ——不落地、不進 cookie / 瀏覽器儲存
        "it is printed here",        # F4:它**就在**這個終端上
        "where ps can",              # F4:開瀏覽器會把網址交給那支程式的命令列
        "--no-browser",
    ],
)
def test_the_ui_help_spells_out_the_safety_notes(capsys, expected):
    """AC 7:`qvault ui --help` 寫明「只綁 127.0.0.1;網址含一次性 token,不要貼給別人」。

    逐項點名要出現的子字串(不然驗收是判斷題)。說明本體以
    `RawDescriptionHelpFormatter` 原樣輸出,故斷言的字串不會被 argparse 的
    重新斷行切成兩段——這也是那個 formatter 在這裡的理由。

    後四格是 QA 第 2 輪 F4 的修正(見 `test_the_help_does_not_claim_the_token_stays_in_memory`)。
    """
    with pytest.raises(SystemExit) as exc:
        cli.main(["ui", "--help"])
    assert exc.value.code == 0
    assert expected in capsys.readouterr().out


def test_the_help_does_not_claim_the_token_stays_in_memory(capsys):
    """F4:`--help` 不得再說「The token only ever lives in memory」——那是假的。

    它**就印在這個終端上**(於是在 scrollback 裡、在你導向的那個檔案裡),而且
    開瀏覽器時以命令列參數交給那支程式(`ps` 看得到)。同使用者的其他行程本來
    就在威脅模型之外(ADR-002),但說明不可以說假話:使用者會依這句話決定要不要
    把終端輸出貼進工單。
    """
    with pytest.raises(SystemExit):
        cli.main(["ui", "--help"])
    out = capsys.readouterr().out
    assert "only ever lives in memory" not in out
    assert "lives in memory" not in out


# ================================================================ AC 8:README


def _readme_section(title: str) -> str:
    """README 裡 `## <title>` 到下一個 `## ` 之間的那一段。"""
    text = README_PATH.read_text(encoding="utf-8")
    assert title in text, f"README 沒有 `{title}` 這一節"
    after = text.split(title, 1)[1]
    return after.split("\n## ", 1)[0]


@pytest.mark.parametrize(
    "expected",
    [
        "qvault ui",
        "--no-browser",
        "--port",
        "`127.0.0.1`",       # 只綁 loopback
        "one-time token",    # token 一次性
        "after the `#`",     # 且在網址 `#` 後
        "close the terminal",  # 關掉終端即失效(`SIGHUP` 也走乾淨退出)
        "dies with the command",
        "never writes it to a file",
        "where `ps` can see it",   # F4:開瀏覽器把網址放進另一支程式的命令列
    ],
)
def test_the_readme_install_section_documents_the_ui(expected):
    """AC 8:README「📦 Install / use」段有 `qvault ui` 用法與三句安全說明。"""
    assert expected in _readme_section("## 📦 Install / use")


def test_the_readme_does_not_claim_the_token_stays_in_memory():
    """F4 的 README 面:同一句假話不能留在這裡。"""
    assert "only ever lives in memory" not in _readme_section("## 📦 Install / use")


def test_the_readme_still_documents_the_other_three_commands():
    """AC 8 的「不改其他段落」在本節內的那一半:三個舊子命令的用法還在。"""
    section = _readme_section("## 📦 Install / use")
    for line in ("pip install -e .", "qvault encrypt", "qvault decrypt", "qvault inspect"):
        assert line in section


# ================================================================ AC 9 / 決策 13:相依邊


def test_the_cli_takes_exactly_two_names_from_webui():
    """決策 13 的 `cli → webui`:只取 `make_server` 與 `LOOPBACK`。

    本票新落的這條 import 邊是 ADR-002 決策 13 定的方向(反向仍然一條都沒有,
    由 `tests/test_webui_server.py` 守著)。這條測試守的是**邊的粗細**:CLI 伸手
    進 `webui` 的 handler、常數表、`_Handler` 之類的內部,就是把 UI 的決定搬了
    一份到 CLI——而那正是決策 13 要避免的事。
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level and node.module == "webui":
            names |= {alias.name for alias in node.names}
        if isinstance(node, ast.Import):
            assert not any(alias.name.startswith("qvault_core") for alias in node.names)
    assert names == {"LOOPBACK", "make_server"}, names
    assert cli.make_server is webui.make_server
    assert cli.LOOPBACK == webui.LOOPBACK


def test_importing_the_package_still_does_not_drag_in_a_server():
    """決策 13 的理由還在:`import qvault_core` 不會把 HTTP 伺服器拖進來。

    被凍結測試擋住的那件事是「每一個使用情境都扛一個伺服器」;`cli → webui`
    這條邊落下來之後,扛它的只有 `qvault_core.cli` 這一個模組(以及 `qvault`
    這個執行檔),而 `import qvault_core`(函式庫用法)的 import 清單一個字
    未變——`qvault_core/__init__.py` 既不 import `cli` 也不 import `webui`。
    """
    package_init = ast.parse((REPO_ROOT / "qvault_core" / "__init__.py").read_text(encoding="utf-8"))
    pulled = {
        node.module
        for node in ast.walk(package_init)
        if isinstance(node, ast.ImportFrom) and node.level
    }
    assert "cli" not in pulled
    assert "webui" not in pulled

    done = subprocess.run(
        [sys.executable, "-c", "import sys, qvault_core; print('webui' in str(sys.modules.keys()))"],
        capture_output=True,
        text=True,
        env=_env(),
        cwd=str(REPO_ROOT),
        timeout=READ_TIMEOUT,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "False", done.stdout
