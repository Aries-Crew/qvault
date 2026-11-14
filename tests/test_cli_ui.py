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

#36(使用者 2026-11-10 裁定,ADR-002 決策 12 修訂)在這三層各加了一段:交給
瀏覽器的不再是那條帶 token 的網址,而是一個只有啟動者讀得到的 `file://` 跳轉
檔。**那一段的斷言要分得清層級**——「`webbrowser.open` 收到什麼」是 in-process
(攔呼叫引數),「瀏覽器那支程式的 argv 長什麼樣」只有子程序裡才算證明(走
`BROWSER` 指到一支把 `"$@"` 寫下來的腳本:它收到的就是 `/proc/<pid>/cmdline`
的內容,而那正是票文那條事實說的東西),「檔案有沒有被刪掉」則要一個**真的**
信號(in-process 收不到)。暫存位置一律指到測試自己的 `tmp_path`:in-process 打
`cli.tempfile.tempdir`(`gettempdir()` 會快取,改環境變數對本行程無效),子程序
改 `TMPDIR`(新行程,快取還沒長出來)。

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
import stat
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

#: 跳轉檔「已經寫完」的證據:內容的最後幾個字元。子程序那一側的寫檔不是原子的
#: (`mkdtemp` → `os.open` → `write` → `close`),所以輪詢要等這個收尾字串出現,
#: 不是等目錄出現(複審 B2)。樣板改了就會被
#: `test_the_redirect_page_ends_with_the_tail_the_pollers_wait_for` 當場抓到。
REDIRECT_TAIL = "</html>\n"

#: AC:收到 signal 後 5 秒內要結束。
EXIT_TIMEOUT = 5.0

#: 嚴格那兩條 in-process 測試(真信號、真請求)**注給退出路徑**的等待期限,
#: 取代產品預設的 `cli.UI_DRAIN_SECONDS = 3.0`(#40 AC-1)。
#:
#: 為什麼要注:慢請求的 body 延遲是 `STRICT_BODY_SECONDS = 2.0` 秒,對上 3.0 秒
#: 的產品期限,名目餘裕只有 1 秒——而那兩條測試斷言的是「在途請求跑完了」,
#: 不是「3 秒夠不夠」。排程抖動超過那 1 秒,`wait_until_idle` 就先逾時,
#: stderr 冒出 `gave up after 3s …` 而測試紅在一件它沒有在驗的事上(主管層宿主
#: 連跑 20 次紅 3 次,#40 票文)。注成 8.0 之後餘裕是 body 延遲的 **4 倍**。
#:
#: 這不是把斷言放寬:「在途請求必須拿到 200」、「stderr 不得有 `gave up` /
#: `stopped waiting`」一個字都沒改,被改掉的只有「排程抖動 < 1 秒」這個賭注。
#: `UI_DRAIN_SECONDS` 的產品預設值本身另有守門人
#: (`test_giving_up_on_a_long_request_says_so_and_still_exits_zero` 斷言
#: `gave up after 3s`),注進去的值不會把那條蓋掉。
STRICT_DRAIN_SECONDS = 8.0

#: 嚴格那兩條裡慢請求的 body 延遲:在途窗口的長度。
STRICT_BODY_SECONDS = 2.0

#: 嚴格那兩條裡「等執行緒收乾淨」的期限(`_InProcessUI.check` 與 `caller.join`)。
#: 要蓋得住最壞情況:退出路徑最多等 `STRICT_DRAIN_SECONDS` + 開瀏覽器的 0.5 秒,
#: 而 HTTP 呼叫端要在那之後才把回應讀完——用 `EXIT_TIMEOUT`(5 秒,那是 AC 給
#: **真行程退出**的預算)量這一段就是另一個太緊的期限。
STRICT_JOIN_SECONDS = 20.0

#: Windows 的 `send_signal` 不送 POSIX signal(`SIGTERM` → `TerminateProcess`,
#: `SIGINT` 根本不支援),故 signal 那一組只在 POSIX 上跑。乾淨退出的**行為**
#: 在 Windows 上由 Ctrl-C 的 `KeyboardInterrupt` 那條 in-process 測試守著。
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="send_signal 在 Windows 上不是 POSIX signal"
)


def _env(**extra: str) -> dict[str, str]:
    """子程序的環境:`PYTHONPATH` 指到 repo(同 `tests/test_cli.py::run_module`)。

    `**extra` 給 #36 那幾條用:它們要指定 `TMPDIR`(於是跳轉檔落在測試自己的
    `tmp_path` 裡,查得到也不會與別的回合互相看見)與 `BROWSER`(於是「交給
    瀏覽器的命令列長什麼樣」是真的 argv,不是替身記下來的字串)。
    """
    return dict(
        os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONIOENCODING="utf-8", **extra
    )


@contextlib.contextmanager
def ui_process(*argv: str, env: dict[str, str] | None = None):
    """跑 `python -m qvault_core.cli ui <argv>`;離開時保證行程不留在樹上。"""
    proc = subprocess.Popen(
        [sys.executable, "-m", "qvault_core.cli", "ui", *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env or _env(),
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


# ---------------------------------------------------------------- #36:跳轉檔的夾具與工具


@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    """把 `tempfile` 的暫存根目錄換成測試自己的 `tmp_path`(in-process 用)。

    打的是 `tempfile.tempdir` 這個模組全域,**不是** `TMPDIR`:
    `tempfile.gettempdir()` 第一次被呼叫之後就把結果快取在 `tempdir` 裡,所以
    改環境變數對一個已經用過 `tempfile` 的行程沒有效果(而 pytest 自己早就
    用過了)。子程序那幾條則相反——它們是新行程,改 `TMPDIR` 才是對的。

    這樣「跳轉檔有沒有被刪掉」才能用「這個目錄是不是空的」來斷言,而不是去
    猜系統 `/tmp` 裡哪一個目錄是本回合留下來的。
    """
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(cli.tempfile, "tempdir", str(root))
    assert cli.tempfile.gettempdir() == str(root)
    return root


def redirect_in(root: pathlib.Path) -> pathlib.Path:
    """`root` 底下那個**唯一**的跳轉檔;不是恰好一個就失敗。

    「恰好一個目錄、裡面恰好一個檔案」本身就是斷言:AC-2 要的是「token 不寫進
    任何其他檔案」,所以多出來的任何一個檔案都要讓測試紅。
    """
    private = [path for path in root.iterdir() if path.name.startswith(cli.UI_REDIRECT_PREFIX)]
    assert [path.name for path in root.iterdir()] == [path.name for path in private], (
        f"{root} 底下有不是跳轉檔目錄的東西:{list(root.iterdir())!r}"
    )
    assert len(private) == 1, f"跳轉檔的私有目錄不是恰好一個:{private!r}"
    inside = list(private[0].iterdir())
    assert [path.name for path in inside] == [cli.UI_REDIRECT_NAME], inside
    return inside[0]


def wait_for_redirect(root: pathlib.Path, timeout: float = READ_TIMEOUT) -> pathlib.Path:
    """等 `root` 底下出現一個**寫完**的跳轉檔(子程序用);逾時即失敗。

    網址那一行是在寫檔**之前**印的(順序由 AC-3 的「埠被占不留檔」決定),所以
    讀到第一行不代表檔案已經在了。這裡輪詢而不是 sleep 一個猜的秒數:慢的機器
    上多等一下,快的機器上立刻回。

    **等的條件是「內容已經以 `REDIRECT_TAIL` 收尾」,不是「目錄出現了」**
    (複審 B2):子程序那一側是 `mkdtemp` → `os.open` → `write` → `close` 四步,
    第一次輪詢完全可能落在「目錄在、檔還沒建」或「檔在、內容還沒寫完」的窗口裡,
    而那會讓呼叫端的斷言變成一條看機器快慢決定紅綠的測試。時序不是斷言的對象,
    **寫完**才是。
    """
    deadline = time.monotonic() + timeout
    seen: list[pathlib.Path] = []
    while time.monotonic() < deadline:
        seen = [path for path in root.iterdir() if path.name.startswith(cli.UI_REDIRECT_PREFIX)]
        if len(seen) == 1:
            page = seen[0] / cli.UI_REDIRECT_NAME
            text = ""
            with contextlib.suppress(OSError):
                text = page.read_text(encoding="utf-8")
            if text.endswith(REDIRECT_TAIL):
                # 「恰好一個目錄、裡面恰好一個檔案」的斷言在 `redirect_in` 裡。
                return redirect_in(root)
        time.sleep(0.02)
    raise AssertionError(f"{timeout} 秒內 {root} 底下沒有出現寫完的跳轉檔:{seen!r}")


def wait_for_complete_file(path: pathlib.Path, tail: str, timeout: float = READ_TIMEOUT) -> str:
    """等 `path` 出現**且**內容以 `tail` 收尾,回那段內容;逾時即失敗。

    同 `wait_for_redirect` 的理由(複審 B2):`>>` 重導向是「先建檔、再寫入」
    兩步,所以「檔案存在」不等於「那一行已經在裡面」。
    """
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            text = path.read_text(encoding="utf-8")
        if text.endswith(tail):
            return text
        time.sleep(0.02)
    raise AssertionError(f"{timeout} 秒內 {path} 沒有寫完(目前:{text!r})")


def quiet_browser(tmp_path: pathlib.Path, body: str = "") -> pathlib.Path:
    """一支**立刻回來**的假瀏覽器,給子程序那幾條用(`BROWSER=<它> %s`)。

    第一件事是 `exec >/dev/null 2>&1`:它繼承 `ui` 子程序的 stdout / stderr
    管線,不換掉的話測試端的 `communicate()` 會等到它死掉為止(`blocking_browser`
    那個夾具踩過同一個坑)。`body` 是要多做的事,例如把自己的 argv 寫下來。
    """
    script = tmp_path / "quietbrowser.sh"
    script.write_text(f"#!/bin/sh\nexec >/dev/null 2>&1\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return script


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


def test_the_default_opens_the_browser_once_at_the_redirect_file(
    opened, serve_forever, private_tmp, capsys
):
    """AC 5 + #36 AC-1:預設 → `webbrowser.open` **被呼叫一次**,參數是跳轉檔。

    #24 原本斷言的是「參數等於印出的那個網址」;#36(使用者 2026-11-10 裁定)
    把那件事**反過來**:交給瀏覽器的網址裡不可以有 token,因為那條網址會變成
    `xdg-open` / `firefox` 的 argv。「瀏覽器最後還是走到印出來的那條網址」這件
    事沒有不見,只是搬到跳轉檔的內容裡,由下面那條測試接手。
    """
    served = serve_forever()
    assert cli.main(["ui", "--port", "0"]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 1, printed
    assert URL_RE.match(printed[0]), printed[0]
    assert len(opened) == 1, opened
    assert opened[0].startswith("file://"), opened[0]
    assert opened[0].endswith(f"/{cli.UI_REDIRECT_NAME}"), opened[0]
    assert cli.UI_REDIRECT_PREFIX in opened[0], opened[0]
    assert len(served) == 1, "沒有真的進到服務"


def test_no_browser_prints_the_url_and_opens_nothing(opened, serve_forever, private_tmp, capsys):
    """AC 5 的另一半 + #36 AC-4:`--no-browser` → 不開瀏覽器,也不寫跳轉檔。

    「服務中」那一刻就看暫存根目錄(不是等 `cli.main` 回來才看):退出序列會把
    跳轉檔刪掉,所以只在結束後看的話,「寫了又刪」與「從來沒寫」長得一模一樣
    ——而 AC-4 要的是後者。
    """
    during: list[pathlib.Path] = []
    served = serve_forever(lambda: during.extend(private_tmp.iterdir()))
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 1, printed
    assert URL_RE.match(printed[0]), printed[0]
    assert opened == []
    assert during == [], f"`--no-browser` 不該寫任何東西:{during!r}"
    assert list(private_tmp.iterdir()) == []
    assert len(served) == 1


def test_the_redirect_page_jumps_to_the_url_of_the_socket_that_is_actually_bound(
    opened, serve_forever, private_tmp, capsys
):
    """`--port 0` 時印的是**實際**配到的埠,不是字面上的 `0`。

    `WebUIServer.port` 讀的是 `server_address`,但「印的是哪一個」是本層的事:
    印成 `0` 的話使用者與瀏覽器都連不上,而伺服器自己好得很。

    #36 之後「瀏覽器拿到哪一條」要**穿過跳轉檔**才驗得到,所以這裡在「正在服務」
    的那一刻把檔案讀起來(`cli.main` 回來的時候它已經被刪掉了,那是 AC-3)。
    """
    page: dict[str, str] = {}
    served = serve_forever(lambda: page.update(text=redirect_in(private_tmp).read_text("utf-8")))
    assert cli.main(["ui", "--port", "0"]) == 0
    printed = capsys.readouterr().out.strip()
    assert len(served) == 1
    assert printed == f"http://{webui.LOOPBACK}:{served[0].port}/#{served[0].token}"
    assert ":0/" not in printed
    assert len(opened) == 1 and opened[0].startswith("file://"), opened
    assert f'location.replace("{printed}")' in page["text"], page["text"]


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
    """`None`(前一個 handler 不是從 Python 裝的)→ 還原成 `SIG_DFL`;**順序**在這裡。

    QA 第 2 輪的 info:原本 `None` 一個值兼兩種意思(「沒裝上」與「拿不回原本
    那個」),後者會靜默跳過還原,把 `_stop_on_signal` **永久**留在行程上——
    之後每次收到 `SIGTERM`,都會從一個早就結束的 `ui` 裡丟出 `_Stopped`。
    `signal.signal(sig, None)` 自己會丟 `TypeError`,所以拿不回來時只能退成
    預設處置;這條把那個選擇釘住。

    **這條今天量到的是什麼**(#48 W6 之後,合併前複審 F-1 校正):`_signals_as_exit`
    的 `previous[sig]` 自 W6 起取自 `signal.getsignal()`,不再是 `signal.signal()`
    的回傳值,而這條的替身只攔 `signal.signal`——所以「取到 `None`」那一格**不是**
    由這條觸發的,它量到的是安裝與還原的**呼叫順序**(先對 `_STOP_SIGNALS` 逐一裝上
    `_stop_on_signal`,離開時再逐一裝回去)。`None` → `SIG_DFL` 那道防護的現役證人是
    `tests/test_cli_signals_restore.py::test_restoring_as_exit_tolerates_a_handler_that_python_did_not_install`
    (替身改攔 `getsignal`);把 `cli.py` 的 `signal.SIG_DFL if handler is None else
    handler` 改成 `handler`,紅的是那一條,這一條照樣綠。斷言照原樣留著,因為順序
    本身也值得釘住。
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


# ================================================================ #36:跳轉檔(AC-1 ~ AC-4)
#
# 使用者 2026-11-10 裁定(ADR-002 決策 12 修訂):自動開瀏覽器時不把帶 token 的
# 網址交給瀏覽器的命令列,改開一個只有啟動者讀得到的本機跳轉檔。終端印出的那
# 一行網址不變,故上面 AC 1–4 的那幾條子程序測試一個字都沒改。


@posix_only
def test_the_token_never_reaches_the_argv_of_the_browser_process(tmp_path):
    """AC-1 的真行程版:瀏覽器那支程式的 **argv** 裡沒有 token。

    `BROWSER` 指到一支把 `"$@"` 寫下來的腳本,而 `webbrowser` 對不認得的
    `BROWSER` 走 `GenericBrowser.open` → `Popen([browser, url])`:那支腳本收到的
    argv **就是** `/proc/<pid>/cmdline` 的內容(票文的事實:同機其他使用者
    `ps aux` 讀得到的正是這個)。所以這條記下來的字串等價於 `ps` 看到的字串。

    in-process 那條(`test_the_default_opens_the_browser_once_at_the_redirect_file`)
    攔的是 `webbrowser.open` 的引數;這一條連「標準庫會不會自己把網址再接到別的
    地方」都一起驗了。
    """
    private = tmp_path / "tmp"
    private.mkdir()
    recorded = tmp_path / "argv.txt"
    script = quiet_browser(tmp_path, f'printf "%s\\n" "$@" >> {recorded}')
    env = _env(BROWSER=f"{script} %s", TMPDIR=str(private))

    with ui_process("--port", "0", env=env) as proc:
        url = first_line(proc)
        assert URL_RE.match(url), url
        token = url.split("#", 1)[1]
        page = wait_for_redirect(private)

        # 那支腳本是 `printf ... >> file`:先建檔、再寫入,故等的是「以換行收尾」
        # 而不是「檔案存在」(複審 B2)。
        argv = wait_for_complete_file(recorded, "\n")

        assert token not in argv, f"token 進了瀏覽器的 argv:{argv!r}"
        assert "#" not in argv, argv
        assert argv.strip() == page.as_uri(), argv
        # 而那個檔案確實會把瀏覽器送到印出來的那一條(token 在這裡,不在 argv)。
        assert f'location.replace("{url}")' in page.read_text(encoding="utf-8")

        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        assert proc.returncode == 0, (proc.returncode, err)
        assert list(private.iterdir()) == [], "跳轉檔的目錄沒被刪掉"


@posix_only
def test_the_redirect_file_is_0600_in_a_0700_private_directory(private_tmp):
    """AC-2:目錄是 `mkdtemp()` 的(0700),檔案自己 0600。

    直接呼叫 `_write_redirect_file`:權限這件事不需要一整個伺服器來驗,而寫成
    單元測試之後,「哪一步給的權限」失手時的失敗訊息指得到那一步。
    """
    url = f"http://{webui.LOOPBACK}:52231/#{'A' * 43}"
    path = cli._write_redirect_file(url)
    try:
        assert path.parent.parent == private_tmp, path
        assert path.name == cli.UI_REDIRECT_NAME
        assert path.parent.name.startswith(cli.UI_REDIRECT_PREFIX), path.parent
        assert stat.S_IMODE(path.stat().st_mode) == cli.UI_REDIRECT_FILE_MODE == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == cli.UI_REDIRECT_DIR_MODE == 0o700
    finally:
        cli._discard_redirect(path)
    assert list(private_tmp.iterdir()) == []


@posix_only
def test_a_wide_open_umask_still_produces_0600_and_0700(private_tmp):
    """AC-2:`umask(0)`(什麼都開放)下,檔案仍是 0600、目錄仍是 0700。

    **這條守的只有「umask 加不了位元」**(0600 / 0700 ⊆ 任何 umask 下的 owner
    位元),不是「中間沒有 chmod 窗口」——複審 B1 點出原本的 docstring 宣稱了
    後者而斷言只看最終權限:先 `open(..., 0o666)` 建檔再 `fchmod(0o600)` 的寫法
    在這條下面是全綠的,而它在那兩步之間留下一個**全世界可讀**的帶 token 檔案。
    那個宣稱現在由下面那條 spy 測試(`..._with_o_excl_at_0600_and_never_chmodded`)
    負責。
    """
    previous = os.umask(0)
    try:
        path = cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    finally:
        os.umask(previous)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    finally:
        cli._discard_redirect(path)


def test_the_file_is_created_with_o_excl_at_0600_and_never_chmodded(private_tmp, monkeypatch):
    """複審 B1:「建立當下就是 0600、不經 `chmod`」要有證人,不是只看最終權限。

    三件事一起斷言,因為它們是同一個宣稱(ADR-002 決策 12)的三半:

    1. `os.open` 恰被呼叫一次,flags 帶 `O_CREAT | O_EXCL | O_WRONLY`
       ——`O_EXCL` 兼擋「那個名字已被預先放成 symlink」。
    2. 那次呼叫的 mode **就是** `0o600`:不是 `0o666` 之後再修。
    3. 本模組不呼叫任何 `chmod`(spy 直接讓它炸,AST 另外掃一遍整個檔案):
       事後修權限的寫法在建檔與 `chmod` 之間留下一個 `0o666 & ~umask` 的窗口,
       而那個檔案裡躺著 token。

    複審提的突變(`os.open(path, O_WRONLY|O_CREAT, 0o666)` + `os.fchmod(fd, 0o600)`)
    會同時踩到 1、2、3。
    """
    calls: list[tuple[int, int]] = []
    real_open = cli.os.open

    def spy(path, flags, mode=0o777, **kwargs):
        calls.append((flags, mode))
        return real_open(path, flags, mode, **kwargs)

    def forbidden(name):
        def boom(*args, **kwargs):
            raise AssertionError(f"不該呼叫 {name}:權限要在建立當下就對")

        return boom

    monkeypatch.setattr(cli.os, "open", spy)
    for name in ("chmod", "fchmod", "lchmod"):
        if hasattr(cli.os, name):
            monkeypatch.setattr(cli.os, name, forbidden(f"os.{name}"))
    monkeypatch.setattr(pathlib.Path, "chmod", forbidden("Path.chmod"))

    path = cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    cli._discard_redirect(path)

    assert len(calls) == 1, calls
    flags, mode = calls[0]
    assert flags & os.O_CREAT, oct(flags)
    assert flags & os.O_EXCL, oct(flags)
    assert flags & os.O_WRONLY == os.O_WRONLY, oct(flags)
    assert mode == 0o600 == cli.UI_REDIRECT_FILE_MODE, oct(mode)


def test_the_cli_has_no_chmod_anywhere():
    """同一個宣稱的結構性守門:`cli.py` 的程式碼裡一個 `chmod` 都沒有。

    spy 只看得到**跑過的那一條路徑**;這條掃整個檔案,所以「在別的地方補一次
    `chmod`」也擋得住。
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert not {call for call in calls if "chmod" in call}, calls


@posix_only
@pytest.mark.parametrize("mask", [0o177, 0o400], ids=["no-x-on-the-dir", "no-r-at-all"])
def test_a_umask_that_eats_the_private_bits_fails_closed(
    mask, opened, serve_forever, private_tmp, capsys
):
    """複審 B1 的第三格:umask 把 0700 / 0600 遮掉時,**寧可失敗**。

    `mkdtemp` 的 0700 與 `os.open` 的 0600 都是**要求**,而 umask 遮得到它們
    (實測 CPython 3.12:`umask 0177` → 目錄 0600,少了 `x`,連啟動者自己都進不去;
    `umask 0400` → 目錄 0300、檔案 0200)。那一形不是「安全性少一點」,是整個
    機制默默失效:瀏覽器打不開那一頁,使用者只看到一個空白視窗,而 token 已經
    落地。所以 `_require_private_mode` 就地停下來——一行乾淨錯誤、非零 exit、
    **不留檔、不開瀏覽器**,而 `--no-browser` 仍然走得通。

    那條網址**照舊印出來**(它在寫檔之前),所以使用者沒有被卡死:終端那一行
    就是後路,而訊息裡也點名了 `--no-browser`。

    `serve_forever` 的替身是**這條測試的保險絲**,不是裝飾:這條走的是
    `cli.main(["ui", ...])` 這條完整路徑,而它只在那道門擋下來的時候才不會進到
    服務。門一旦回歸,`umask 0400` 那一格會寫檔**成功**(目錄 0300 有 `wx`,
    `os.open` 進得去),於是真的 `serve_forever` 會把這一格**卡死**——本 repo
    沒有裝 `pytest-timeout`,那在 CI 上是一個掛著的 job 而不是一條紅燈
    (QA 實測:門關掉後這一格被外部 `timeout 60` 殺掉、退出碼 124;
    `umask 0177` 那一格則是 0.06 秒就紅)。裝上替身之後,「門不見了」會在
    下面那句 `served == []` 當場轉紅。
    """
    served = serve_forever()
    previous = os.umask(mask)
    try:
        code = cli.main(["ui", "--port", "0"])
    finally:
        os.umask(previous)
    captured = capsys.readouterr()

    assert code == cli.EXIT_FAIL
    printed = captured.out.strip()
    assert URL_RE.match(printed), printed
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, lines
    assert lines[0].startswith("qvault: refusing to open a browser: "), lines[0]
    assert "use --no-browser" in lines[0]
    assert "Traceback" not in captured.err
    assert printed.split("#", 1)[1] not in lines[0], "錯誤訊息不得帶 token"
    assert opened == [], "權限不對就不該把任何東西交給瀏覽器"
    assert served == [], "權限不對就不該進到服務——門不見了的話這裡要紅,不是卡住"
    assert list(private_tmp.iterdir()) == [], "失敗路徑不得留檔"


@posix_only
def test_a_filesystem_that_ignores_the_file_mode_also_fails_closed(private_tmp, monkeypatch):
    """同一道門的另一半:**檔案**的權限不對時也停下來。

    umask 走不到這一半(檔案要的 `rw` ⊆ 目錄要的 `rwx`,所以任何遮到檔案的
    umask 都先把目錄遮掉,目錄那道門會先擋),但「mode 根本不被尊重」的檔案
    系統走得到:POSIX 上的 FAT / exFAT / 某些網路掛載。那裡 0600 這句承諾不成立,
    而這個函式的工作就是不要在那種地方默默寫一個帶 token 的檔案。替身只改
    `os.fstat` 回報的 `st_mode`,不碰真的權限——要的就是「量到的不是 0600」這
    一件事。

    **Windows 不在這條的範圍內**(`posix_only`):那裡的 mode 位元根本不是這個
    語意(`mkdtemp` 的目錄回報 0777),所以 `cli._MODES_ARE_MEANINGFUL` 在那邊
    把整道門關掉——不關的話每一次 `qvault ui` 都會被自己判成失敗。
    """
    real_fstat = cli.os.fstat

    def lying_fstat(fd):
        fields = list(real_fstat(fd))
        fields[0] = stat.S_IFREG | 0o644
        return os.stat_result(fields)

    monkeypatch.setattr(cli.os, "fstat", lying_fstat)
    with pytest.raises(cli._CleanExit) as exc:
        cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    assert "0644, not 0600" in str(exc.value)
    assert exc.value.code == cli.EXIT_FAIL
    assert list(private_tmp.iterdir()) == [], "失敗路徑不得留檔"


def test_the_mode_check_is_posix_only_so_windows_can_still_open_a_browser(monkeypatch):
    """那道門在 POSIX 之外要**整個關掉**,否則 Windows 上每一次 `ui` 都會自我否決。

    Windows 的 `mkdtemp` 目錄回報 `0o777`、`os.open` 的 mode 只認唯讀位元,拿
    0700 / 0600 去比是穩定失敗。這條用 `_MODES_ARE_MEANINGFUL = False` 模擬那
    一側:同一個「權限不對」的輸入在那邊必須**放行**。
    """
    monkeypatch.setattr(cli, "_MODES_ARE_MEANINGFUL", False)
    cli._require_private_mode(pathlib.Path("whatever"), stat.S_IFDIR | 0o777, 0o700)

    monkeypatch.setattr(cli, "_MODES_ARE_MEANINGFUL", True)
    with pytest.raises(cli._CleanExit):
        cli._require_private_mode(pathlib.Path("whatever"), stat.S_IFDIR | 0o777, 0o700)


def test_the_redirect_page_ends_with_the_tail_the_pollers_wait_for():
    """`REDIRECT_TAIL` 是輪詢用的「寫完」證據,它得真的是樣板的結尾(複審 B2)。

    樣板改了而這個常數沒跟上的話,子程序那幾條會變成「等到逾時才紅」,而紅的
    原因看起來像產品壞了。這條讓那種漂移當場失敗。
    """
    assert cli.UI_REDIRECT_HTML.endswith(REDIRECT_TAIL)
    assert REDIRECT_TAIL.strip() == "</html>"


def test_the_private_directory_comes_from_mkdtemp(private_tmp, monkeypatch):
    """AC-2 的「住在 `tempfile.mkdtemp()` 建的私有目錄」是**機制**,不只是結果。

    0700 不是我們自己 `chmod` 出來的,是 `mkdtemp` 的保證(標準庫:目錄只有
    建立者能讀寫搜尋)。換成 `gettempdir()` + 自己組一個檔名,競爭條件就回來了
    ——別人可以先建好那個路徑。這條把機制釘住,順手也釘住前綴。
    """
    calls: list[dict] = []
    real = cli.tempfile.mkdtemp

    def spy(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(cli.tempfile, "mkdtemp", spy)
    path = cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    cli._discard_redirect(path)
    assert calls == [{"prefix": cli.UI_REDIRECT_PREFIX}], calls


def test_the_redirect_page_only_jumps_and_loads_nothing_else(private_tmp):
    """AC-2 的內容面:一行 `location.replace(...)`,零外部資源。

    這一頁走 `file://`,**不經** ADR-002 決策 10 的 CSP(那條 CSP 與「前端零
    inline script」是對伺服器服務的那三份內容說的,`tests/test_webui_page.py`
    掃的也正是 `webui.PAGE_HTML`)。所以「不載入任何外部資源」在這裡沒有 CSP
    幫忙,只能靠這條測試:任何 `src=` / `href=` / `<link` 都會把一個本機檔案的
    內容(或存在與否)洩漏給那個來源。
    """
    url = f"http://{webui.LOOPBACK}:52231/#{'A' * 43}"
    path = cli._write_redirect_file(url)
    text = path.read_text(encoding="utf-8")
    cli._discard_redirect(path)

    assert text.startswith("<!DOCTYPE html>")
    assert f'location.replace("{url}")' in text
    lowered = text.lower()
    for banned in ("src=", "href=", "<link", "<img", "<iframe", "@import", "http-equiv", "fetch("):
        assert banned not in lowered, banned
    # 唯一一處 `http://` 就是那條跳轉目標;token 在這個檔案裡也只出現一次。
    assert lowered.count("http://") == 1
    assert lowered.count("https://") == 0
    assert text.count(url) == 1
    assert text.count(url.split("#", 1)[1]) == 1


def test_the_redirect_file_is_the_only_file_the_token_is_written_into(
    opened, serve_forever, private_tmp, capsys
):
    """AC-2 末句:token 不寫進任何**其他**檔案。

    範圍講清楚:這條驗的是「暫存根目錄底下恰好一個檔案,而 token 只在它裡面」
    (`redirect_in` 本身就在斷言「恰好一個」)。終端上那一行是決策 12 要的、
    也是使用者唯一的後路,不在這條的範圍內。
    """
    found: dict[str, object] = {}

    def look():
        path = redirect_in(private_tmp)
        found["text"] = path.read_text(encoding="utf-8")
        found["uri"] = path.as_uri()

    served = serve_forever(look)
    assert cli.main(["ui", "--port", "0"]) == 0
    printed = capsys.readouterr().out.strip()
    token = printed.split("#", 1)[1]
    assert len(served) == 1
    assert token in found["text"]
    assert opened == [found["uri"]]
    assert list(private_tmp.iterdir()) == []


@posix_only
@pytest.mark.parametrize("sig", (signal.SIGINT, *cli._STOP_SIGNALS), ids=lambda s: s.name)
def test_a_stop_signal_deletes_the_redirect_file_and_its_directory(sig, tmp_path):
    """AC-3:Ctrl-C / `SIGTERM` / `SIGHUP` → 檔案與目錄都不留,且 exit 仍是 0。

    `returncode == 0` 一起斷言是故意的(票上留言 ③ 的提醒):清理是新長出來的
    一步,而 #24 已經把「每一種停止都 exit 0」凍成測試——新的刪檔邏輯不可以
    偷偷把它改成非零。
    """
    private = tmp_path / "tmp"
    private.mkdir()
    env = _env(BROWSER=f"{quiet_browser(tmp_path)} %s", TMPDIR=str(private))
    with ui_process("--port", "0", env=env) as proc:
        url = first_line(proc)
        page = wait_for_redirect(private)
        assert url in page.read_text(encoding="utf-8")
        directory = page.parent

        proc.send_signal(sig)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        assert proc.returncode == 0, (proc.returncode, err)
        assert err == "", err
        assert not page.exists(), "跳轉檔還在"
        assert not directory.exists(), "跳轉檔的目錄還在"
        assert list(private.iterdir()) == []


def test_any_exception_on_the_way_out_still_deletes_the_redirect_file(
    opened, serve_forever, private_tmp, capsys
):
    """AC-3 的「或任何例外結束」:`serve_forever` 當場丟 `RuntimeError`。

    子程序裡沒有辦法按一下就讓它丟例外(那要注入故障),所以這一形用 in-process
    的替身:刪檔跑在 `finally` 裡,故它與「怎麼離開 `serve_forever`」無關——
    這條就是那句話的證明。順手確認例外照舊走 `main()` 的 `internal error` 出口
    (刪檔不吞例外、也不把它變成別的東西)。
    """
    def boom():
        raise RuntimeError("boom")

    serve_forever(boom)
    assert cli.main(["ui", "--port", "0"]) == cli.EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.err.strip() == "qvault: internal error (RuntimeError)", captured.err
    assert "Traceback" not in captured.err
    assert len(opened) == 1
    assert list(private_tmp.iterdir()) == [], "例外路徑上跳轉檔沒被刪掉"


@posix_only
def test_an_occupied_port_fails_before_the_redirect_file_is_written(tmp_path):
    """AC-3 的後半:埠被占 → 非零 exit,而暫存根目錄裡**什麼都沒多**。

    寫成「可觀察」而不是「時序」(票上留言 ③ 的建議):不去斷言「先 bind 再
    寫檔」這個順序,而是斷言那條失敗路徑上**一個檔案都沒留**——順序錯了的話
    這裡就會看到一個帶 token 的殘留。
    """
    private = tmp_path / "tmp"
    private.mkdir()
    env = _env(BROWSER=f"{quiet_browser(tmp_path)} %s", TMPDIR=str(private))
    sock, port = occupied_port()
    try:
        done = subprocess.run(
            [sys.executable, "-m", "qvault_core.cli", "ui", "--port", str(port)],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
            timeout=READ_TIMEOUT,
        )
    finally:
        sock.close()
    assert "Address already in use" in clean_failure(done)
    assert list(private.iterdir()) == [], "失敗的 `ui` 不該留下任何東西"


@posix_only
def test_no_browser_writes_no_redirect_file_in_a_real_process(tmp_path):
    """AC-4 的真行程版:`--no-browser` 全程不寫任何東西。

    in-process 那條(`test_no_browser_prints_the_url_and_opens_nothing`)已經在
    「服務中」那一刻看過一次;這一條用真行程再看一次,因為 AC-4 說的是
    `qvault ui --no-browser` 這個命令,而不是 `cli.main` 這個函式。
    """
    private = tmp_path / "tmp"
    private.mkdir()
    env = _env(BROWSER=f"{quiet_browser(tmp_path)} %s", TMPDIR=str(private))
    with ui_process("--no-browser", "--port", "0", env=env) as proc:
        url = first_line(proc)
        assert URL_RE.match(url), url
        # 伺服器已經在服務了(網址印出來了),所以「現在還沒有」不是「還沒寫到」。
        remote = _Remote(int(URL_PARTS_RE.match(url).group(2)), URL_PARTS_RE.match(url).group(3))
        assert send(remote, payload={"path": str(GOLDEN)}).status == 200
        assert list(private.iterdir()) == []

        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        assert proc.returncode == 0, (proc.returncode, err)
        assert list(private.iterdir()) == []


def test_discarding_is_a_no_op_when_there_is_nothing_to_discard(private_tmp):
    """`_discard_redirect` 對 `None`(`--no-browser`)與「已經不在了」都不出聲。

    它跑在退出序列的 `finally` 裡,而那條路徑上還有一句「可能留下明文片段」的
    警告要印:這裡拋例外的話,使用者會為了一個暫存檔少看到那句話。
    """
    cli._discard_redirect(None)
    path = cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    cli._discard_redirect(path)
    assert list(private_tmp.iterdir()) == []
    cli._discard_redirect(path)          # 第二次:檔案與目錄都已經不在了
    assert list(private_tmp.iterdir()) == []


def test_a_write_that_blows_up_leaves_nothing_behind(private_tmp, monkeypatch):
    """`_write_redirect_file` 自己失敗時也不留東西(連 Ctrl-C 那一形)。

    `mkdtemp` 成功之後、檔案寫完之前被打斷的話,`_serve` 的 `redirect` 還是
    `None`(指派還沒發生),於是退出序列那一步**不知道**有東西要刪——所以這個
    函式得自己收。接 `BaseException` 而不是 `Exception` 的理由就是這一形:
    `KeyboardInterrupt` 不是 `Exception`。
    """
    def explode(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.os, "open", explode)
    with pytest.raises(KeyboardInterrupt):
        cli._write_redirect_file(f"http://{webui.LOOPBACK}:1/#{'A' * 43}")
    assert list(private_tmp.iterdir()) == []


def test_the_redirect_url_is_a_js_string_literal_not_a_hand_rolled_quote():
    """`location.replace(...)` 的引數由 `json.dumps` 算,不是手寫的 `"{url}"`。

    網址今天由我們自己組(`LOOPBACK` 是常數、埠是 int、token 是
    `secrets.token_urlsafe` 的 base64url),所以沒有可注入的字元;這條守的是
    明天——哪天網址裡多一個引號或反斜線,手寫引號的那個寫法會產生一段壞掉的
    script(瀏覽器停在空白頁,而使用者只看到「開了但沒反應」)。
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    formats = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "UI_REDIRECT_HTML.format"
    ]
    assert len(formats) == 1, formats
    assert [kw.arg for kw in formats[0].keywords] == ["url"]
    assert ast.unparse(formats[0].keywords[0].value) == "json.dumps(url)"
    # 樣板裡那個位置本身不帶引號——引號是 `json.dumps` 給的。
    assert "location.replace({url})" in cli.UI_REDIRECT_HTML


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

    **`TMPDIR` 也一起指到 `tmp_path`**(複審 T1):用這個夾具的兩條測試刻意
    **不**給 `--no-browser`,所以自 #36 起它們會寫一個**真的帶 token 的跳轉檔**
    ——不隔離的話那個檔案落在 runner 的系統 `/tmp` 裡,而測試中途失敗被
    `SIGKILL` 收掉時它會留在那裡。`_env()` 是 `os.environ` 的複本,故
    `monkeypatch.setenv` 一次就同時管到這個夾具的每一個子程序。
    (in-process 的 `tempfile` 不受影響:`gettempdir()` 早就把結果快取起來了,
    那一側要打的是 `cli.tempfile.tempdir`——見 `private_tmp`。)
    """
    script = tmp_path / "blockbrowser.sh"
    script.write_text("#!/bin/sh\nexec >/dev/null 2>&1\nsleep 60\n", encoding="utf-8")
    script.chmod(0o755)
    private = tmp_path / "tmp"
    private.mkdir()
    monkeypatch.setenv("BROWSER", f"{script} %s")
    monkeypatch.setenv("TMPDIR", str(private))
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


def test_an_interrupt_while_the_browser_thread_starts_is_still_exit_zero(
    serve_forever, private_tmp, capsys, monkeypatch
):
    """Ctrl-C 正好落在**起瀏覽器執行緒**的那幾微秒 → 仍然 exit 0。

    這個窗口是上面那條子程序測試在全套裡隨機撞到的(1138 passed / 1 failed):
    `browser` 若在 `start()` **之前**就被指派,退出路徑的 `join()` 會對一條還沒
    start 的執行緒丟 `RuntimeError: cannot join thread before it is started`;
    它從 `finally` 冒出去、**取代**原本的 `KeyboardInterrupt`,於是 `main()` 把它
    翻成 `qvault: internal error (RuntimeError)` + exit 1——使用者按了 Ctrl-C,
    拿到的卻是「我們有 bug」,而 AC 第 3 條要的是 `returncode == 0`。

    子程序那條靠運氣才撞得到(窗口只有幾微秒),所以這裡用一條**確定性**的:
    把 `Thread.start` 換成「當場丟 `KeyboardInterrupt`」,等價於信號在那一刻到達。
    替身是 `threading.Thread` 的子類別,且只在這一次 `cli.main` 的期間有效
    (`monkeypatch` 負責還原);這段期間本檔沒有別的地方會起執行緒。
    """
    class InterruptedThread(threading.Thread):
        def start(self):
            raise KeyboardInterrupt

    serve_forever()
    monkeypatch.setattr(cli.threading, "Thread", InterruptedThread)
    assert cli.main(["ui", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.err == "", f"不該變成 internal error:{captured.err!r}"
    assert URL_RE.match(captured.out.strip()), captured.out
    # #36 AC-3:這個窗口裡跳轉檔**已經寫出去了**(它在起執行緒之前),所以
    # 「Ctrl-C 落在這裡」也是一條必須把它刪掉的退出路徑。
    assert list(private_tmp.iterdir()) == []


# ================================================================ QA 第 2 輪 F1:在途的工作


#: 「標頭已經送出去了」之後再多等這麼久,才**盡力**讓請求進到在途狀態。
#:
#: **只有子程序那幾條煙霧測試用它,而且沒有任何斷言靠它成立**(複審第 2 輪
#: F-A)。原本的用法是錯的:用它猜「請求已在途」然後嚴格斷言在途請求一定跑完
#: ——猜錯的方向是**假紅**(信號落在請求被數進在途之前 → 根本沒有東西要等 →
#: 請求被丟掉,但那不是產品的錯),主管層本機實測 10 次紅 3 次。嚴格的時序
#: 斷言已搬到 `_InProcessUI` 那幾條:它們等的是**伺服器端可觀測的狀態**
#: (`wait_until_idle(0) is False`、`is_stopping`),一個 sleep 都不猜。
SETTLE = 0.2


def _background(body, errors: list, name: str) -> threading.Thread:
    """在背景跑 `body`,例外收進 `errors` 並回那條執行緒。

    不收的話,輔助執行緒裡的失敗只會變成 pytest 的一條 warning
    (`PytestUnhandledThreadExceptionWarning`),而主執行緒的斷言訊息看不出
    原因——複審第 2 輪 F-A 點名的「失敗訊息把原因歸給錯的東西」就是這麼來的。
    """

    def wrapped() -> None:
        try:
            body()
        except BaseException as exc:  # noqa: BLE001 —— 要帶回主執行緒報
            errors.append(exc)

    thread = threading.Thread(target=wrapped, name=name, daemon=True)
    thread.start()
    return thread


class _InProcessUI:
    """在**主執行緒**上跑一個真的 `ui`:真 `serve_forever`、真信號、真請求。

    為什麼需要它(複審第 2 輪 F-A):「第二個停止信號落在退出路徑等待期間」
    這種斷言要知道**伺服器端**的狀態——請求有沒有被數進在途、退出路徑有沒有
    開始收尾。那個狀態在子程序裡從外面看不到,只能用固定 sleep 猜,而猜錯就是
    假紅。這裡把 `cli.make_server` 包起來、把實例抓在手上,於是每一步都**等到**
    狀態成立才動作:`wait_until_idle(0) is False` → 送第一個信號;`is_stopping`
    → 送第二個。沒有任何斷言靠 sleep。

    信號走 `signal.pthread_kill(<主執行緒>, sig)`:與 Ctrl-C / `kill` 完全同一條
    路(C 層 handler 設旗標 → 主執行緒跑 Python handler),不是直接呼叫 handler
    ——`_Stopped` 要不要被某個 `except` 吞掉這種事,只有走真信號才驗得到。

    子程序那幾條留著當煙霧測試(AC 要的那種跨行程證據),但嚴格的時序斷言在
    這裡。
    """

    #: 主執行緒這麼久還沒回來就認定它卡住了(產品若真的不停——F-B 就是那種
    #: ——測試要**紅**,不是把回合吊死)。
    #:
    #: 15 秒怎麼來的(#40 AC-1):AC 第 3 條給的 5 秒 + **最壞情況的退出預算**。
    #: 嚴格那兩條把等待期限注成 `STRICT_DRAIN_SECONDS = 8.0`,退出預算因此是
    #: 8.0 + 開瀏覽器的 `UI_BROWSER_SECONDS = 0.5` = 8.5 秒,5 + 8.5 = 13.5 秒。
    #: 看門狗比它小的話(原本是 10.0,配 3.5 秒的產品預算)就會在「產品還在
    #: 合法等待」的時候開火:`check()` 的 `self.stuck` 斷言紅,而死因寫的是
    #: 「`ui` 沒有自己停下來」——完全看不出是測試自己的期限太短。
    WATCHDOG_SECONDS = 15.0

    def __init__(self, monkeypatch, join_timeout: float = EXIT_TIMEOUT) -> None:
        self._servers: list[webui.WebUIServer] = []
        self._threads: list[threading.Thread] = []
        self._main = threading.get_ident()
        #: `check()` 收驅動執行緒的期限。預設是 AC 的 5 秒;注了等待期限的那
        #: 兩條要傳 `STRICT_JOIN_SECONDS`,否則呼叫端還在合法地等回應就被判
        #: 「沒有收乾淨」。
        self._join_timeout = join_timeout
        self._returned = threading.Event()
        self.stuck = threading.Event()
        self.errors: list[BaseException] = []
        real_make_server = cli.make_server

        def make_server(port):
            server = real_make_server(port)
            self._servers.append(server)
            return server

        monkeypatch.setattr(cli, "make_server", make_server)

    def until(self, predicate, what: str, timeout: float = EXIT_TIMEOUT):
        """等到 `predicate()` 為真;逾時就是一條說得清楚的紅。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.005)
        raise AssertionError(f"{timeout} 秒內沒等到:{what}")

    def server(self) -> webui.WebUIServer:
        """`ui` 綁好的那個伺服器實例(等到 `make_server` 被呼叫為止)。"""
        self.until(lambda: self._servers, "`ui` 把伺服器綁起來")
        return self._servers[0]

    def fire(self, sig) -> None:
        """對**主執行緒**送一個真信號。"""
        signal.pthread_kill(self._main, sig)

    def drive(self, body, name: str) -> threading.Thread:
        """背景跑一段驅動碼,例外收進 `self.errors`,並記下來等 `check` 收。"""
        thread = _background(body, self.errors, name)
        self._threads.append(thread)
        return thread

    def run(self, *argv: str) -> int:
        """在主執行緒上跑 `cli.main(["ui", *argv])`,帶一條看門狗。"""

        def watchdog() -> None:
            if not self._returned.wait(self.WATCHDOG_SECONDS):
                self.stuck.set()
                if self._servers:
                    self._servers[0].shutdown()

        guard = threading.Thread(target=watchdog, name="watchdog", daemon=True)
        guard.start()
        try:
            return cli.main(["ui", *argv])
        finally:
            self._returned.set()
            guard.join(timeout=EXIT_TIMEOUT)

    def check(self, context: str = "") -> None:
        """**先把驅動執行緒收乾淨**,再報真正的死因。呼叫端要在其他斷言之前叫它。

        收乾淨這一步不是潔癖,是正確性:`cli.main` 回來只代表**伺服器端**的
        退出路徑走完了,不代表那個 HTTP 呼叫端已經把回應讀完、寫進 `result`。
        不 join 就斷言 `result`,等於用「主執行緒回來了」猜「呼叫端也回來了」
        ——又是一個時序假設,而且在有負載的機器上 20 回會紅 9 回(本輪實測,
        症狀正是 access log 已記 `200` 而 `result` 仍是空的)。
        """
        deadline = time.monotonic() + self._join_timeout
        index = 0
        while index < len(self._threads):          # 迴圈中還會長出新執行緒
            self._threads[index].join(timeout=max(0.0, deadline - time.monotonic()))
            index += 1
        alive = [thread.name for thread in self._threads if thread.is_alive()]
        assert not self.stuck.is_set(), f"`ui` 沒有自己停下來(看門狗開火){context}"
        assert not self.errors, (
            f"驅動執行緒出錯(在途請求被砍掉時會是 RemoteDisconnected):"
            f"{self.errors!r}{context}"
        )
        assert not alive, f"驅動執行緒沒有收乾淨:{alive}{context}"


def _slow_api_request(remote, seconds: float, sent: threading.Event | None = None, on_sent=None):
    """送一個 `/api/inspect`,但 body **慢慢**送——請求在途 `seconds` 秒。

    不需要一個大到解密得花好幾秒的檔案:`_handle` 在讀 body **之前**就開始計數
    (在途 = 「這個請求還沒處理完」),所以把 body 拖慢就能造出一個長度可控、
    不佔磁碟的在途窗口。

    `sent` 在**標頭送出之後**被 set:呼叫端等這個事件,而不是賭一個固定的
    `sleep` 夠不夠執行緒起來 + 連線 + 送標頭(那正是本檔在全套裡偶發紅掉的
    那種賭法)。`on_sent` 在 set **之前**被呼叫,給 `_ExitTiming` 蓋那個
    monotonic 時間戳用:等 `sent` 的那一端最多晚 5 毫秒(輪詢間隔)才看到,
    而失敗訊息要的是標頭真的送出去的那一刻。
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
        if on_sent is not None:
            on_sent()
        if sent is not None:
            sent.set()
        time.sleep(seconds)                    # ……然後讓它等 body
        conn.send(body)
        res = conn.getresponse()
        return res.status, res.read()
    finally:
        conn.close()


class _ExitTiming:
    """把退出路徑的時間線量下來,讓那兩條嚴格測試紅的時候說得出**誰晚了**。

    同時做兩件事(#40 AC-1):

    1. **注等待期限**:`monkeypatch.setattr(cli, "UI_DRAIN_SECONDS", drain)`。
       `_serve` 是在呼叫 `wait_until_idle(UI_DRAIN_SECONDS)` 的那一刻才讀這個
       模組屬性(不是 import 時綁死、也沒有預設參數把它凍住),所以 monkeypatch
       有效;`wait_timeout` 把**實際傳進去**的值記下來當證據——下次紅的時候,
       「期限沒注進去」與「真的超時了」因此分得開(triage 建議 ②)。
    2. **蓋三個 monotonic 時間戳**:`sent`(慢請求的標頭送出去)、`wait_started`
       (退出路徑開始等在途工作)、`work_finished`(伺服器把那份工作減回 0)。
       票文那條紅的死因就藏在這三個數之間:`work_finished − wait_started`
       超過期限 = 真的等不到;遠小於期限卻還是紅 = 死因在別處。

    `wait_until_idle(0)` 不算「開始等待」:那是測試自己用來輪詢「請求被數進
    在途了沒」的,一回合會打好幾次。只認第一次 `timeout` 非 0 的呼叫——那是
    退出路徑那一次。
    """

    def __init__(self, monkeypatch, drain: float = STRICT_DRAIN_SECONDS) -> None:
        self.drain = drain
        self.sent: float | None = None
        self.wait_started: float | None = None
        self.wait_timeout: float | None = None
        self.work_finished: float | None = None
        monkeypatch.setattr(cli, "UI_DRAIN_SECONDS", drain)
        real_wait = webui.WebUIServer.wait_until_idle
        real_finished = webui.WebUIServer.work_finished

        def wait_until_idle(server, timeout):
            if timeout and self.wait_started is None:
                self.wait_started = time.monotonic()
                self.wait_timeout = timeout
            return real_wait(server, timeout)

        def work_finished(server):
            # 先蓋戳再減計數:戳要代表「工作做完的那一刻」,而 `real_finished`
            # 會 set `_idle`、把等待那一端放走——先跑它的話這個戳就晚於
            # 「等待結束」,時間線讀起來會變成因果顛倒。
            self.work_finished = time.monotonic()
            real_finished(server)

        monkeypatch.setattr(webui.WebUIServer, "wait_until_idle", wait_until_idle)
        monkeypatch.setattr(webui.WebUIServer, "work_finished", work_finished)

    def mark_sent(self) -> None:
        """`_slow_api_request` 的 `on_sent`:標頭送出去的那一刻。"""
        self.sent = time.monotonic()

    def summary(self) -> str:
        """失敗訊息的尾巴:三個時間戳 + 期限 + 「晚了多久」。"""

        def stamp(value: float | None) -> str:
            return "(沒量到)" if value is None else f"{value:.3f}"

        if self.wait_started is None or self.work_finished is None:
            late = "(算不出來:上面有時間戳沒量到)"
        else:
            late = f"{self.work_finished - self.wait_started:+.3f}s"
        return (
            f";monotonic:sent={stamp(self.sent)}"
            f",開始等待={stamp(self.wait_started)}"
            f",work_finished={stamp(self.work_finished)}"
            f";work_finished−開始等待={late}"
            f";期限=注的 {self.drain:g}s/cli.UI_DRAIN_SECONDS={cli.UI_DRAIN_SECONDS:g}s"
            f"/實際傳進 wait_until_idle={self.wait_timeout!r}"
        )


@posix_only
def test_an_in_flight_request_is_finished_before_the_process_exits():
    """F1:退出前等在途的 `/api/*` 工作做完,不把它砍在半路。

    為什麼要緊:`vault` 的寫法是「寫 `.qvault-*.part` → `os.replace`」,而連線
    執行緒是 daemon——直譯器一結束就被砍掉、`finally` 不跑,於是中途被打斷的
    **解密**會把一個明文片段留在 `out_dir` 裡。純 CLI 沒有這個問題:那裡的解密
    跑在主執行緒上,Ctrl-C 會把堆疊解開、`finally` 清掉暫存檔。是 `ui` 這個
    生命週期把它變出來的,所以也由 `ui` 收掉。

    **這一條是子程序層級的煙霧測試**(複審第 2 輪 F-A):「請求有沒有被數進
    在途」在子程序外面看不到,只能用固定 sleep 猜,而猜錯的方向是假紅——信號
    落在請求被數進去之前,根本沒有東西要等,請求被丟掉不是產品的錯。嚴格那半
    搬到 `test_an_in_flight_request_is_finished_before_the_exit_path_returns`
    (in-process + 輪詢伺服器狀態)。這裡驗的是只有跨行程才看得到的部分:
    rc 0、無 traceback、stdout 只有那一行網址;而**若**請求收到了回應,那個
    回應必須是 `200`(連線被丟掉時不會換成別的狀態碼,只會沒有回應)。
    """
    with running_ui() as (proc, _url, remote):
        result: list[tuple[int, bytes]] = []
        failures: list[BaseException] = []
        sent = threading.Event()
        caller = _background(
            lambda: result.append(_slow_api_request(remote, 2.0, sent)), failures, "caller"
        )
        assert sent.wait(EXIT_TIMEOUT), "請求的標頭沒送出去,測試本身壞了"
        time.sleep(SETTLE)                     # 盡力讓它進到在途;沒有斷言靠它
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        caller.join(timeout=EXIT_TIMEOUT)
    context = f";stderr={err!r};caller={failures!r}"
    assert proc.returncode == 0, f"沒有乾淨退出{context}"
    assert "Traceback" not in err, context
    assert out == "", f"stdout 不只那一行網址{context}"
    if result:
        assert result[0][0] == 200, f"在途的請求拿到非 200:{result!r}{context}"


@posix_only
def test_an_in_flight_request_is_finished_before_the_exit_path_returns(monkeypatch, capsys):
    """F1 的**嚴格**那半:退出路徑真的等在途的 `/api/*` 工作做完才回來。

    與上面那條煙霧測試的差別只有一件事:這裡拿得到伺服器實例,所以信號是在
    **確認請求已被數進在途之後**才送的(`wait_until_idle(0) is False`),不是
    猜的。於是「在途請求必須拿到 200」這個斷言只會因為產品錯了而紅
    (複審第 2 輪 F-A)。

    信號走 `pthread_kill` 送到主執行緒:與真 Ctrl-C 同一條路。

    **等待期限是注進去的**(`_ExitTiming`,#40 AC-1):驗的是「在途工作有沒有
    被等完」,不是「3 秒夠不夠」,所以餘裕給到 body 延遲的 4 倍,不賭排程抖動。
    """
    ui = _InProcessUI(monkeypatch, join_timeout=STRICT_JOIN_SECONDS)
    timing = _ExitTiming(monkeypatch)
    result: list[tuple[int, bytes]] = []

    def driver() -> None:
        server = ui.server()
        remote = _Remote(server.port, server.token)
        sent = threading.Event()
        caller = ui.drive(
            lambda: result.append(
                _slow_api_request(remote, STRICT_BODY_SECONDS, sent, on_sent=timing.mark_sent)
            ),
            "caller",
        )
        ui.until(sent.is_set, "請求的標頭送出去")
        ui.until(lambda: server.wait_until_idle(0) is False, "請求被數進在途工作")
        ui.fire(signal.SIGINT)
        caller.join(timeout=STRICT_JOIN_SECONDS)

    ui.drive(driver, "driver")
    rc = ui.run("--no-browser", "--port", "0")
    err = capsys.readouterr().err
    context = f";stderr={err!r}{timing.summary()}"
    ui.check(context)
    assert rc == cli.EXIT_OK, context
    assert result and result[0][0] == 200, f"在途的請求被砍掉了:{result!r}{context}"
    assert "gave up" not in err, f"在預算內的工作不該觸發放棄等待的警告{context}"
    assert "Traceback" not in err, context


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
    sent = threading.Event()
    caller = threading.Thread(target=lambda: result.append(_slow_api_request(remote, 1.5, sent)))
    caller.start()
    try:
        assert sent.wait(EXIT_TIMEOUT), "請求的標頭沒送出去,測試本身壞了"
        # 標頭到了之後**等到**它被數進去,而不是賭一個固定的 sleep:body 要到
        # 1.5 秒後才送,所以這個迴圈最多轉 1 秒也還在窗口裡。
        deadline = time.monotonic() + 1.0
        while server.wait_until_idle(0) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.wait_until_idle(0) is False, "在途的請求沒有被數到"
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


# ================================================================ 複審 M1:第二個停止信號


def _api_inspect(conn: http.client.HTTPConnection, remote) -> tuple[int, bytes]:
    """在**既有的連線上**送一個合格的 `POST /api/inspect`,回 `(status, body)`。

    與 `_slow_api_request` 的差別只有「不拖 body」與「連線是呼叫端給的」:
    keep-alive 的那一刀(`server_close()` 之後既有連線還送得進新請求)只有在
    同一條連線上連送兩個請求才看得到。
    """
    body = json.dumps({"path": str(GOLDEN)}).encode("utf-8")
    conn.putrequest("POST", webui.API_INSPECT_PATH, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", remote.expected_host)
    conn.putheader("Content-Type", webui.JSON_MEDIA_TYPE)
    conn.putheader("Authorization", f"Bearer {remote.token}")
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    conn.send(body)
    res = conn.getresponse()
    return res.status, res.read()


@posix_only
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=lambda s: s.name)
def test_a_second_stop_signal_does_not_abandon_the_in_flight_request(sig, monkeypatch, capsys):
    """M1:等在途工作的那幾秒裡再收到一次停止信號,**不可以**把等待丟掉。

    為什麼會發生:`wait_until_idle` 底下是 `Event.wait`,POSIX 上信號會打斷它,
    而 PEP 475 的重試只在 handler **不拋例外**時成立——標準庫的 `SIGINT` 拋
    `KeyboardInterrupt`、我們的 `_stop_on_signal` 拋 `_Stopped`,兩者都會從
    `_serve` 的 `finally` 冒出去、被 `_cmd_ui` 接住回 0。症狀完全靜音:rc 還是
    0、stderr 一個字都沒有,但在途的解密被砍在半路,`.qvault-*.part` 明文片段
    留在 out_dir。退出時最多會不出聲地等 3.5 秒,那段時間使用者再按一次
    Ctrl-C 非常自然。

    **量法(複審第 2 輪 F-A 重寫過)**:in-process 跑真的 `ui`,兩個信號都用
    `pthread_kill` 送到主執行緒,而**每一步都等伺服器端的狀態**,不猜時序:
    `wait_until_idle(0) is False`(請求真的在途了)→ 送第一個;`is_stopping`
    (退出路徑真的開始收尾了)→ 送第二個。原本的子程序版用兩個 `sleep(0.2)`
    猜這兩件事,主管層本機 10 次紅 3 次——而紅的是**測試的時序假設**,不是
    產品:信號若落在請求被數進在途之前,根本沒有東西要等。跨行程那半留在
    `test_two_stop_signals_in_a_row_are_a_clean_exit_in_a_real_process`(煙霧)。

    **期限是注進去的**(`_ExitTiming`,#40):這一條驗的是「第二個信號有沒有
    把等待丟掉」,而產品預設的 3 秒期限對上 2 秒的在途窗口只留 1 秒名目餘裕
    ——主管層宿主連跑 20 次紅 3 次,每次都紅在 `gave up after 3s …`:請求拿到
    200、驅動執行緒無錯、看門狗沒開火,只有 `work_finished` 晚於「開始等待
    + 3 秒」。那是測試的時間預算,不是產品的缺陷(#40 票文,獨立複審判定)。
    注成 8 秒之後餘裕是 4 倍;守門力沒有掉——變異「退出序列不包
    `_signals_deferred`」照樣被 `"stopped waiting" not in err` 殺掉(期限再寬也
    沒用:那條路是**例外**把等待丟掉,不是逾時)。
    """
    ui = _InProcessUI(monkeypatch, join_timeout=STRICT_JOIN_SECONDS)
    timing = _ExitTiming(monkeypatch)
    result: list[tuple[int, bytes]] = []

    def driver() -> None:
        server = ui.server()
        remote = _Remote(server.port, server.token)
        sent = threading.Event()
        caller = ui.drive(
            lambda: result.append(
                _slow_api_request(remote, STRICT_BODY_SECONDS, sent, on_sent=timing.mark_sent)
            ),
            "caller",
        )
        ui.until(sent.is_set, "請求的標頭送出去")
        ui.until(lambda: server.wait_until_idle(0) is False, "請求被數進在途工作")
        ui.fire(sig)                           # 第一個:在途窗口正中間
        ui.until(lambda: server.is_stopping, "退出路徑開始收尾(宣布停止受理)")
        ui.fire(sig)                           # 第二個:它正在等那個在途請求
        caller.join(timeout=STRICT_JOIN_SECONDS)

    ui.drive(driver, "driver")
    rc = ui.run("--no-browser", "--port", "0")
    err = capsys.readouterr().err
    context = f";stderr={err!r}{timing.summary()}"
    ui.check(context)
    assert rc == cli.EXIT_OK, context
    assert result and result[0][0] == 200, f"在途的請求沒有跑完:{result!r}{context}"
    assert "gave up" not in err, f"在預算內的工作不該觸發放棄等待的警告{context}"
    assert "stopped waiting" not in err, f"等待不該被中途放棄{context}"
    assert "Traceback" not in err, context


@posix_only
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=lambda s: s.name)
def test_two_stop_signals_in_a_row_are_a_clean_exit_in_a_real_process(sig):
    """M1 的跨行程**煙霧測試**:連送兩次真信號,行程仍然乾淨收場。

    時序斷言不在這裡(見上一條的「量法」)。這裡驗的是只有真行程才看得到的
    部分:連送兩次信號不會變成非零 exit、不吐 traceback、stdout 仍只有那一行
    網址;**若**在途請求收到了回應,那個回應必須是 `200`。
    """
    with running_ui() as (proc, _url, remote):
        result: list[tuple[int, bytes]] = []
        failures: list[BaseException] = []
        sent = threading.Event()
        caller = _background(
            lambda: result.append(_slow_api_request(remote, 2.0, sent)), failures, "caller"
        )
        assert sent.wait(EXIT_TIMEOUT), "請求的標頭沒送出去,測試本身壞了"
        time.sleep(SETTLE)                     # 盡力;沒有斷言靠它
        proc.send_signal(sig)
        time.sleep(SETTLE)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=EXIT_TIMEOUT)
        caller.join(timeout=EXIT_TIMEOUT)
    context = f";stderr={err!r};caller={failures!r}"
    assert proc.returncode == 0, f"連兩個信號沒有乾淨退出{context}"
    assert "Traceback" not in err, context
    assert out == "", f"stdout 不只那一行網址{context}"
    if result:
        assert result[0][0] == 200, f"在途的請求拿到非 200:{result!r}{context}"


@pytest.mark.parametrize("exc", [KeyboardInterrupt, cli._Stopped], ids=["SIGINT", "SIGTERM"])
def test_a_stop_signal_while_the_handlers_are_restored_is_still_exit_zero(
    exc, serve_forever, capsys, monkeypatch
):
    """退出路徑的**最後一步**(還原信號處置)也要是 exit 0 的。

    `_signals_as_exit` 離開時逐一把原處置裝回去,而那段迴圈裡裝著的還是會拋
    例外的 handler。信號落在那幾微秒時,例外是從 **context manager 的離開路徑**
    冒出來的——`with _signals_as_exit(): try: _serve() except …` 這種寫法的
    `except` 不在那條路徑上,於是 `_Stopped` 冒到 `main()` 變成
    `qvault: internal error (_Stopped)` + exit 1、`KeyboardInterrupt` 變成
    `qvault: interrupted` + 130,兩者都違反決策 12。與 `_serve` 裡那個
    join-before-start 的窗口同一族,只是落在更後面一步。

    量法:把 `_signals_as_exit` 換成「正常進出,然後在離開時丟一次」——等價於
    信號正好落在還原那一刻(真信號只能靠運氣撞到)。`_cmd_ui` 必須把它接住。
    """
    real = cli._signals_as_exit

    @contextlib.contextmanager
    def raising_on_exit():
        with real():
            yield
        raise exc                              # ← 信號落在還原處置的那一刻

    monkeypatch.setattr(cli, "_signals_as_exit", raising_on_exit)
    serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.err == "", f"不該變成 interrupted / internal error:{captured.err!r}"
    assert URL_RE.match(captured.out.strip()), captured.out


def test_the_stop_exception_is_not_an_exception_so_socketserver_cannot_eat_it():
    """F-B 的根因,一條斷言:`_Stopped` 必須是 `BaseException`。

    `socketserver._handle_request_noblock`(3.12)把 `process_request` 包在
    `except Exception: handle_error(); shutdown_request()` 裡,而 `webui` 的
    `handle_error` 刻意不出聲(決策 9:不吐 traceback)。`_Stopped` 若是
    `Exception`,信號落在那個窗口時就被整個吞掉——只有那條連線被關、
    `serve_forever` 照跑。`SIGINT` 從來沒有這個毛病,正是因為
    `KeyboardInterrupt` 是 `BaseException`;`_Stopped` 要的是同一種待遇。
    """
    assert issubclass(cli._Stopped, BaseException)
    assert not issubclass(cli._Stopped, Exception), (
        "`except Exception` 吃得到 `_Stopped` 的話,SIGTERM / SIGHUP 會被標準庫吞掉"
    )


@posix_only
def test_a_stop_signal_while_a_connection_thread_starts_still_stops_the_server(
    monkeypatch, capsys
):
    """F-B:信號落在「為新連線起執行緒」那一刻,`ui` 還是要停下來。

    `ThreadingMixIn.process_request` 的 `t.start()` 會等新執行緒真的起來——那是
    一個跑在**主執行緒**上、機器越忙越寬的窗口,而它整段被標準庫包在
    `except Exception` 裡(見上一條)。修正前的症狀:`SIGTERM` 下 AC 第 3 條的
    「5 秒內結束」不成立;`SIGHUP` 下**關掉終端後行程仍在、token 仍有效**,而
    `--help` 與 README 都寫「關掉終端即失效」。

    量法:把 `process_request` 換成「第一次被呼叫時先走一次停止信號的 handler」
    ——等價於信號正好落在那個窗口裡,而且不必賭時序。修正前 `cli.main` 不會
    回來(看門狗開火 → 紅);修正後它立刻回 `EXIT_OK`。
    """
    ui = _InProcessUI(monkeypatch)
    real_process_request = webui.WebUIServer.process_request
    hit = threading.Event()

    def process_request(self, request, client_address):
        if not hit.is_set():
            hit.set()
            # 等價於 SIGTERM 正好落在 `t.start()` 那一刻(handler 跑在主執行緒上)
            cli._stop_on_signal(signal.SIGTERM, None)
        return real_process_request(self, request, client_address)

    monkeypatch.setattr(webui.WebUIServer, "process_request", process_request)

    def knock() -> None:
        server = ui.server()
        with contextlib.closing(
            socket.create_connection((webui.LOOPBACK, server.port), timeout=EXIT_TIMEOUT)
        ):
            ui.until(hit.is_set, "伺服器收下那條連線")

    ui.drive(knock, "knock")
    rc = ui.run("--no-browser", "--port", "0")
    err = capsys.readouterr().err
    ui.check(f";stderr={err!r}")
    assert hit.is_set(), "測試本身沒打到那個窗口(`process_request` 沒被呼叫)"
    assert rc == cli.EXIT_OK, err
    assert "Traceback" not in err, err


def test_the_exit_path_defers_stop_signals_and_restores_them():
    """`_signals_deferred`:區塊內的 handler 收下信號但**不拋**,離開時還原。

    直接呼叫那個已安裝的 handler(不 `os.kill` 自己:handler 要是沒裝上,
    `SIGTERM` 的預設處置會把跑測試的行程殺掉)。「不拋」就是 PEP 475 能把
    等待接回去的條件,也是這個 context manager 存在的唯一理由。
    """
    watched = (signal.SIGINT, *cli._STOP_SIGNALS)
    before = {sig: signal.getsignal(sig) for sig in watched}
    with cli._signals_deferred():
        for sig in watched:
            handler = signal.getsignal(sig)
            assert callable(handler), f"{sig!r} 的 handler 沒裝上:{handler!r}"
            assert handler is not before[sig], f"{sig!r} 還是原本那個會拋例外的 handler"
            handler(sig, None)                 # 不可以拋:拋了就是等待會被丟掉
    assert {sig: signal.getsignal(sig) for sig in watched} == before, "離開時沒有還原"


def test_the_exit_path_announces_the_stop_before_it_waits(serve_forever, capsys, monkeypatch):
    """退出序列的順序:先宣布停止受理,**才**開始等在途工作。

    反過來(先等、等完才宣布)等於留一個窗口:等待結束之後才從 keep-alive 的
    既有連線進來的那個 `/api/*` 沒有任何人在等它,而它寫的 `.qvault-*.part`
    會被直譯器結束時砍掉的 daemon 執行緒留在半路。
    """
    seen: list[bool] = []
    real = webui.WebUIServer.wait_until_idle

    def recording(self, timeout):
        seen.append(self.is_stopping)
        return real(self, timeout)

    monkeypatch.setattr(webui.WebUIServer, "wait_until_idle", recording)
    served = serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    capsys.readouterr()
    assert seen == [True], f"開始等的時候還沒宣布停止:{seen!r}"
    assert served and served[0].is_stopping is True


def test_abandoning_the_wait_still_warns_about_the_part_file(serve_forever, capsys, monkeypatch):
    """等待**被中途放棄**(而不是逾時)時也要印那行警告。

    `_signals_deferred` 把常見的那條路(第二個信號)關掉了,但它裝上之前還有
    幾微秒的窗口,而「沒等完就退出」這件事對使用者的意義一模一樣:磁碟上可能
    多了一個明文片段。這條把那個窗口模擬成「`wait_until_idle` 直接拋」,驗
    exit 仍是 0、而且**不是靜音**的。
    """

    def interrupted(self, timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(webui.WebUIServer, "wait_until_idle", interrupted)
    serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, lines
    assert lines[0].startswith("qvault: stopped waiting for a request still running"), lines[0]
    assert ".qvault-*.part" in lines[0]
    assert "Traceback" not in captured.err


class _InterruptedOnEnter:
    """`_signals_deferred` 的替身:`__enter__` 走到一半就被停止信號打斷。

    真實形狀:`__enter__` 裡那幾個 `signal.signal(sig, ignore)` 跑的時候,裝著
    的**還是**會拋例外的那個 handler(標準庫的 `SIGINT` → `KeyboardInterrupt`、
    `cli._stop_on_signal` → `cli._Stopped`),信號落在那裡例外就從 `with` 那一行
    冒出去:body 一次都沒跑,區塊**內**的 `finally` 也就沒跑。那是 `_serve` 的
    退出序列裡唯一還會「沒等完就退出」卻可能靜音的一格。

    用替身而不是真的去打那個窗口:窗口是幾微秒寬的,打中它只能靠運氣——而這
    條測試要驗的是 `_serve` 外層那個 `try/finally`,不是 `_signals_deferred`
    自己(它有 `test_the_exit_path_defers_stop_signals_and_restores_them`)。
    同一個手法:`test_abandoning_the_wait_still_warns_about_the_part_file` 也是
    把 `wait_until_idle` 換成「直接拋」。
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self):
        raise self._exc

    def __exit__(self, *exc_info) -> bool:
        return False                           # 進不去就不會離開,放這裡只為合約完整


@pytest.mark.parametrize(
    "exc",
    [KeyboardInterrupt(), cli._Stopped()],
    ids=["KeyboardInterrupt", "_Stopped"],
)
def test_a_signal_before_the_deferral_is_installed_still_warns(
    exc, serve_forever, capsys, monkeypatch
):
    """#40 AC-2:信號落在 `_signals_deferred.__enter__` **完成之前**,警告仍要印。

    那一行警告說的是「輸出目錄可能留下明文 `.qvault-*.part`」——使用者有權
    知道該去看一眼。PR #35 把 `_report` 搬進 `with` 區塊內(處置還沒還原,
    信號吃不掉那次 I/O),順手把這一格變成**靜音**:例外從 `with` 那一行冒
    出來,區塊內的 `finally` 沒跑過。那是一個退步,不是新行為——`_serve` 外層
    的 `try/finally` + `reported` 旗標把它補回來(主管層 2026-11-14 裁 (b))。

    exit code 仍是 0(`_cmd_ui` 接掉 `KeyboardInterrupt` / `_Stopped`),而
    stderr 恰好一行:兩層 `finally` **不可以**各印一次。
    """
    monkeypatch.setattr(cli, "_signals_deferred", lambda: _InterruptedOnEnter(exc))
    served = serve_forever()
    assert cli.main(["ui", "--no-browser", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, f"警告沒印、或印了兩次:{lines!r}"
    assert lines[0].startswith("qvault: stopped waiting for a request still running"), lines[0]
    assert ".qvault-*.part" in lines[0]
    assert "Traceback" not in captured.err
    # 這條路徑沒走到產品的 `server_close()`(例外在它之前就冒出去了),listen
    # socket 因此留在測試行程手上:自己收掉,不要漏給後面的測試。
    assert served, "沒有真的開始服務"
    served[0].server_close()


def test_a_signal_before_the_deferral_is_installed_still_deletes_the_redirect(
    opened, serve_forever, private_tmp, capsys, monkeypatch
):
    """#36 × #40 的交點(本次 base 合併的解法所在):那一格也要把跳轉檔刪掉。

    上面那條(#40 AC-2)驗的是「警告仍要印」,走的是 `--no-browser`。同一格在
    **預設**(有開瀏覽器)下還多一件事:磁碟上已經有一個帶 token 的跳轉檔,而
    區塊**內**的 `finally`——#36 原本放刪除的地方——一次都沒跑。所以 `_serve`
    外層那個 `try/finally` 除了補印警告,也補刪那個檔案(`_discard_redirect`
    是 idempotent 的,正常路徑上這第二次呼叫什麼都不做)。

    這條是**解衝突的證人**:兩票各自的那一半都還在(警告恰一行、檔案不留),
    刪掉外層那一行刪除即紅。
    """
    monkeypatch.setattr(cli, "_signals_deferred", lambda: _InterruptedOnEnter(KeyboardInterrupt()))
    served = serve_forever()
    assert cli.main(["ui", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()

    assert URL_RE.match(captured.out.strip()), captured.out
    assert len(opened) == 1, "預設路徑:瀏覽器還是要被叫一次"
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, f"警告沒印、或印了兩次:{lines!r}"
    assert lines[0].startswith("qvault: stopped waiting for a request still running"), lines[0]
    assert list(private_tmp.iterdir()) == [], "這一格的跳轉檔沒被刪掉"
    # 同上一條:這條路徑沒走到產品的 `server_close()`,listen socket 自己收。
    assert served, "沒有真的開始服務"
    served[0].server_close()
def test_the_redirect_is_gone_before_the_stop_signals_come_back(
    opened, serve_forever, private_tmp, capsys, monkeypatch
):
    """刪跳轉檔發生在**信號處置還原之前**:第二個 Ctrl-C 搶不走它(#36 AC-3)。

    `_serve` 有兩處 `_discard_redirect`,而它們的**保證不一樣**:

    - 區塊**內**那一處(`with _signals_deferred():` 裡的 `finally`)跑的時候停止
      信號還是降級的,所以那一步刪除不會被打斷;
    - 區塊**外**那一處(`_serve` 外層的 `finally`,本次 base 合併補的)跑的時候
      處置**已經還原**,落在那一刻的停止信號會讓 handler 拋例外、把那一步刪除
      整個跳過,磁碟上就留著一個帶 token 的檔案。它補的是另一格(`__enter__`
      自己被信號打斷,見上一條),不是這一格。

    只斷言「`main` 回來之後檔案在不在」的話兩者同形——外層那一處一樣刪得掉,
    於是把區塊內那一行拿掉,本檔其餘的斷言**全都還是綠的**(實測 136 passed)。
    故這條把斷言打在那個**時刻**上:包一層 `_signals_deferred`(真貨照跑),在
    它的 `__exit__`——區塊內的 `finally` 之後、`signal.signal` 還原之前——量一次
    暫存根目錄,要的是「那時候就已經空了」。拿掉區塊內那一行刪除即紅。
    """
    real = cli._signals_deferred
    at_exit: list[list[str]] = []

    class WatchedDeferral:
        """真的 `_signals_deferred`,只多記一筆「離開那一刻根目錄有什麼」。"""

        def __enter__(self):
            self._inner = real()
            return self._inner.__enter__()

        def __exit__(self, *exc_info):
            at_exit.append(sorted(path.name for path in private_tmp.iterdir()))
            return self._inner.__exit__(*exc_info)

    monkeypatch.setattr(cli, "_signals_deferred", WatchedDeferral)
    served = serve_forever()
    assert cli.main(["ui", "--port", "0"]) == cli.EXIT_OK
    captured = capsys.readouterr()

    assert URL_RE.match(captured.out.strip()), captured.out
    assert captured.err == "", f"乾淨退出不該吐 stderr:{captured.err!r}"
    assert len(opened) == 1, "預設路徑:瀏覽器還是要被叫一次"
    assert served, "沒有真的開始服務"
    assert at_exit == [[]], (
        f"停止信號還原的那一刻跳轉檔還在:{at_exit!r}"
        "——那一步刪除必須跑在 `_signals_deferred` 區塊內"
    )
    assert list(private_tmp.iterdir()) == []


def test_a_new_api_request_after_the_stop_is_503(server):
    """M1 的同類:`server_close()` 之後既有 keep-alive 連線送進的 `/api/*` 拿 503。

    `server_close()` 關的是 **listen socket**,不是已經建立的連線——頁面開著的
    瀏覽器那條連線還在,它送進來的請求照樣會被服務。那份工作在退出路徑等完
    之後才開始寫 `.qvault-*.part`,而沒有任何人在等它。

    `503`(不是 `4xx`):客戶端沒做錯事,是伺服器不幹了。被擋下的請求**不計入**
    在途工作(否則計數會在沒人減的情況下留著,`_idle` 永遠不 set)。
    """
    conn = http.client.HTTPConnection(webui.LOOPBACK, server.port, timeout=READ_TIMEOUT)
    try:
        remote = _Remote(server.port, server.token)
        assert _api_inspect(conn, remote)[0] == 200, "連線要先是一條用得好的 keep-alive 連線"

        server.stop_accepting_work()
        assert server.is_stopping is True

        status, body = _api_inspect(conn, remote)
        assert status == 503, f"退出中的伺服器還在受理新工作:{status}"
        assert json.loads(body)["error"] == "server is shutting down"
        assert server.wait_until_idle(0) is True, "被擋下的請求不該被數進在途工作"
    finally:
        conn.close()


def test_the_stop_only_closes_the_api_doors(server):
    """宣布停止只擋 `/api/*`:頁面與靜態內容照舊 200。

    它們不寫檔,擋它們換不到任何東西——只會讓「退出中的那一瞬間重新整理頁面」
    變成一個看不懂的錯誤畫面。
    """
    server.stop_accepting_work()
    assert send(server, method="GET", path=webui.PAGE_PATH, token=None).status == 200
    assert send(server, method="GET", path=webui.APP_JS_PATH, token=None).status == 200


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
        "into a cookie or into browser storage",  # 不進 cookie / 瀏覽器儲存
        "it is printed here",        # F4:它**就在**這個終端上
        "where ps can",              # F4 / #36:命令列那一面(現在是「拿不到」)
        "other users on this machine",  # 複審 L1:預設沒有 hidepid,不只「同使用者」
        "--no-browser",
        # 以下為 #36(使用者 2026-11-10 裁定)的修訂:事實變了,說法跟著變。
        "It is not passed to the browser on a command line",
        "a 0600 file in a 0700 private directory",
        "deleted when this command stops",
        "kill -9",                   # 收不乾淨的那幾形(ADR-002「不防」)
        "cannot catch or does not handle",  # 複審 S1:不只 kill -9
        "no redirect page is written at all",  # `--no-browser` 的新保證(AC-4)
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


def test_the_help_no_longer_claims_the_token_is_never_written_to_a_file(capsys):
    """#36:`--help` 不得再說「qvault never writes it to a file」——那也成了假話。

    自 #36 起 token **有**一個落地的地方:那個跳轉檔(0600、在 0700 的私有目錄
    裡、命令停掉就刪)。說明因此要說的是「只有那一個地方,而它長這樣、什麼時候
    消失、哪一種死法會留下殘留」,不是一句「從來不寫檔」。同一句話在 README 那
    邊也有一條(`test_the_readme_no_longer_claims_the_token_is_never_written`)。
    """
    with pytest.raises(SystemExit):
        cli.main(["ui", "--help"])
    out = capsys.readouterr().out
    assert "never writes it to a file" not in out
    assert "writes it to a file" not in out


def test_the_help_does_not_say_the_browser_is_handed_the_url_any_more(capsys):
    """#36:`--help` 不得再說「opening the browser passes the URL to that program」。

    那是 #24 寫下的事實,而本票就是來改掉這個事實的。這條與上面兩條負向測試
    同一個用途:文件與碼之間的「第二本帳」一旦漂開,漂掉的那一份是安全說明。
    """
    with pytest.raises(SystemExit):
        cli.main(["ui", "--help"])
    out = capsys.readouterr().out
    assert "passes the URL to that program" not in out
    assert "on its command line, where ps can see it" not in out


def test_the_help_does_not_narrow_the_ps_exposure_to_your_own_processes(capsys):
    """複審 L1:`--help` 不得讀起來像「只有同使用者看得到」。

    Linux 預設沒有 `hidepid`,`/proc/<pid>/cmdline` **同機任何使用者**都讀得到,
    所以「processes running as you」這個限定詞把暴露面說窄了。威脅模型照舊
    (ADR-002:同機其他帳號在模型之外),但文案不可以把它說得比實際更窄——
    使用者會依這句話決定要不要在共用主機上跑這個命令。

    #36(使用者 2026-11-10 裁定)已經把網址從命令列拿掉了,所以同一句話現在說的
    是「`ps` **拿不到**,而那正是跳轉檔存在的理由」;那個限定詞照樣不能回來——
    它窄的是「誰讀得到 `ps`」這件事實,而那件事實沒有變。
    """
    with pytest.raises(SystemExit):
        cli.main(["ui", "--help"])
    out = capsys.readouterr().out
    assert "Processes running as you are outside the threat model" not in out


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
        "into a cookie or into browser storage",
        "where `ps` can see it",   # F4 / #36:命令列那一面(現在是「拿不到」)
        "other users on this machine",  # 複審 L1:預設沒有 hidepid 的那句實話
        "*does* send it",          # 複審 L2:fragment 不進請求行,但 JS 會送回來
        "`Authorization: Bearer` header",
        # 以下為 #36(使用者 2026-11-10 裁定)的修訂。
        "*not* handed to the browser on a command line",
        "a `0600` file in a `0700` private temporary directory",
        "the only file the token is ever written to",
        "`kill -9`",
        "cannot catch or does not handle",  # 複審 S1:不只 kill -9
        "then no redirect page is written at all",
        "2026-11-10",              # 修訂寫明是哪一天的裁定
    ],
)
def test_the_readme_install_section_documents_the_ui(expected):
    """AC 8:README「📦 Install / use」段有 `qvault ui` 用法與三句安全說明。"""
    assert expected in _readme_section("## 📦 Install / use")


def test_the_readme_does_not_claim_the_token_stays_in_memory():
    """F4 的 README 面:同一句假話不能留在這裡。"""
    assert "only ever lives in memory" not in _readme_section("## 📦 Install / use")


def test_the_readme_no_longer_claims_the_token_is_never_written():
    """#36 的 README 面:「never writes it to a file」那句話也不能留在這裡。

    理由同 `--help` 那條:token 現在**有**一個落地的地方,而 README 是使用者
    決定「要不要在共用主機上跑這個命令」時讀的那一份。
    """
    section = _readme_section("## 📦 Install / use")
    assert "never writes it to a file" not in section
    assert "passes the URL to that program" not in section


def test_the_readme_does_not_narrow_the_ps_exposure_either():
    """複審 L1 的 README 面:同一個限定詞不能留在這裡(理由見 `--help` 那條)。"""
    section = _readme_section("## 📦 Install / use")
    assert "Processes running as you are outside the threat model" not in section


def test_the_readme_still_documents_the_other_three_commands():
    """AC 8 的「不改其他段落」在本節內的那一半:三個舊子命令的用法還在。"""
    section = _readme_section("## 📦 Install / use")
    for line in ("pip install -e .", "qvault encrypt", "qvault decrypt", "qvault inspect"):
        assert line in section


# ================================================================ #36 AC-5:ADR-002 的修訂


ADR_PATH = REPO_ROOT / "docs" / "adr" / "ADR-002-local-web-ui.md"


def _adr() -> str:
    return ADR_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "expected",
    [
        "2026-11-10 使用者裁定",          # 修訂寫明是哪一天、誰裁定的
        "瀏覽器程序的命令列",              # 威脅模型「防」③ 新增的那一形
        "/proc/<pid>/cmdline",
        "攔不住或未處理的致死信號下跳轉檔的殘留",  # 「不防」新增的那一形(複審 S1 校過措辭)
        "`_STOP_SIGNALS` 只處理 `SIGTERM` / `SIGHUP`",
        "殘留只有**啟動者**讀得到",         # 且說明殘留的可讀範圍
        'location.replace("http://127.0.0.1:<port>/#<token>")',  # 決策 12 的機制
        "`tempfile.mkdtemp()`",
        "`--no-browser` **一個檔案都不寫**",
        "寫檔發生在綁 socket 成功之後",
        "不經那條 CSP",                    # 留言 ① 要的那句:跳轉檔不是決策 10 的頁面
    ],
)
def test_the_adr_records_the_redirect_file_decision(expected):
    """AC-5:決策 12 改寫、威脅模型兩欄各補一形、修訂寫明裁定日。

    ADR-002 是這個專案的安全憲法(種子四類「安全」,合併即核准),而這張票動的
    正是它——所以「文件有沒有真的跟著改」要有測試,不是靠讀 PR 的人記得。同一
    條規矩已經有先例:`tests/test_webui_server.py::test_csp_constant_matches_adr_002`
    把決策 10 那一串 CSP 釘在 ADR 原文上。
    """
    assert expected in _adr()


def test_the_adr_no_longer_says_the_token_is_never_written_to_a_file():
    """決策 5 的「token 不寫檔」在本票之後是假的,ADR 自己不可以留著它。

    留著的話,ADR 就有兩段互相矛盾的話(決策 5 說不寫檔、決策 12 說寫一個
    跳轉檔),而讀者沒有辦法知道哪一段是現行的——這正是 QA 在 `.asp/pr/4.md`
    判過的「第二本帳」。
    """
    adr = _adr()
    assert "token 不寫檔" not in adr
    assert "預設 `webbrowser.open` 該網址" not in adr, "決策 12 的舊行為還留在 ADR 裡"


def test_the_redirect_page_is_not_one_of_the_contents_the_server_serves():
    """留言 ① 的擔憂,釘成測試:跳轉檔不在決策 10 / 11 的掃描半徑裡。

    跳轉檔必然帶 inline script(`location.replace(...)`),而決策 10 的 CSP 與
    「前端零 inline script」是對**伺服器服務的那三份內容**說的
    (`tests/test_webui_page.py` 掃的是 `webui.PAGE_HTML`)。這條守兩件事:
    ① 跳轉檔不是那三份裡的任何一份;② 它也沒有被偷偷掛成一條新路由——它只以
    `file://` 存在,一旦變成 HTTP 服務的東西,那條 CSP 就會讓它當場失效,而
    #23 那條掃 inline script 的凍結測試也會紅。
    """
    assert cli.UI_REDIRECT_HTML not in (webui.PAGE_HTML, webui.APP_JS, webui.APP_CSS)
    assert "location.replace" not in webui.PAGE_HTML
    assert set(webui._STATIC_RESPONSES) == {"/", "/app.js", "/app.css"}
    assert f"/{cli.UI_REDIRECT_NAME}" not in webui._STATIC_RESPONSES


def test_the_served_page_is_still_free_of_inline_script(server):
    """同一件事的另一半:本票一個字都沒改到伺服器服務的那份 HTML。

    #23 那條凍結測試(`tests/test_webui_page.py`)掃的是 `webui.PAGE_HTML`,這裡
    順手從**真 socket** 再確認一次:本票落地之後,`/` 的內容裡還是沒有 inline
    script,決策 10 的那條凍結測試因此不會被本票踩紅。
    """
    body = send(server, "GET", "/").text
    assert "<script src=\"/app.js\"" in body
    assert "location.replace" not in body
    assert cli.UI_REDIRECT_NAME not in body


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
