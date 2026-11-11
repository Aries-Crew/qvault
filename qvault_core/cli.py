"""CLI 層:`qvault encrypt / decrypt / inspect / ui`(argparse)。

相依圖(ADR-001「模組切法」)的最外層:`cli → vault → {container, aead, kek}`,
自 #24 起另有 `cli → webui`(ADR-002 決策 13 定的方向;反向一條都沒有)。
本檔**只做五件事**——解析參數、問密碼、把例外翻成一行乾淨訊息 + 非零 exit、
把 `inspect` 的白名單欄位印出來、把本機 Web UI 跑起來並乾淨地收掉。
密碼學、格式、檔名淨化一律不在這裡發生。

## 三條在本層才成立的規矩

1. **密碼只從 `getpass` 來,永遠不是一個選項。** 沒有 `--passphrase`、沒有
   `--password`、沒有從環境變數讀:進 argv 的密碼會躺在 shell history、`ps aux`
   與 CI log 裡。`encrypt` 另問第二次確認——打錯字的密碼會產生一個**誰也解不開**
   的檔案,而錯誤要到還原那天才發作。空字串直接拒絕(決策 8 不強制強度,但空
   字串不是弱、是無)。
2. **不吐 traceback。** 錯密碼、壞檔、缺檔都是**正常的使用情境**,不是程式錯誤;
   traceback 對使用者是雜訊,對工單是雜訊,而 frame 裡躺著密碼與 DEK。所有出口
   都收斂成 `qvault: <一行>` 到 stderr + 非零 exit(見 `_report`)。
3. **`inspect` 走白名單,不是黑名單**([M7])。輸出欄位寫死在 `_INSPECT_FIELDS`
   裡,新增 header 欄位**不會**自動被印出來——黑名單(「印全部,除了 salt…」)
   只要 header 多一欄就默默漏一欄。`salt` / `nonce_prefix` / `wrapped_dek` 因此
   在本檔的**程式碼裡一次都沒有被取值**(`tests/test_cli.py` 掃 AST 守著,只有這
   段說明文字提到它們):wrapped DEK 進了終端截圖或工單,攻擊者不需要那個檔案
   就能離線爆密碼。

## 本層不做的事(#4 的 `.asp/pr/4.md`「對後續票的介面承諾」)

- **不做檔名淨化、不自己組還原路徑**:`decrypt_file` 已經做完全套(Zip Slip、
  Windows 保留名、`realpath` 圍籬),回傳值就是實際寫出的路徑,直接印它。
  在這裡再做一份 = 兩份會漂,而漂掉的那一份是安全檢查。
- **`inspect` 不解 chunk 0**:原始檔名與 `orig_size` 在 chunk 0 裡,要密碼才拿得到,
  而它們正是決策 9 要保護的中繼資料。`inspect` 因此**不收密碼**。
- **不區分「密碼錯」與「被竄改」**:兩者共用 `QVaultDecryptError` 且訊息逐字相同
  (保證③);CLI 照抄,不自己加「密碼可能錯誤」之類的猜測——那就是把 ADR 花力氣
  消掉的 oracle 在最外層又裝回去。
- **`ui` 不決定任何 Web UI 的事**:綁哪個位址、token 怎麼來、哪些門要擋,全在
  `webui.py`(ADR-002 決策 4、5、6)。本層只做「起它 / 印那一行 / 開瀏覽器 /
  收掉」,故這裡**沒有** `--host`、`--bind`,也沒有任何改綁定位址的路徑——
  `make_server` 的簽章就只有 `port`,型別層面就改不了。
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import signal
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__
from .container import HEADER_SIZE_KEM1, deserialize
from .errors import (
    MSG_INPUT_IS_DIR,
    MSG_INPUT_MISSING,
    MSG_INPUT_NO_NAME,
    MSG_INPUT_NOT_REGULAR,
    MSG_OUT_DIR_MISSING,
    MSG_PASSPHRASE_EMPTY,
    MSG_PASSPHRASE_UNENCODABLE,
    MSG_REFUSE_OVERWRITE,
    classify,
)
from .vault import decrypt_file, encrypt_file
from .webui import LOOPBACK, make_server

__all__ = ["main"]

PROG = "qvault"

#: `encrypt <f>` 的輸出檔名 = `<f>` **加上**這個後綴(不是取代副檔名):
#: `secret.txt` → `secret.txt.qvt`。還原端的檔名不從這裡推,是從 chunk 0 解出來的。
QVT_SUFFIX = ".qvt"

# exit code:0 成功、1 操作失敗(全部乾淨錯誤)、2 argparse 的用法錯誤(其預設)、
# 130 使用者 Ctrl-C(128 + SIGINT,shell 慣例)。測試只斷言「非零」,但這張表讓
# 腳本能分辨「檔案有問題」與「你參數打錯了」。
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_INTERRUPT = 130

#: 演算法 id → 人看得懂的名字。純顯示用;id 的合法性由 `container` 把關
#: (未知 id 在 `deserialize` 就被擋下,不會走到這裡)。
_KDF_NAMES = {1: "scrypt"}
_AEAD_NAMES = {1: "AES-256-GCM"}
_KEM_NAMES = {1: "scrypt-KEK"}


class _CleanExit(Exception):
    """本層自己判定的使用錯誤:一行訊息 + 非零 exit,永不 traceback。

    只裝**訊息**,不裝原例外——`__cause__` 一旦帶上,任何一個手滑的 `raise` 都
    可能把底層例外印出來。
    """

    def __init__(self, message: str, code: int = EXIT_FAIL) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- 密碼


def _check_encodable(passphrase: str) -> None:
    """孤兒代理對(Windows argv / 某些輸入法)會讓 `kek` 那邊丟 `ValueError`。

    在這裡先擋,是為了給一句可操作的訊息;**不得**把 `UnicodeEncodeError` 轉述
    出去——它的訊息會把出錯的那個字元印出來,而那是密碼的一部分(鐵律 5)。
    """
    try:
        passphrase.encode("utf-8")
    except UnicodeEncodeError:
        raise _CleanExit(MSG_PASSPHRASE_UNENCODABLE) from None


def _prompt(label: str) -> str:
    """`getpass` 的薄封裝:把「沒有 stdin」翻成乾淨錯誤,不讓 `EOFError` 冒出來。

    提示字串寫到 **stderr**(`getpass` 的預設就是 stderr),故 `qvault inspect` 這
    類的 stdout 永遠只有資料,管線接得動。
    """
    try:
        return getpass.getpass(label)
    except EOFError:
        raise _CleanExit("no terminal available to read the passphrase") from None


def _ask_new_passphrase() -> str:
    """`encrypt`:問兩次,兩次一致才算數;空字串直接拒絕。"""
    passphrase = _prompt("Passphrase: ")
    if not passphrase:
        raise _CleanExit(MSG_PASSPHRASE_EMPTY)
    _check_encodable(passphrase)
    if _prompt("Confirm passphrase: ") != passphrase:
        # 不提示「哪裡不一樣」——那會把密碼的資訊漏給旁邊的人/螢幕錄影。
        raise _CleanExit("passphrases do not match")
    return passphrase


def _ask_passphrase() -> str:
    """`decrypt`:問一次。

    空字串在這裡就拒絕,不進 KDF:`encrypt` 從不接受空密碼,故不存在任何一個
    `.qvt` 是空密碼加密的——省下的那次 scrypt 是 80ms,而使用者拿到的是「你什麼
    都沒輸入」而不是「密碼錯誤」。
    """
    passphrase = _prompt("Passphrase: ")
    if not passphrase:
        raise _CleanExit(MSG_PASSPHRASE_EMPTY)
    _check_encodable(passphrase)
    return passphrase


# ---------------------------------------------------------------- 輸入檢查


def _require_file(path: Path) -> None:
    """輸入必須是一個**普通檔案**;不是的話在問密碼**之前**就說清楚。

    三種情況分開講,因為使用者的下一步不一樣:打錯路徑、把目錄當檔案傳、
    指到一個 FIFO/裝置。底層的 `open()` 也會擋(`IsADirectoryError` 等),但那
    要等到密碼問完之後——沒有人該為了一個打錯的路徑白打兩次密碼。
    """
    if not path.exists():
        raise _CleanExit(MSG_INPUT_MISSING.format(path=path))
    if path.is_dir():
        raise _CleanExit(MSG_INPUT_IS_DIR.format(path=path))
    if not path.is_file():
        raise _CleanExit(MSG_INPUT_NOT_REGULAR.format(path=path))


# ---------------------------------------------------------------- 子命令


def _cmd_encrypt(args: argparse.Namespace) -> int:
    """`encrypt <f>` → `<f>.qvt`(同目錄、同名加後綴)。"""
    inp = Path(args.file)
    if not inp.name:
        # `.` / `..` / `/`:`with_name` 會丟 ValueError,先擋成一句話。
        raise _CleanExit(MSG_INPUT_NO_NAME.format(path=inp))
    out = inp.with_name(inp.name + QVT_SUFFIX)

    _require_file(inp)
    if out.exists() and not args.force:
        # `encrypt_file` 也會擋(它才是真正的守門人,見下方 FileExistsError),
        # 這裡先擋只是為了不讓使用者白打密碼。
        raise _CleanExit(MSG_REFUSE_OVERWRITE.format(path=out))

    passphrase = _ask_new_passphrase()
    print(encrypt_file(inp, out, passphrase, force=args.force))
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """`decrypt <f.qvt> [--out-dir DIR] [--force]`;檔名由 `decrypt_file` 還原。"""
    inp = Path(args.file)
    out_dir = Path(args.out_dir)
    _require_file(inp)
    if not out_dir.is_dir():
        raise _CleanExit(MSG_OUT_DIR_MISSING.format(path=out_dir))

    passphrase = _ask_passphrase()
    # 回傳值就是實際寫出的路徑(檔名經 C4 淨化)——不要自己從 `f.qvt` 去掉副檔名猜。
    print(decrypt_file(inp, out_dir, passphrase, force=args.force))
    return EXIT_OK


#: [M7] `inspect` 的**白名單**:(標籤, 取值函式)。
#:
#: 一律具名取欄位,**不**走 `dataclasses.asdict` / `vars()` / `FIELD_LAYOUT` 迴圈——
#: 那些都是黑名單思維:header 哪天多一欄,迴圈就自動把它印出來,而下一個新欄位
#: 很可能又是個不該見光的東西。這裡多一欄要有人動手加,程式碼審查看得見。
_INSPECT_FIELDS: tuple[tuple[str, object], ...] = (
    ("version", lambda h: h.version),
    ("kdf_id", lambda h: f"{h.kdf_id} ({_KDF_NAMES.get(h.kdf_id, 'unknown')})"),
    ("aead_id", lambda h: f"{h.aead_id} ({_AEAD_NAMES.get(h.aead_id, 'unknown')})"),
    ("kem_id", lambda h: f"{h.kem_id} ({_KEM_NAMES.get(h.kem_id, 'unknown')})"),
    ("kdf_log2n", lambda h: h.kdf_log2n),
    ("kdf_r", lambda h: h.kdf_r),
    ("kdf_p", lambda h: h.kdf_p),
    ("chunk_size", lambda h: h.chunk_size),
)


def _cmd_inspect(args: argparse.Namespace) -> int:
    """`inspect <f.qvt>`:只印 header 白名單 + 檔案在磁碟上的位元組數。

    **不問密碼**:白名單的每一項都在明文 header 裡,而需要密碼才拿得到的兩樣
    東西(原始檔名、`orig_size`)正是決策 9 要保護的中繼資料——為了顯示它們而
    在 header 新增明文欄位,等於親手把決策 9 拆掉([M7] 明令禁止)。
    """
    inp = Path(args.file)
    _require_file(inp)

    with open(inp, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        header, _ = deserialize(fh.read(HEADER_SIZE_KEM1))

    rows = [(label, str(get(header))) for label, get in _INSPECT_FIELDS]
    rows.append(("file_size", f"{size} bytes"))
    width = max(len(label) for label, _ in rows) + 1
    for label, value in rows:
        print(f"{label + ':':<{width + 1}} {value}")
    return EXIT_OK


# ---------------------------------------------------------------- ui(本機 Web UI)

#: `ui --help` 的說明本體(決策 12 要求「只綁 127.0.0.1;網址含一次性 token,
#: 不要貼給別人」寫在使用者看得到的地方)。以 `RawDescriptionHelpFormatter`
#: 原樣輸出,不讓 argparse 重排斷行——這幾句是安全說明,不是裝飾。
#:
#: 第三、四點是 #24 QA 第 2 輪 F4 的修正:原文寫「The token only ever lives in
#: memory」,而那是**假的**——它就印在這個終端上(於是在 scrollback 裡、在你
#: 導向的那個檔案裡),開瀏覽器時又以命令列參數交給那支程式(`ps` 看得到)。
#: 同使用者的其他行程本來就在威脅模型之外(ADR-002),但說明不可以說假話。
UI_DESCRIPTION = """Serve the local web UI, print its URL, and open it in a browser.

Four things worth knowing before you use it:

  * It binds 127.0.0.1 only. There is no --host and no --bind: the address
    is a constant in the source, not something a flag can change.
  * The URL carries a one-time token after the '#'. Do not paste that URL
    to anyone and do not put it in a bug report -- whoever holds it can
    encrypt and decrypt files on this machine as you.
  * The token is minted at startup and dies with this command: qvault never
    writes it to a file, a cookie or browser storage, and stopping this
    command (Ctrl-C, SIGTERM, or closing the terminal) retires it for good.
  * It is not hidden from this machine, though: it is printed here, so it is
    in your scrollback and in whatever you piped stdout into, and opening the
    browser passes the URL to that program on its command line, where ps can
    see it. Processes running as you are outside the threat model; use
    --no-browser if you would rather hand the URL over yourself."""

#: 合法埠號範圍。`0` = 由 OS 配一個空埠(決策 4 的預設)。
MIN_PORT = 0
MAX_PORT = 65535

#: 退出時最多等在途的 `/api/*` 工作多久(#24 QA F1)。決策 12 給的預算是
#: 「5 秒內結束」,這裡 3.0 + 下面的 0.5 把最壞情況留在 3.5 秒上下。
UI_DRAIN_SECONDS = 3.0

#: 退出時最多等「開瀏覽器」那條執行緒多久(#24 QA F3)。它是 daemon,等不到
#: 也不擋行程結束;等這 0.5 秒只是為了「Ctrl-C 來得很快」時瀏覽器仍開得成。
UI_BROWSER_SECONDS = 0.5

#: 「使用者說停」的信號。`SIGINT` 不在表裡——標準庫預設就把它變成
#: `KeyboardInterrupt`,那正是我們要的。`SIGHUP`(終端關掉)在 Windows 上不存在,
#: 故用 `getattr` 取:決策 12 只點名 Ctrl-C 與 `SIGTERM`,但說明與 README 都寫
#: 「關掉終端即失效」,而預設處置下關終端是**被殺**(exit −1),在途的解密會
#: 留下明文片段——要讓那句話是真的,`SIGHUP` 就得走同一條乾淨退出。
_STOP_SIGNALS = tuple(
    sig
    for sig in (getattr(signal, name, None) for name in ("SIGTERM", "SIGHUP"))
    if sig is not None
)

#: 「這個信號的 handler 根本沒裝上」——與 `signal.signal` 回傳的 `None`
#: (前一個 handler 不是從 Python 裝的)不是同一件事,故不能共用 `None`。
_NOT_INSTALLED = object()


class _Stopped(Exception):
    """收到 `SIGTERM` / `SIGHUP`。只用來把控制流從 `serve_forever` 裡拉出來。"""


def _stop_on_signal(signum: object, frame: object) -> None:
    """停止信號 → 丟 `_Stopped`,從它打斷的那個呼叫裡冒出來。

    **不**在 signal handler 裡呼叫 `server.shutdown()`:handler 跑在主執行緒上,
    而 `shutdown()` 會等主執行緒的 `serve_forever` 迴圈回應它——那是一個必死的
    死鎖。拋例外是標準庫對 `SIGINT` 的做法(`KeyboardInterrupt`),這裡照抄,
    好讓它們收在同一個 `except` 裡(決策 12 要每一種都 exit 0)。
    """
    raise _Stopped


@contextlib.contextmanager
def _signals_as_exit():
    """在這個區塊內把停止信號變成例外,離開時**還原**原本的處置。

    還原不是潔癖:`cli.main` 是一個函式庫呼叫端也會用的進入點(測試就是這麼
    用的),把行程的信號處置永久改掉是副作用,不是功能。

    兩種「沒有原 handler 可還原」要分開(#24 QA 的 info):
    - `signal.signal` 丟 `ValueError` = 這裡不是主執行緒,**根本沒裝上**,
      離開時什麼都不要做(照樣服務,只是少了這條捷徑)。
    - 回傳 `None` = 裝上了,但前一個 handler 不是從 Python 裝的,**拿不回來**
      (`signal.signal(sig, None)` 會丟 `TypeError`)。這時還原成 `SIG_DFL`:
      留著我們的 handler 更糟——行程之後每次收到這個信號,都會從一個早就結束
      的 `ui` 裡丟出 `_Stopped`。
    """
    previous: dict[object, object] = {}
    for sig in _STOP_SIGNALS:
        try:
            previous[sig] = signal.signal(sig, _stop_on_signal)
        except ValueError:
            previous[sig] = _NOT_INSTALLED
    try:
        yield
    finally:
        for sig, handler in previous.items():
            if handler is _NOT_INSTALLED:
                continue
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)


def _open_browser(url: str) -> None:
    """開瀏覽器。**在背景執行緒裡跑**(#24 QA F3)。

    `webbrowser.open` 會不會回來,取決於使用者的 `BROWSER`:指到 `lynx` / `w3m`
    或任何 wrapper script 時,標準庫走 `GenericBrowser.open` → `Popen(...).wait()`,
    也就是**瀏覽器關掉之前不回來**。在主執行緒上呼叫它,`serve_forever` 就永遠
    輪不到——使用者看到的是一個印了網址卻完全不回應的伺服器(QA 實測:
    `/api/inspect` 逾時),而且信號也還沒裝,`SIGTERM` 當場把行程殺掉(F2)。

    例外一律吞掉:開不開得了瀏覽器不影響服務,而從執行緒冒出來的例外會讓
    `threading` 把一整段 traceback 印到 stderr(決策 12:不吐 traceback)。
    """
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 —— 見 docstring:執行緒裡的例外 = stderr 上的 traceback
        pass


def _serve(args: argparse.Namespace) -> int:
    """`ui` 的本體:綁 socket、印網址、開瀏覽器、服務、收乾淨。

    順序有意義:

    1. **綁 socket**(`make_server`)——先綁才知道 `--port 0` 配到哪個埠,也才
       能在埠被占的時候**什麼都還沒印**就乾淨地失敗。
    2. **印那一行**,並立刻 `flush`。
    3. **開瀏覽器**(除非 `--no-browser`),在一條 daemon 執行緒上。此時 socket
       已經在 listen,故瀏覽器比 `serve_forever` 早到也只是排在 backlog 裡。
    4. **服務**到使用者說停(信號由呼叫端的 `_signals_as_exit` 翻成例外)。
    5. **收乾淨**:關 listen socket → 等在途的 `/api/*` 工作(有界)→ 等開瀏覽器
       那條執行緒(有界)。
    """
    try:
        server = make_server(args.port)
    except OSError as exc:
        # 埠被占(`EADDRINUSE`)走這裡:一行、非零 exit、零 traceback。
        # 訊息的後半取 `errors.classify`(**不**自己編 `OSError` 的措辭,
        # 那是 `errors` 的事);前半補上「是哪個位址綁不起來」,因為
        # `Address already in use` 單獨一句看不出是誰占了什麼。
        raise _CleanExit(f"cannot serve on {LOOPBACK}:{args.port}: {classify(exc)[1]}") from None

    browser: threading.Thread | None = None
    try:
        url = server.url
        # `flush=True` 是必要的:stdout 接管線時是區塊緩衝,不 flush 的話這一行
        # 會被壓到行程結束才吐——而讀它的人(使用者、`Popen(stdout=PIPE)` 的
        # 測試)要在伺服器**還活著**的時候就拿到它。
        print(url, flush=True)
        if not args.no_browser:
            browser = threading.Thread(target=_open_browser, args=(url,), daemon=True)
            browser.start()
        server.serve_forever()
    finally:
        # listen socket 一定要關:`ui` 可能是一個跑很久的行程,而 `server_close`
        # 沒跑過的話那個埠會留在 OS 手上。先關它才等在途工作——關掉之後不再有
        # 新連線進來,等待才會收斂。
        server.server_close()
        if not server.wait_until_idle(UI_DRAIN_SECONDS):
            # 放棄等待要**說出來**:`vault` 寫到一半的 `.qvault-*.part` 是明文
            # 片段(0600、在 out_dir 裡),使用者有權知道該去看一眼。
            _report(
                f"gave up after {UI_DRAIN_SECONDS:g}s waiting for a request still "
                "running; a partial .qvault-*.part file may be left in its output "
                "directory"
            )
        if browser is not None:
            browser.join(timeout=UI_BROWSER_SECONDS)
    return EXIT_OK


def _cmd_ui(args: argparse.Namespace) -> int:
    """`ui [--port N] [--no-browser]`:起伺服器、印網址、開瀏覽器、乾淨退出。

    這個函式只做一件事:**把整個 `ui` 的生命週期包在信號處置裡**。

    包住整個本體(不只 `serve_forever`)是 #24 QA 第 2 輪 F2 的修正:原本的
    handler 在印網址、開瀏覽器**之後**才裝 `SIGTERM`,而 `webbrowser.open` 可能
    一走就不回來(見 `_open_browser`)。那段空窗期裡 `SIGTERM` 走預設處置 →
    行程 `-15`;`SIGINT` 則冒到 `main()` 的共用出口 → `qvault: interrupted` + 130。
    QA 實測兩者皆違反「`returncode == 0`」。

    Ctrl-C 與停止信號都是「使用者說停」,不是錯誤:**在這裡**接掉並回
    `EXIT_OK`,不落到 `main()` 的共用 `except KeyboardInterrupt`(那條印
    `qvault: interrupted` 並回 130,是 `getpass` 提示下被打斷的語意,且已被
    `tests/test_cli.py` 凍住)。`_CleanExit`(埠被占、埠超範圍)照常往上冒。

    乾淨退出不印任何告別詞:stdout 的那一行是給管線讀的,多一行就多一個要解析
    的東西(決策 12 只要 exit 0 + 不吐 traceback)。唯一的例外是上面那句「放棄
    等待在途工作」的警告——它報的是磁碟上可能多了一個明文片段。
    """
    if not MIN_PORT <= args.port <= MAX_PORT:
        # argparse 的 `type=int` 只保證是整數;範圍在這裡擋,否則 `bind` 會丟
        # `OverflowError`(不是 `OSError`),使用者拿到的是「internal error」。
        raise _CleanExit(f"--port must be {MIN_PORT}-{MAX_PORT}, got {args.port}")

    with _signals_as_exit():
        try:
            return _serve(args)
        except (KeyboardInterrupt, _Stopped):
            return EXIT_OK


# ---------------------------------------------------------------- 參數解析


def _build_parser() -> argparse.ArgumentParser:
    """argparse 的三個子命令。

    **這裡沒有任何收密碼的選項,而且不可以有**:密碼只能走 `getpass`。
    `tests/test_cli.py::test_no_option_anywhere_takes_a_passphrase` 掃過所有
    子解析器的所有選項字串,擋住「加個 `--password` 比較好測」這種手滑。
    """
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="QVault — post-quantum-ready local file vault (.qvt).",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"{PROG} {__version__}"
    )
    subs = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    enc = subs.add_parser("encrypt", help=f"encrypt FILE into FILE{QVT_SUFFIX}")
    enc.add_argument("file", metavar="FILE", help="file to encrypt")
    enc.add_argument(
        "--force",
        action="store_true",
        help=f"overwrite an existing FILE{QVT_SUFFIX}",
    )
    enc.set_defaults(handler=_cmd_encrypt)

    dec = subs.add_parser("decrypt", help="restore the original file from a .qvt")
    dec.add_argument("file", metavar="FILE", help=f"{QVT_SUFFIX} container to restore")
    dec.add_argument(
        "--out-dir",
        default=".",
        metavar="DIR",
        help="directory to restore into (default: current directory)",
    )
    dec.add_argument(
        "--force", action="store_true", help="overwrite an existing target file"
    )
    dec.set_defaults(handler=_cmd_decrypt)

    ins = subs.add_parser("inspect", help="print header fields and algorithms")
    ins.add_argument("file", metavar="FILE", help=f"{QVT_SUFFIX} container to inspect")
    ins.set_defaults(handler=_cmd_inspect)

    # `ui`:**沒有** `--host` / `--bind`(決策 4——「不能改綁定位址」要在
    # 型別層面成立);也沒有任何收密碼的選項(密碼走網頁表單的 POST body)。
    ui = subs.add_parser(
        "ui",
        help="serve the local web UI in a browser (127.0.0.1 only)",
        description=UI_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ui.add_argument(
        "--port",
        type=int,
        default=0,
        metavar="N",
        help="port to serve on (default: 0 = let the OS pick a free one)",
    )
    ui.add_argument(
        "--no-browser",
        action="store_true",
        help="only print the URL, do not open a browser",
    )
    ui.set_defaults(handler=_cmd_ui)

    return parser


def _report(message: str) -> None:
    """所有錯誤的唯一出口:一行、到 stderr、帶 `qvault: ` 前綴、零 traceback。"""
    print(f"{PROG}: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """進入點(`[project.scripts] qvault = "qvault_core.cli:main"`)。

    回傳 exit code,**不呼叫 `sys.exit`**:console script 的 wrapper 會
    `sys.exit(main())`,而測試可以直接拿回傳值斷言。argparse 自己的用法錯誤仍走
    它的 `SystemExit(2)`(它已經印過一行乾淨的 usage,不需要本層再包一次)。

    例外的收斂(分類交 `errors.classify`;`.asp/pr/4.md` 已替 CLI 分好四類):

    - `_CleanExit` = 本層自己判定的使用錯誤(訊息取自 `errors` 的 `MSG_*` 常數)。
    - 其餘一律交給 `errors.classify`,它回 `(kind, message)`:
      - `QVaultError`(Decrypt/Format/Version)= 密碼錯、被竄改、或檔案不是 `.qvt`。
        **訊息直接轉述**,一個字都不加(保證③:錯密碼與竄改不可區分)。
      - `OSError` 家族 = 用法/環境問題(缺檔、目標已存在、目錄不對、權限)。
      - 其餘 = 我們的 bug。仍然**不吐 traceback**(frame 裡有密碼與 DEK),
        只印型別名;要看 traceback 請直接呼叫函式庫。

    分類與訊息都**不在本層現編**(#22 的主管層裁定):同一個例外在本層與另一個
    呼叫端必須說同一句話,而「兩本帳」是靠人去對帳的,對帳總有一天會漏。
    本層只決定**怎麼表達**(一行 `qvault: …` + exit code),不決定分類。
    """
    args = _build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except _CleanExit as exc:
        _report(str(exc))
        return exc.code
    except KeyboardInterrupt:
        # `BaseException`,故與下面那條 `except Exception` 不重疊;順序無關。
        _report("interrupted")
        return EXIT_INTERRUPT
    except Exception as exc:  # noqa: BLE001 —— 見 docstring:永不 traceback
        kind, message = classify(exc)
        # `classify` 對未預期例外只回型別名(永不 `str(exc)`:frame 與訊息裡
        # 躺著密碼與 DEK)。本層把它包成 `internal error (...)`,好讓使用者分得出
        # 「你的檔案有問題」與「我們有 bug」;`QVaultError` / `OSError` 則**逐字**
        # 轉述,一個字都不加(保證③)。
        _report(f"internal error ({message})" if kind == "unexpected" else message)
        return EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover —— `python -m qvault_core.cli`
    sys.exit(main())
