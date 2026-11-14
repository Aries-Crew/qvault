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
- **「怎麼把網址交給瀏覽器」是本層的事**(#36,決策 12 修訂):那一步發生在
  `webbrowser.open` 的呼叫點,而呼叫點在這裡。自 #36 起交出去的是一個只有啟動者
  讀得到的 `file://` 跳轉檔,不是那條帶 token 的網址——見 `UI_REDIRECT_HTML` 與
  `_write_redirect_file`。這一頁**不是** `webui.py` 服務的那三份靜態內容,故決策
  10 的 CSP 與「前端零 inline script」與它無關。
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import signal
import stat
import sys
import tempfile
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
#: 導向的那個檔案裡)。第四點的末句另經複審 L1 修過:原本寫「同使用者的其他
#: 行程本來就在威脅模型之外」,讀起來像「只有同使用者看得到」,而 Linux 預設
#: 沒有 `hidepid`,`/proc/<pid>/cmdline` **同機任何使用者**都讀得到。
#:
#: #36(使用者 2026-11-10 裁定)把那兩句話的**事實**也改掉了:網址不再進瀏覽器
#: 的命令列(改走跳轉檔),所以第四點從「`ps` 看得到」變成「`ps` 看不到,而那
#: 正是這件事存在的理由」;token 現在**有**一個落地的地方(那個跳轉檔),故
#: 「qvault never writes it to a file」那句整句拿掉——它已經不是真的,而這份
#: 說明的用途正是讓使用者據以決定要不要在共用主機上跑這個命令。
#:
#: 「什麼時候會留下殘留」那一句另經合併前複審(S1)校過:原文寫「除了 kill -9,
#: 任何停法都會刪檔」,而 `_STOP_SIGNALS` 只有 `SIGTERM` / `SIGHUP`——`SIGQUIT`
#: (Ctrl-\)、`SIGUSR1/2`、行程崩潰都走預設處置,一樣清不了。說法因此改成
#: 「攔不住或我們沒處理的致死信號會留下」。
UI_DESCRIPTION = """Serve the local web UI, print its URL, and open it in a browser.

Five things worth knowing before you use it:

  * It binds 127.0.0.1 only. There is no --host and no --bind: the address
    is a constant in the source, not something a flag can change.
  * The URL carries a one-time token after the '#'. Do not paste that URL
    to anyone and do not put it in a bug report -- whoever holds it can
    encrypt and decrypt files on this machine as you.
  * The token is minted at startup and dies with this command: it never goes
    into a cookie or into browser storage, and stopping this command (Ctrl-C,
    SIGTERM, or closing the terminal) retires it for good.
  * It is not passed to the browser on a command line, where ps can read it
    -- and on a stock Linux (no hidepid) that process list is readable by
    other users on this machine, not only by processes running as you. What
    the browser is given instead is a local redirect page that only you can
    read: a 0600 file in a 0700 private directory, holding one line of script
    that jumps to the URL above. It is deleted when this command stops the
    ways it knows how to stop: Ctrl-C, SIGTERM, SIGHUP, or an error. A signal
    it cannot catch or does not handle (kill -9, SIGQUIT from Ctrl-\\, a
    crash) leaves the file behind; a leftover is still readable only by you.
  * It is not hidden from this machine, though: it is printed here, so it is
    in your scrollback and in whatever you piped stdout into. Use
    --no-browser if you would rather hand the URL over yourself:
    then no redirect page is written at all."""

#: 合法埠號範圍。`0` = 由 OS 配一個空埠(決策 4 的預設)。
MIN_PORT = 0
MAX_PORT = 65535

#: 退出時最多等在途的 `/api/*` 工作多久(#24 QA F1)。決策 12 給的預算是
#: 「5 秒內結束」,這裡 3.0 + 下面的 0.5 把最壞情況留在 3.5 秒上下。
UI_DRAIN_SECONDS = 3.0

#: 兩句「沒等完就退出」的警告共用的尾句。只說檔名長什麼樣子、不說哪個目錄:
#: `out_dir` 來自請求 body,而決策 9 是「伺服器不記 body」——為了這句警告把
#: 使用者的路徑寫到 stderr 等於在那條決策上開一個洞。
_PART_FILE_WARNING = (
    "; a partial .qvault-*.part file may be left in its output directory"
)

#: 退出時最多等「開瀏覽器」那條執行緒多久(#24 QA F3)。它是 daemon,等不到
#: 也不擋行程結束;等這 0.5 秒只是為了「Ctrl-C 來得很快」時瀏覽器仍開得成。
UI_BROWSER_SECONDS = 0.5

#: 跳轉檔住的那個私有目錄的名字前綴(`mkdtemp` 會在後面接一串隨機字元)。
#: 看得出是誰留下來的:攔不住的致死信號(`kill -9` 等)之後,使用者才找得到那個
#: 殘留(ADR-002「不防」)。
UI_REDIRECT_PREFIX = "qvault-ui-"

#: 跳轉檔的檔名。它住在一個**現開的**私有目錄裡,所以不必唯一化,也不會撞到
#: 任何既有的檔案(`O_EXCL` 另外把這件事釘死)。
UI_REDIRECT_NAME = "open.html"

#: 跳轉檔的權限:只有啟動者讀得到。目錄的 0700 由 `mkdtemp` 要求,檔案的 0600 由
#: `os.open` 的 mode 要求——**不是**先建檔再 `chmod`:那兩步之間檔案的權限由
#: umask 決定,而 umask 是使用者環境裡的變數,不是我們的保證。
#:
#: 「要求」不等於「拿到」:這兩個數字**都**會被 umask 遮掉(實測 CPython 3.12:
#: `umask 0177` 下 `mkdtemp` 給的是 0600——少了 `x`,連啟動者自己都進不去那個
#: 目錄;`umask 0400` 下檔案是 0200,寫得進去但讀不回來)。那一形不是「安全性
#: 少一點」,而是**整個機制默默失效**:瀏覽器打不開那個檔案,使用者只看到一個
#: 開了卻空白的視窗,而 token 已經落地。故兩者都在建立之後**量一次**
#: (`_require_private_mode`),不符就一行乾淨錯誤 + 非零 exit、不留檔。
UI_REDIRECT_DIR_MODE = 0o700
UI_REDIRECT_FILE_MODE = 0o600

#: 「量權限位元」這件事只在 POSIX 上有意義。Windows 的 `os.open` mode 只認唯讀
#: 位元、`mkdtemp` 建出來的目錄回報 `0o777`,那裡的私有性來自 per-user 的
#: `%TEMP%` 與目錄 ACL——在那邊拿 0700 / 0600 去比,會把**每一次** `qvault ui`
#: 都判成失敗。故量測在那裡跳過,而本檔對權限的承諾(`--help`、README)講的也
#: 一直是 POSIX 的那個模型(`ps`、`hidepid`)。
_MODES_ARE_MEANINGFUL = os.name == "posix"

#: 跳轉檔的內容(`{url}` 由 `json.dumps` 算出來,**含**那對引號)。
#:
#: 為什麼是一個檔案而不是直接把網址交給瀏覽器(#36,使用者 2026-11-10 裁定):
#: `webbrowser.open(url)` 在瀏覽器還沒開的時候走 `xdg-open <url>` /
#: `firefox <url>`,於是那條**帶 token 的網址**在那支程式的整個生命期裡躺在
#: `/proc/<pid>/cmdline` 裡;預設沒有 `hidepid` 的 Linux 上,同機的其他使用者
#: `ps aux` 就拿得到,接著能以啟動者的身分讀寫本機檔案(ADR-002 決策 2 的路徑
#: 模式)。改開一個只有啟動者讀得到的跳轉檔,交給瀏覽器的命令列就只有一條
#: `file://` 網址——比照 Jupyter 的做法。
#:
#: 三件事是刻意的:
#:
#: - **`location.replace` 而不是 `<meta http-equiv="refresh">`**:`replace` 不留
#:   歷史記錄(按上一頁不會回到這個檔案),而 `meta refresh` 會。兩者都保留
#:   fragment,但只有前者在跳過去之後「這一頁從來沒存在過」。
#: - **零外部資源、零 `src`/`href`**:這一頁只有一行 script 與一句 `noscript`
#:   文字。它走 `file://`、不經伺服器,故 ADR-002 決策 10 的 CSP 管不到它——
#:   那條 CSP 與「前端沒有 inline script」是對**伺服器服務的那三份內容**說的
#:   (`tests/test_webui_page.py` 掃的也正是 `webui.PAGE_HTML`);這個檔案不是
#:   那三份裡的任何一份。`no-referrer` 那行 `<meta>` 則是為了連「從哪個
#:   `file://` 路徑跳過來的」都不要進 `Referer`。
#: - **`noscript` 不重印那條網址**:它只叫使用者回終端去拿。重印一次不會更安全
#:   (同一個檔案裡已經有了),但會讓「token 只寫在這一個地方」這句話更難驗。
UI_REDIRECT_HTML = """<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>qvault</title>
<script>location.replace({url})</script>
<noscript>This page needs JavaScript to hand you over to qvault. Paste the URL
that qvault printed in your terminal into the address bar instead.</noscript>
</html>
"""

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


class _Stopped(BaseException):
    """收到 `SIGTERM` / `SIGHUP`。只用來把控制流從 `serve_forever` 裡拉出來。

    **繼承 `BaseException` 而不是 `Exception`,而且不可以改回去**(複審第 2 輪
    F-B)。標準庫 `socketserver._handle_request_noblock` 在 `process_request`
    外面包著:

        except Exception:  self.handle_error(...); self.shutdown_request(...)
        except:            self.shutdown_request(...); raise

    而 `ThreadingMixIn.process_request` 的 `t.start()` 會等新執行緒真的起來
    ——那是一個跑在**主執行緒**上、機器越忙越寬的窗口。信號落在那裡時,
    `Exception` 版的 `_Stopped` 會被上面第一條 `except` 吞掉(`webui` 的
    `handle_error` 刻意不出聲),只有那條連線被關、`serve_forever` 照跑:
    `SIGTERM` 下 AC 第 3 條的「5 秒內結束」不成立,`SIGHUP` 下**關掉終端後
    行程仍在、token 仍有效**,而 `--help` 與 README 都寫「關掉終端即失效」。
    `BaseException` 走第二條 `except`(關連線後 `raise`),於是信號照樣把控制流
    帶出 `serve_forever`。

    這與 `KeyboardInterrupt`(也是 `BaseException`)的待遇一致——標準庫對
    Ctrl-C 的設計正是「不要被攔路的 `except Exception` 吃掉」,而 `SIGINT` 也
    因此從來沒有這個毛病。代價是 `main()` 的 `except Exception` 碰不到它:
    `_cmd_ui` **明確**接 `(KeyboardInterrupt, _Stopped)`,而裝上這個 handler
    的 `_signals_as_exit` 整段都在那個 `try` 裡面(見 `_cmd_ui`),所以沒有
    「冒到頂變成 traceback」的路。
    """


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


@contextlib.contextmanager
def _signals_deferred():
    """在這個區塊內把停止信號(**含 `SIGINT`**)降級成「什麼都不做」,離開時還原。

    給**退出序列**用(複審 M1)。那段路徑上有兩個有界的等待
    (`wait_until_idle`、`Thread.join`),而它們底下是 `Event.wait` / lock
    acquire——POSIX 上信號會打斷那個系統呼叫,PEP 475 之後標準庫會重試,
    **除非** handler 拋例外。而我們這一側兩個 handler 都拋:標準庫的
    `SIGINT` → `KeyboardInterrupt`、我們的 `_stop_on_signal` → `_Stopped`。
    於是「等在途工作的時候再按一次 Ctrl-C」會讓例外從 `_serve` 的 `finally`
    裡冒出去、被 `_cmd_ui` 接住回 `EXIT_OK`:等待被丟掉、警告沒印、daemon 的
    連線執行緒被直譯器結束時砍掉,`.qvault-*.part` **明文片段**留在 out_dir
    ——正是那段等待存在的理由。退出時最多會不出聲地等 3.5 秒,那段時間再按
    一次 Ctrl-C 很自然,所以這不是一個理論上的窗口。

    降級而不是 `SIG_IGN`:`SIG_IGN` 是行程層的處置,離開這個區塊之後要還原成
    「Python 的那個 handler」就得重新裝一次,而中間收到的信號會被**真的**丟掉
    (`SIG_IGN` 連 pending 都不留)。裝一個 Python 函式則讓位元還在、只是我們
    不理它。

    **有界**:這個區塊裡的每一個等待都有逾時,故「不理信號」最多持續
    `UI_DRAIN_SECONDS + UI_BROWSER_SECONDS` ≈ 3.5 秒(< 決策 12 的 5 秒),
    之後就算沒等到也會往下走。這裡不是一個會吞掉 Ctrl-C 的無限迴圈。

    還原的兩種「沒有原 handler」與 `_signals_as_exit` 同一套規矩(見那裡)。
    """

    def ignore(signum: object, frame: object) -> None:
        """收下但不做事:讓 PEP 475 的重試邏輯把等待接回去。"""

    previous: dict[object, object] = {}
    for sig in (signal.SIGINT, *_STOP_SIGNALS):
        try:
            previous[sig] = signal.signal(sig, ignore)
        except ValueError:
            previous[sig] = _NOT_INSTALLED
    try:
        yield
    finally:
        for sig, handler in previous.items():
            if handler is _NOT_INSTALLED:
                continue
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)


def _require_private_mode(path: Path, st_mode: int, required: int) -> None:
    """量到的權限不是我們承諾的那一個 → `_CleanExit`(一行、非零 exit、不留檔)。

    為什麼要量而不是信:`mkdtemp` 的 0700 與 `os.open` 的 0600 都是**要求**,
    而 umask 會遮掉它們(見 `UI_REDIRECT_DIR_MODE` 那段實測)。`--help` 與
    README 對使用者承諾的正是這兩個數字,所以它們要嘛成立、要嘛這個命令拒絕
    跑——**不猜、不補**:事後 `chmod` 回去等於把使用者 umask 的意思推翻,而
    「少給一點權限也沒關係」在這裡是假的(0600 少掉 `r` 就打不開那一頁)。

    停下來的代價是 `ui` 整個失敗(訊息點名 `--no-browser`,那條路徑一個檔案都
    不寫),換到的是「跳轉檔只有啟動者讀得到」這句話在 POSIX 上沒有例外。
    POSIX 之外不量(見 `_MODES_ARE_MEANINGFUL`);POSIX 之內,mode 不被尊重的
    檔案系統(vfat / exfat / 某些網路掛載)走的也是這條拒絕——在那裡我們**真的**
    做不到那個承諾。
    """
    if not _MODES_ARE_MEANINGFUL:
        return
    actual = stat.S_IMODE(st_mode)
    if actual != required:
        raise _CleanExit(
            f"refusing to open a browser: {path} came out {actual:04o}, not {required:04o} "
            f"(umask or the filesystem is in the way); use --no-browser"
        )


def _write_redirect_file(url: str) -> Path:
    """把 `url` 包成一頁跳轉 HTML 寫出去,回傳那個檔案的路徑。

    檔案住在 `tempfile.mkdtemp()` 現開的私有目錄裡(0700),本身 0600:交給
    瀏覽器的是它的 `file://` 網址,於是 token 不進任何程序的命令列(#36;
    內容與理由見 `UI_REDIRECT_HTML`)。那兩個權限是**量過**的,不是信的
    (`_require_private_mode`;量不到就拒絕,連一個帶 token 的 byte 都不落地)。

    **呼叫端負責刪它**(見 `_serve` 的退出序列)。這個函式只保證一件事:它
    自己失敗的時候不留東西——`mkdtemp` 成功之後任何一步出錯(含 Ctrl-C 正好
    落在寫檔那一刻),目錄與半成品檔案都在往上拋之前先收掉。故接的是
    `BaseException` 而不是 `Exception`:這裡漏掉的不是一個暫存檔,是一個
    **帶著 token** 的暫存檔。
    """
    directory = Path(tempfile.mkdtemp(prefix=UI_REDIRECT_PREFIX))
    path = directory / UI_REDIRECT_NAME
    try:
        # 目錄的權限先量:`mkdtemp` 要的是 0700,但 umask 遮得到它(見
        # `UI_REDIRECT_DIR_MODE`)。量在寫檔**之前**,故這一形連一個帶 token
        # 的 byte 都沒落地。
        _require_private_mode(directory, os.stat(directory).st_mode, UI_REDIRECT_DIR_MODE)
        # `O_EXCL` + mode:檔案從**存在的第一刻**就是 0600,中間沒有一個
        # umask 說話的窗口,也沒有「跟著某個既有檔案的權限走」的可能,而
        # `O_EXCL` 連「那個名字已經被人預先放了一個 symlink」都擋掉。
        # **不可以**改寫成「`open()` 建檔 + `chmod` 補權限」:那會把這兩件事
        # 都換成一個窗口(`tests/test_cli_ui.py` 以 spy 記下 flags 與 mode,
        # 並禁止本模組出現任何 `chmod`)。
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, UI_REDIRECT_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            # 檔案的權限量在**已開好的 fd** 上(`os.fstat`,不是 `os.stat(path)`):
            # 量的保證跟著我們手上這個 fd,不跟著那個名字。
            _require_private_mode(
                path, os.fstat(handle.fileno()).st_mode, UI_REDIRECT_FILE_MODE
            )
            # `json.dumps` 算的是一個 **JS 字串字面值**(含引號與必要的跳脫)。
            # 網址這一條全由我們自己組(`LOOPBACK` 是常數、埠是 int、token 是
            # `token_urlsafe` 的 base64url),所以今天沒有可注入的字元;用
            # `json.dumps` 是為了讓這句話明天還成立——手寫 `"{url}"` 的話,
            # 哪天網址裡多一個引號或反斜線,這一頁就是一段壞掉的 script。
            handle.write(UI_REDIRECT_HTML.format(url=json.dumps(url)))
    except BaseException:
        _discard_redirect(path)
        raise
    return path


def _discard_redirect(path: Path | None) -> None:
    """刪掉跳轉檔與它那個私有目錄。`None`(沒開瀏覽器)與「已經不在了」都是 no-op。

    **不出聲、不拋例外**:它跑在退出序列的 `finally` 裡,而那條路徑上還有一句
    「可能留下明文片段」的警告要印(見 `_serve`)。這裡拋出去的話,使用者會為了
    一個暫存檔少看到那句話。

    先刪檔再刪目錄,順序有意義:帶著 token 的是**檔案**。目錄刪不掉(理論上:
    有人在裡面放了別的東西)只是留一個空目錄,而那裡面已經沒有 token 了。
    """
    if path is None:
        return
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        path.parent.rmdir()


def _open_browser(url: str) -> None:
    """開瀏覽器。**在背景執行緒裡跑**(#24 QA F3)。

    `url` 自 #36 起是**跳轉檔**的 `file://` 網址,不是那條帶 token 的網址
    ——這個函式本身不在乎是哪一條,但它是「交給瀏覽器的命令列」那一步,
    故這裡是整個 token 暴露面的收口處(見 `_write_redirect_file`)。

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
    3. **寫跳轉檔**(除非 `--no-browser`)。在綁 socket **之後**:埠被占的時候
       `make_server` 已經把我們從上面那條 `raise` 帶走了,於是磁碟上一個字都
       沒留下(#36 AC-3 的後半)。
    4. **開瀏覽器**(除非 `--no-browser`),在一條 daemon 執行緒上,交給它的是
       跳轉檔的 `file://` 網址。此時 socket 已經在 listen,故瀏覽器比
       `serve_forever` 早到也只是排在 backlog 裡。
    5. **服務**到使用者說停(信號由呼叫端的 `_signals_as_exit` 翻成例外)。
    6. **收乾淨**:宣布停止受理新工作(之後進來的 `/api/*` 拿 `503`)→ 關 listen
       socket → 等在途的 `/api/*` 工作(有界)→ 等開瀏覽器那條執行緒(有界)
       → **刪跳轉檔與它的目錄**。這一整段跑在 `_signals_deferred()` 裡:再一次
       的 Ctrl-C 不會把等待丟掉(複審 M1),也搶不走那一步刪除(#36 AC-3)。
       「沒等完就退出」的那句警告與那一步刪除都由**兩層** `try/finally` 夾著,
       連「`_signals_deferred` 還沒裝好就收到信號」那一格都做得到(#40 AC-2)。
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
    #: 跳轉檔(`--no-browser` 時一直是 `None`——AC-4:那一條路徑一個檔案都不寫)。
    #: 在 `try` **之前**宣告:下面的 `finally` 一定要看得到它,而「寫到一半被
    #: 打斷」那一形由 `_write_redirect_file` 自己收(見那裡)。
    redirect: Path | None = None
    try:
        url = server.url
        # `flush=True` 是必要的:stdout 接管線時是區塊緩衝,不 flush 的話這一行
        # 會被壓到行程結束才吐——而讀它的人(使用者、`Popen(stdout=PIPE)` 的
        # 測試)要在伺服器**還活著**的時候就拿到它。
        print(url, flush=True)
        if not args.no_browser:
            # 交給瀏覽器的是跳轉檔,**不是**這條網址(#36,使用者 2026-11-10
            # 裁定):`xdg-open <url>` / `firefox <url>` 的 argv 在那支程式的整個
            # 生命期裡躺在 `/proc/<pid>/cmdline`,而預設沒有 `hidepid` 的 Linux
            # 上同機其他使用者 `ps aux` 就讀得到。
            redirect = _write_redirect_file(url)
            opener = threading.Thread(
                target=_open_browser, args=(redirect.as_uri(),), daemon=True
            )
            opener.start()
            # **先 start 再記下來**,順序不能反:Ctrl-C 可能正好落在
            # `Thread.start()` 回來之前的那幾微秒,而 `Thread.join` 對一條還沒
            # start 的執行緒丟的是 `RuntimeError: cannot join thread before it is
            # started`。那個 `RuntimeError` 會從下面的 `finally` 冒出去、**取代**
            # 原本的 `KeyboardInterrupt`,於是 `main()` 把它翻成
            # `qvault: internal error (RuntimeError)` + exit 1——使用者按了 Ctrl-C,
            # 拿到的卻是「我們有 bug」。反過來寫就沒有這個窗口:`browser` 非 None
            # ⇒ 它一定 start 過。
            browser = opener
        server.serve_forever()
    finally:
        # 「沒等完就退出」要說的那句話的**預設值**:這條退出路徑還沒走完,
        # 所以悲觀地假設在途工作被丟下了。下面量到結果才把它改掉——這樣
        # 「等待被中途放棄」(例如信號在 `_signals_deferred` 裝上之前的那幾
        # 微秒就到了)也一定會印出警告,而不是靜靜地留下一個明文片段。
        warning: str | None = (
            f"stopped waiting for a request still running{_PART_FILE_WARNING}"
        )
        # 那句話說了沒有(#40 AC-2)。**兩層** `try/finally` 都可能是印它的人:
        # 區塊**內**那個印正常路徑(處置還沒還原,信號吃不掉這次 I/O——複審
        # 第 2 輪的 info 要的就是這個);區塊**外**這個補 `_signals_deferred()`
        # 的 `__enter__` 自己被信號打斷的那一格:它在裝處置的時候裝著的還是會
        # 拋例外的 handler,信號落在那裡例外就從 `with` 那一行冒出去,body 一次
        # 都沒跑、區塊內的 `finally` 也就沒跑。那一格在 PR #35 把 `_report` 搬
        # 進區塊內時變成**靜音**(退步),這一層把它補回來。
        #
        # #36 的「刪跳轉檔」跟著同一個理由走兩層(本次 base 合併的交點):
        # 那一格裡磁碟上還有一個帶 token 的檔案,而區塊內的 `finally` 沒跑。
        reported = False
        try:
            # 整段退出序列對停止信號免疫(複審 M1):否則在途工作等到一半時的第二個
            # Ctrl-C / SIGTERM 會把下面的等待整個丟掉。見 `_signals_deferred`。
            with _signals_deferred():
                try:
                    # 先宣布停止受理:`serve_forever` 回來之後不再有新**連線**,
                    # 但 keep-alive 的既有連線還送得進新的 `/api/*`(`server_close`
                    # 關的是 listen socket,不是已建立的連線)。不宣布的話,下面
                    # 等的那個集合會在等待期間長大,或者在等完之後才長出一份
                    # 沒有人等的寫檔工作。
                    server.stop_accepting_work()
                    # listen socket 一定要關:`ui` 可能是一個跑很久的行程,而
                    # `server_close` 沒跑過的話那個埠會留在 OS 手上。
                    server.server_close()
                    if server.wait_until_idle(UI_DRAIN_SECONDS):
                        warning = None      # 都做完了,沒有話要說
                    else:
                        # 放棄等待要**說出來**:`vault` 寫到一半的 `.qvault-*.part`
                        # 是明文片段(0600、在 out_dir 裡),使用者有權知道該去看
                        # 一眼。
                        warning = (
                            f"gave up after {UI_DRAIN_SECONDS:g}s waiting for a request "
                            f"still running{_PART_FILE_WARNING}"
                        )
                    if browser is not None:
                        browser.join(timeout=UI_BROWSER_SECONDS)
                finally:
                    # 跳轉檔在這裡死,而且是**無條件**地死:上面那段不管走到哪一行
                    # 出錯(或根本沒走完),帶著 token 的那個檔案都不留在磁碟上
                    # (#36 AC-3)。位置在這個 `finally` 而不是上面那個 `try` 的
                    # 尾巴,正是為了這個「不管怎麼走」;在 `_signals_deferred`
                    # 裡面則是為了第二個 Ctrl-C 搶不走它。
                    #
                    # 在 `browser.join` **之後**:`webbrowser.open` 回來只代表那支
                    # 程式被 spawn 了,不代表它已經把檔案讀完,所以能多給的那
                    # 0.5 秒都給它。這仍然不是一個保證(見 `.asp/pr/36.md` 的已知
                    # 限制),但終端上那條網址永遠是後路。
                    _discard_redirect(redirect)
                    # 旗標先立再印:`_report` 自己要是炸了,外層補印一次也沒有
                    # 意義(同一個 stderr),而重複印一行警告反而讓讀的人以為
                    # 有兩份在途工作。
                    reported = True
                    if warning is not None:
                        _report(warning)
        finally:
            if not reported and warning is not None:
                _report(warning)
            # 同一格的另一半:`_signals_deferred()` 的 `__enter__` 被信號打斷時,
            # 上面區塊內的 `finally` 一次都沒跑,而那條路徑上磁碟還留著一個帶
            # token 的跳轉檔。`_discard_redirect` 是 idempotent 的(刪過了就是
            # no-op,`test_discarding_is_a_no_op_when_there_is_nothing_to_discard`
            # 守著),所以這裡無條件再收一次:正常路徑上它什麼都不做,那一格上
            # 它是唯一的清理者。不用 `reported` 那種旗標,因為「刪兩次」沒有
            # 副作用,而那句警告「印兩次」會誤導讀的人。
            _discard_redirect(redirect)
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

    接例外的範圍是**整個** `with`(不只 `_serve`):見下面那段註解——信號落在
    還原信號處置的那一刻時,例外是從 context manager 的離開路徑冒出來的。

    乾淨退出不印任何告別詞:stdout 的那一行是給管線讀的,多一行就多一個要解析
    的東西(決策 12 只要 exit 0 + 不吐 traceback)。唯一的例外是上面那句「放棄
    等待在途工作」的警告——它報的是磁碟上可能多了一個明文片段。
    """
    if not MIN_PORT <= args.port <= MAX_PORT:
        # argparse 的 `type=int` 只保證是整數;範圍在這裡擋,否則 `bind` 會丟
        # `OverflowError`(不是 `OSError`),使用者拿到的是「internal error」。
        raise _CleanExit(f"--port must be {MIN_PORT}-{MAX_PORT}, got {args.port}")

    # `except` 包在 `with` **外面**,順序不能反:停止信號可能正好落在
    # `_signals_as_exit` **還原**處置的那幾微秒裡(退出路徑的最後一步)。那時
    # 裝著的還是會拋例外的 handler,而例外是從 context manager 的離開路徑冒
    # 出來的——寫成 `with: try: …` 的話那個 `except` 根本不在它的路徑上,於是
    # `_Stopped` 冒到 `main()` 變成 `qvault: internal error (_Stopped)` + exit 1、
    # `KeyboardInterrupt` 變成 `qvault: interrupted` + 130。兩者都違反決策 12 的
    # 「每一種停止都 exit 0」,而且使用者只是按了 Ctrl-C。
    # 同一個窗口的另一半(`Thread.start()` 回來之前)已由 `_serve` 裡「先 start
    # 再記下來」關掉;這裡關的是最後一步。
    try:
        with _signals_as_exit():
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
