"""CLI 層:`qvault encrypt / decrypt / inspect`(argparse)。

相依圖(ADR-001「模組切法」)的最外層:`cli → vault → {container, aead, kek}`。
本檔**只做四件事**——解析參數、問密碼、把例外翻成一行乾淨訊息 + 非零 exit、
把 `inspect` 的白名單欄位印出來。密碼學、格式、檔名淨化一律不在這裡發生。

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
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .container import HEADER_SIZE_KEM1, deserialize
from .errors import QVaultError
from .vault import decrypt_file, encrypt_file

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
        raise _CleanExit(
            "passphrase contains characters that cannot be encoded as UTF-8"
        ) from None


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
        raise _CleanExit("passphrase must not be empty")
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
        raise _CleanExit("passphrase must not be empty")
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
        raise _CleanExit(f"input file does not exist: {path}")
    if path.is_dir():
        raise _CleanExit(f"input is a directory, not a file: {path}")
    if not path.is_file():
        raise _CleanExit(f"input is not a regular file: {path}")


# ---------------------------------------------------------------- 子命令


def _cmd_encrypt(args: argparse.Namespace) -> int:
    """`encrypt <f>` → `<f>.qvt`(同目錄、同名加後綴)。"""
    inp = Path(args.file)
    if not inp.name:
        # `.` / `..` / `/`:`with_name` 會丟 ValueError,先擋成一句話。
        raise _CleanExit(f"input path has no file name: {inp}")
    out = inp.with_name(inp.name + QVT_SUFFIX)

    _require_file(inp)
    if out.exists() and not args.force:
        # `encrypt_file` 也會擋(它才是真正的守門人,見下方 FileExistsError),
        # 這裡先擋只是為了不讓使用者白打密碼。
        raise _CleanExit(f"refusing to overwrite existing output: {out} (use --force)")

    passphrase = _ask_new_passphrase()
    print(encrypt_file(inp, out, passphrase, force=args.force))
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """`decrypt <f.qvt> [--out-dir DIR] [--force]`;檔名由 `decrypt_file` 還原。"""
    inp = Path(args.file)
    out_dir = Path(args.out_dir)
    _require_file(inp)
    if not out_dir.is_dir():
        raise _CleanExit(f"output directory does not exist: {out_dir}")

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

    return parser


def _report(message: str) -> None:
    """所有錯誤的唯一出口:一行、到 stderr、帶 `qvault: ` 前綴、零 traceback。"""
    print(f"{PROG}: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """進入點(`[project.scripts] qvault = "qvault_core.cli:main"`)。

    回傳 exit code,**不呼叫 `sys.exit`**:console script 的 wrapper 會
    `sys.exit(main())`,而測試可以直接拿回傳值斷言。argparse 自己的用法錯誤仍走
    它的 `SystemExit(2)`(它已經印過一行乾淨的 usage,不需要本層再包一次)。

    例外的四類收斂(`.asp/pr/4.md` 已替 CLI 分好):

    - `QVaultError`(Decrypt/Format/Version)= 密碼錯、被竄改、或檔案不是 `.qvt`。
      **訊息直接轉述**,一個字都不加(保證③:錯密碼與竄改不可區分)。
    - `OSError` 家族 = 用法/環境問題(缺檔、目標已存在、目錄不對、權限)。
    - `_CleanExit` = 本層自己判定的使用錯誤。
    - 其餘 `Exception` = 我們的 bug。仍然**不吐 traceback**(frame 裡有密碼與
      DEK),只印型別名;要看 traceback 請直接呼叫函式庫。
    """
    args = _build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except _CleanExit as exc:
        _report(str(exc))
        return exc.code
    except QVaultError as exc:
        _report(str(exc))
        return EXIT_FAIL
    except OSError as exc:
        # `strerror` 存在時用「訊息: 路徑」,免得吐出 `[Errno 2] ...` 這種噪音;
        # `FileExistsError` 等由 vault 自己 raise 的沒有 errno,走 str()。
        if exc.strerror:
            path = exc.filename or ""
            _report(f"{exc.strerror}: {path}" if path else exc.strerror)
        else:
            _report(str(exc))
        return EXIT_FAIL
    except KeyboardInterrupt:
        _report("interrupted")
        return EXIT_INTERRUPT
    except Exception as exc:  # noqa: BLE001 —— 見 docstring:永不 traceback
        _report(f"internal error ({type(exc).__name__})")
        return EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover —— `python -m qvault_core.cli`
    sys.exit(main())
