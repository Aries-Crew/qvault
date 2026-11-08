"""QVault 錯誤體系(ADR-001「錯誤體系」)。

    QVaultError
      ├── QVaultFormatError   magic 錯、欄位長度不符、界限外、截斷
      ├── QVaultVersionError  未知 `.qvt` version
      └── QVaultDecryptError  AEAD tag 驗證失敗(竄改或錯金鑰,不於訊息區分)

鐵律(AGENTS.md 5 / ADR-001 決策 19):例外訊息**永不**含金鑰、密碼或明文。
本模組的訊息一律只描述「哪個欄位、期望什麼」,不回填使用者資料。

本模組另外是**錯誤分類的單一事實源**(ADR-002 決策 8;#22 的主管層裁定):
`classify(exc) -> (kind, message)` 與 `MSG_*` 常數被 `cli` 與 `webui` 兩端共用,
故「同一個例外在 CLI 與 Web UI 說同一句話」不靠人去對帳,靠兩端取同一個來源。
**HTTP 狀態碼不在這裡**——`kind → status` 是 web 那一層的表達,住 `webui.py`。
"""


class QVaultError(Exception):
    """QVault 全部錯誤的基底。"""


class QVaultFormatError(QVaultError):
    """`.qvt` 位元佈局壞掉:magic 不符、定長欄位長度不符、欄位值越界、輸入截斷。

    界限檢查一律走本例外——**不得**讓 `struct.error` / `IndexError` /
    `MemoryError` / `OverflowError` 外洩(ADR-001 決策 15)。
    """


class QVaultVersionError(QVaultError):
    """`.qvt` 的 version 不是本實作認得的版本(ADR-001「不變式」④)。"""


class QVaultDecryptError(QVaultError):
    """AEAD 驗證失敗。

    **竄改**與**錯密碼**共用本例外且訊息完全相同(ADR-001 保證③,避免 oracle)。
    實際的 raise 點在 #2/#3/#4;此處先定義以固定錯誤體系。
    """


# ================================================================ 使用錯誤訊息
#
# 以下常數是**兩個呼叫端都要說的同一句話**(ADR-002 決策 8:UI 與 CLI 對同一狀況
# 逐字同訊息)。住在這裡的判準只有一條:**有兩個以上的呼叫端**。
# `cli` 專屬的提示(「兩次密碼不一致」、「沒有終端可以讀密碼」、「interrupted」)
# 留在 `cli.py`——那些話在 HTTP 上沒有對應情境,搬過來只會讓本模組變成字串倉庫。
#
# 一律是 `{path}` 樣板 + `.format(path=...)`,不是 f-string:樣板本身要能被測試
# 拿去比對(`tests/test_webui_crypto.py` 用它斷言兩端輸出一致),而 f-string 在
# 原始碼裡就被攤平了,比不了。

#: 輸入檔不存在。狀態碼側對 `missing`(HTTP `404`)。
MSG_INPUT_MISSING = "input file does not exist: {path}"

#: 目標已存在且未 `force`。`(use --force)` 這個尾巴是 CLI 的用語,但訊息只有
#: **一本帳**比「兩端各自措辭」重要得多:UI 的 `force` 欄位就是這個旗標。
MSG_REFUSE_OVERWRITE = "refusing to overwrite existing output: {path} (use --force)"

#: 還原目的目錄不存在。狀態碼側對 `not_dir`(HTTP `400`,ADR-002 決策 8 明列)。
MSG_OUT_DIR_MISSING = "output directory does not exist: {path}"

#: 輸入存在但不是普通檔案的兩種情況(分開講:使用者的下一步不一樣)。
MSG_INPUT_IS_DIR = "input is a directory, not a file: {path}"
MSG_INPUT_NOT_REGULAR = "input is not a regular file: {path}"

#: `.` / `..` / `/`:算不出「同目錄同名加 `.qvt`」的輸出路徑。
MSG_INPUT_NO_NAME = "input path has no file name: {path}"

#: 空密碼不是弱、是無(ADR-001 決策 8 / ADR-002 決策 7)。
MSG_PASSPHRASE_EMPTY = "passphrase must not be empty"

#: 孤兒代理對等無法 UTF-8 編碼的密碼。
#: **訊息不得含那個字元**——它是密碼的一部分(鐵律 5);故這句是定值,不帶輸入。
MSG_PASSPHRASE_UNENCODABLE = (
    "passphrase contains characters that cannot be encoded as UTF-8"
)


# ================================================================ 例外分類
#
#: `classify` 回傳的 `kind` 全集。**不含 HTTP 狀態碼**:狀態碼是表達層
#: (web)自己的事,`kind → status` 的對映表住在那一層
#: (`webui._STATUS_BY_KIND`),不住這裡——錯誤體系不該知道 HTTP 存在。
KINDS: tuple[str, ...] = (
    "format",
    "decrypt",
    "version",
    "missing",
    "exists",
    "not_dir",
    "usage",
    "unexpected",
)


def _oserror_message(exc: OSError) -> str:
    """`OSError` → 一行訊息。

    不吐 `[Errno 2] ...` 這種噪音;沒有 `strerror` 的(由 `vault` 自己 raise 的
    `FileExistsError` / `NotADirectoryError`)走 `str()`。
    """
    if exc.strerror:
        path = exc.filename or ""
        return f"{exc.strerror}: {path}" if path else exc.strerror
    return str(exc)


def classify(exc: BaseException) -> tuple[str, str]:
    """例外 → `(kind, message)`。**純函式**,不記 log、不碰 I/O、不看全域狀態。

    這是「同一個例外在 CLI 與 Web UI 兩端說同一句話」的唯一事實源:兩端都把
    自己的出口接到這個回傳值上,故訊息不可能漂。回傳的 `kind` 是語意分類,
    呼叫端自己決定要怎麼表達——CLI 印 `qvault: <message>` + 非零 exit,
    web 層查自己的 `kind → status` 表。

    `QVaultError` 的三個子類**分開**回,不是因為兩端的處置不同(三者在 HTTP 上
    都是 `422`、在 CLI 都是 exit 1),而是因為「錯密碼」與「格式壞」在語意上
    不同,而呼叫端有權知道差別——**但訊息一個字都不加**:錯密碼與竄改共用
    `QVaultDecryptError` 且訊息完全相同(ADR-001 保證③),分類不是 oracle,
    `kind` 與 `message` 都不區分那兩者。

    未預期例外只回**型別名**,絕不 `str(exc)`:例外訊息會轉述輸入(路徑、甚至
    密碼),而我們自己的 bug 不該變成一條洩漏路徑(鐵律 5)。
    """
    if isinstance(exc, QVaultDecryptError):
        return "decrypt", str(exc)
    if isinstance(exc, QVaultVersionError):
        return "version", str(exc)
    # 基底 `QVaultError` 併入 `format`:兩端的處置與 `QVaultFormatError` 相同,
    # 而多一個 `kind` 就是多一列沒有人測得到的對映。
    if isinstance(exc, QVaultError):
        return "format", str(exc)
    if isinstance(exc, FileNotFoundError):
        return "missing", _oserror_message(exc)
    if isinstance(exc, FileExistsError):
        return "exists", _oserror_message(exc)
    if isinstance(exc, NotADirectoryError):
        return "not_dir", _oserror_message(exc)
    if isinstance(exc, OSError):
        return "usage", _oserror_message(exc)
    return "unexpected", type(exc).__name__
