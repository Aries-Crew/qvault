"""QVault 錯誤體系(ADR-001「錯誤體系」)。

    QVaultError
      ├── QVaultFormatError   magic 錯、欄位長度不符、界限外、截斷
      ├── QVaultVersionError  未知 `.qvt` version
      └── QVaultDecryptError  AEAD tag 驗證失敗(竄改或錯金鑰,不於訊息區分)

鐵律(AGENTS.md 5 / ADR-001 決策 19):例外訊息**永不**含金鑰、密碼或明文。
本模組的訊息一律只描述「哪個欄位、期望什麼」,不回填使用者資料。
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
