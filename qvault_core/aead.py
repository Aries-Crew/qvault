"""AES-256-GCM 的薄封裝——**只呼叫 `cryptography`,永不手刻 AES/GCM**(AGENTS.md 鐵律 1)。

本檔是信封的最內層:給它 32B 金鑰、12B nonce、明文與 AAD,回 `ct‖tag`;反過來
驗不過就 raise。**不決定 nonce、不決定金鑰、不碰檔案**——那些分別是 #4(STREAM
的 `nonce_for`)、#3(`ScryptKEK`)與 #4(`vault.py`)的事。

## 為什麼 `seal(key, nonce, ...)` 收 nonce,而不是自己產一個回傳

ROADMAP 的那行交付寫的是 `encrypt(plaintext, aad) -> (nonce, ct, tag)`,但 ADR-001
決策 5 把 nonce 定死成 STREAM 構造 `nonce_prefix(7B) ‖ uint32_BE(i) ‖ flag(1B)`:
nonce **必須**由呼叫端依塊序號算出(`container.nonce_for`),AEAD 層自產隨機 nonce
會直接毀掉「`(prefix ‖ counter)` 全域唯一、永不重用」這條最關鍵的不變式,也拿不到
末塊 flag 的防截斷。故本檔採 `docs/P0-acceptance-criteria.md` #2 的
`seal`/`unseal` 簽章(該份 AC 經獨立密碼安全複審補強,是較晚、較細的一份)。

## 命名(AC #2 的 [L])

用 `seal`/`unseal`,**不用 `open`**——模組層的 `open` 會遮蔽內建 `open`,而這個
套件正要拿內建 `open` 去讀寫 `.qvt`。

## 失敗一律同一句話

`unseal` 不論是 ct、tag、nonce、aad 還是金鑰不符,甚至輸入被截到比 tag 還短,
一律 raise `QVaultDecryptError(_AUTH_FAILED)`——**型別與訊息逐字相同**
(ADR-001 保證③:竄改與錯密碼不於訊息區分,避免 oracle)。包 `InvalidTag` 時用
`raise ... from None`(決策 19),不外洩原例外,訊息裡也**永不**出現金鑰或明文
(鐵律 5)。
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import QVaultDecryptError

__all__ = [
    "KEY_LEN",
    "DEK_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "gen_dek",
    "seal",
    "unseal",
]

KEY_LEN = 32  # AES-256
DEK_LEN = 32  # DEK 就是一把 AES-256 金鑰
NONCE_LEN = 12  # GCM 的 96-bit nonce(= container.nonce_for 的輸出長度)
TAG_LEN = 16  # GCM tag,附在密文尾端

#: 所有驗證失敗共用的訊息。**不得**依失敗原因分歧——分歧就是 oracle。
_AUTH_FAILED = "AEAD authentication failed"


def _as_bytes(name: str, value: object, *, size: int | None = None) -> bytes:
    """位元組參數的型別 / 長度檢查,並正規化成 `bytes`。

    `memoryview` 的 `len()` 是**元素數**不是**位元組數**(#1 在 `wrapped_dek` 上
    踩過這個洞),故一律先 `bytes()` 再量長度——「長度」在本檔只有一個定義。

    型別 / 長度不符丟 `ValueError` 而**非** `QVaultDecryptError`:金鑰與 nonce 都
    來自程式自己(`gen_dek` / `ScryptKEK` / `nonce_for`),**永遠不來自 `.qvt`**,
    長度不對代表呼叫端寫錯,不是使用者拿到一個壞檔。混成解密錯誤會讓 CLI 把程式
    bug 報成「密碼錯誤」。(密文 `sealed` 是唯一由檔案來的參數,它的長度不足另行
    處理——見 `unseal`。)
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{name} must be bytes")
    try:
        raw = bytes(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a contiguous byte buffer") from None
    if size is not None and len(raw) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return raw


def gen_dek() -> bytes:
    """新的 256-bit 資料金鑰 = `secrets.token_bytes(32)`。

    隨機來源限 `secrets`(ADR-001 決策 20;`qvault_core/` 內禁止 `import random`)。
    回傳值是金鑰:**不得**寫檔、進 log、進例外訊息(鐵律 5)。
    """
    return secrets.token_bytes(DEK_LEN)


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM 加密,回 `ciphertext ‖ tag(16B)`(即落盤的一整塊)。

    `nonce` 由呼叫端提供(見模組 docstring):同一把 `key` 底下**同一個 nonce 只能
    用一次**——重用會洩明文差值並可解出 GHASH 子鑰 H。`aad` 是必填位置參數且不接受
    `None`:若允許 `None`,一個「忘了傳 header」的呼叫端會靜默失去 header 綁定
    (決策 6),而 round-trip 與竄改測試**照樣全綠**。空 AAD 請明寫 `b""`。
    """
    key_b = _as_bytes("key", key, size=KEY_LEN)
    nonce_b = _as_bytes("nonce", nonce, size=NONCE_LEN)
    pt = _as_bytes("plaintext", plaintext)
    aad_b = _as_bytes("aad", aad)
    return AESGCM(key_b).encrypt(nonce_b, pt, aad_b)


def unseal(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    """驗證並解密 `ciphertext ‖ tag(16B)`,回明文。

    ct / tag / nonce / aad / key **任一**不符 → `QVaultDecryptError`,型別與訊息
    逐字相同(保證③),且明文**絕不**部分回傳(保證①:GCM 先驗 tag 才交資料,
    `cryptography` 的 one-shot API 天然如此)。
    """
    key_b = _as_bytes("key", key, size=KEY_LEN)
    nonce_b = _as_bytes("nonce", nonce, size=NONCE_LEN)
    sealed_b = _as_bytes("sealed", sealed)
    aad_b = _as_bytes("aad", aad)

    # 截斷到連 tag 都放不下,也是竄改的一種:走**完全相同**的例外與訊息,
    # 不讓攻擊者從「哪一種錯」讀出任何資訊。
    if len(sealed_b) < TAG_LEN:
        raise QVaultDecryptError(_AUTH_FAILED)

    try:
        return AESGCM(key_b).decrypt(nonce_b, sealed_b, aad_b)
    except InvalidTag:
        # `from None`(決策 19):不外洩 InvalidTag,不讓 traceback 帶出任何脈絡。
        raise QVaultDecryptError(_AUTH_FAILED) from None
