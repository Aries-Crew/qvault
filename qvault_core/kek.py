"""KEK 層——`KeyEncapsulation` ABC(PQC 插槽)+ P0 的 `ScryptKEK`。

信封的**中間層**:DEK 由 #2 的 `aead` 加密檔案資料,而 DEK 本身由本層包起來
(wrap)存進 header 的 `wrapped_dek`。換 KEK / 加後量子時只換這一層,**整檔不必
重加密**(ADR-001 決策 1);P1 的 `MLKEMKek` / `HybridKEK` 只要實作同一個 ABC,
信封層一行不動(決策 2、鐵律 3)。

## 依賴方向

`kek → {aead, errors}`,**不 import `container`**:ADR 的相依圖裡 `container` 與
`kek` 是兄弟(`cli → vault → {container, aead, kek}`),互相 import 就成了環。
代價是 `SALT_LEN` / `KEM_ID_SCRYPT` / `WRAPPED_DEK_LEN` / KDF 界限在兩處各有一份;
沿用 #2 的辦法,用 `test_constants_agree_with_container` 把兩份數字釘在一起。

## wrap 的線格式(決策 11 / [C2])

    wrapped_dek = wrap_nonce(12B) ‖ ct(32B) ‖ tag(16B)   # 恰 60B

`wrap_nonce = secrets.token_bytes(12)`,**每次 `wrap()` 重新產生**。這條與決策 10
(salt 每檔隨機)是**一組**的:兩條之中任一條沒落實,同一把 KEK 底下就會出現
GCM nonce 重用 → 洩 DEK 差值、可解出 GHASH 子鑰 H → **偽造任意 wrapped DEK**。
故本層**不接受**外部傳入的 nonce,連參數都不留——沒有參數就沒有「呼叫端傳了
常數進來」這條路徑。(注意這與 #2 的 `seal(key, nonce, ...)` 相反:那一層的 nonce
必須由 STREAM 計數器決定,自產反而會毀掉不變式①。兩層的理由是同一條「nonce
永不重用」,只是在各自的脈絡下結論相反。)

## wrap 的 AAD 是常數,**不是 header**(決策 11)

`WRAP_AAD = b"QVLT-dek-v1"`。header 自己含 `wrapped_dek`,拿 header 當 wrap 的
AAD 會循環(要先有 wrapped_dek 才能組 header,要先有 header 才能算 wrapped_dek)。
常數 AAD 的用途是 **domain separation**:同一把 KEK 產生的密文不會被搬去別的
脈絡冒充。chunk 的 AAD 才是 header 全段(決策 12),那是 #4 的事。

## 金鑰不得可印(決策 19 / [H4])

- **passphrase 不留**:`__init__` 派生完 KEK 就丟掉,實例裡從頭到尾沒有密碼。
- KEK 本身包在 `_SecretBytes` 裡,`repr()` 只吐 `<secret 32 bytes>`——`__repr__`
  管得住 `repr(kek)`,管不住 `repr(vars(kek))` 與 `logging.debug("%r", kek.__dict__)`,
  那個洞得靠被包住的值自己閉嘴。
- **不是 dataclass**:預設 dataclass repr 會把每個欄位吐進 `logging.exception` 與
  pytest 的 locals 展開。

失敗一律沿用 `aead.unseal` 的 `QVaultDecryptError`,**訊息一個字都不加**——錯密碼
與竄改因此天然逐字相同([M4]、保證③)。
"""

from __future__ import annotations

import secrets
import unicodedata
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .aead import DEK_LEN, KEY_LEN, NONCE_LEN, TAG_LEN, seal, unseal
from .errors import QVaultFormatError

__all__ = [
    "KEM_ID_SCRYPT",
    "KEK_LEN",
    "SALT_LEN",
    "WRAP_NONCE_LEN",
    "WRAPPED_DEK_LEN",
    "WRAP_AAD",
    "SCRYPT_LOG2N",
    "SCRYPT_R",
    "SCRYPT_P",
    "KDF_LOG2N_RANGE",
    "KDF_R_RANGE",
    "KDF_P_RANGE",
    "KeyEncapsulation",
    "ScryptKEK",
]

#: header 的 `kem_id`:1 = scrypt-KEK(P0);2 = ML-KEM、3 = hybrid 留給 P1。
KEM_ID_SCRYPT = 1

KEK_LEN = KEY_LEN  # 32:KEK 是一把 AES-256 金鑰,故 scrypt 的 dklen = 32
SALT_LEN = 16  # header 的定長欄位(決策 10:每檔重新隨機)
WRAP_NONCE_LEN = NONCE_LEN  # 12
WRAPPED_DEK_LEN = WRAP_NONCE_LEN + DEK_LEN + TAG_LEN  # 12 + 32 + 16 = 60

#: wrap/unwrap 的 AAD——**常數**,不是 header(決策 11;理由見模組 docstring)。
WRAP_AAD = b"QVLT-dek-v1"

# P0 的 scrypt 成本參數(決策 7),同時是 `.qvt` header 寫進去的那三個值。
SCRYPT_LOG2N = 15
SCRYPT_R = 8
SCRYPT_P = 1

# 界限(決策 15)——與 `container` 的同名常數必須一致,由測試釘住。
KDF_LOG2N_RANGE = (14, 22)
KDF_R_RANGE = (1, 32)
KDF_P_RANGE = (1, 16)

# `insecure_for_tests()` 專用的放寬下界:`Scrypt` 要求 n 是 > 1 的 2 的冪,
# 故 log2n 至少 1。上界仍是正規上界——放寬只往「更快」的方向,不往「更貴」的方向
# (往更貴的方向放寬 = 開一條 OOM 的路)。
_TEST_LOG2N_RANGE = (1, KDF_LOG2N_RANGE[1])


def _check_int(name: str, value: object, lo: int, hi: int) -> int:
    """整數參數的型別 + 範圍檢查(訊息與 `container._check_int` 逐字相同)。

    用 `QVaultFormatError` 而非 `ValueError`:解密路徑的 `log2n`/`r`/`p`/`salt`
    **來自 `.qvt` header**,是攻擊者可控的欄位值,越界屬「格式壞掉」。`deserialize`
    已經先擋過一輪(決策 15),本層是第二道——KDF 參數是唯一一組「在 tag 被驗證
    之前就要拿去配置記憶體」的值,兩道都便宜,少一道就得賭呼叫端沒繞路。
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise QVaultFormatError(f"{name} must be an int")
    if not lo <= value <= hi:
        raise QVaultFormatError(f"{name} out of range: expected {lo}..{hi}")
    return value


def _check_bytes_field(name: str, value: object, size: int) -> bytes:
    """定長位元組欄位(`salt`、`wrapped_dek`)的檢查——來源是 header,故 Format。

    `memoryview` 的 `len()` 是**元素數**不是**位元組數**,一律先 `bytes()` 再量長度
    (#1 在 `wrapped_dek` 上踩過這個洞)。
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise QVaultFormatError(f"{name} must be bytes")
    try:
        raw = bytes(value)
    except (TypeError, ValueError):
        raise QVaultFormatError(f"{name} must be a contiguous byte buffer") from None
    if len(raw) != size:
        raise QVaultFormatError(f"{name} must be exactly {size} bytes")
    return raw


def _check_dek(value: object) -> bytes:
    """DEK 的檢查——來源是 `gen_dek()`,**不是**檔案,故長度錯是呼叫端的程式錯誤。

    沿用 #2 `aead._as_bytes` 的同一條判準:報成 `QVaultDecryptError` 會讓 CLI 把
    程式 bug 說成「密碼錯誤」,而真正的 bug 被靜音。
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("dek must be bytes")
    try:
        raw = bytes(value)
    except (TypeError, ValueError):
        raise ValueError("dek must be a contiguous byte buffer") from None
    if len(raw) != DEK_LEN:
        raise ValueError(f"dek must be exactly {DEK_LEN} bytes")
    return raw


def _passphrase_bytes(passphrase: object) -> bytes:
    """passphrase → bytes:**一律** `NFC` 正規化再 UTF-8(決策 18 / [M6])。

    macOS 的輸入法給 NFD、Windows/Linux 給 NFC;同一個密碼在兩邊派生出不同 KEK,
    檔案就跨平台打不開——直接牴觸「OS 無關」,而且症狀是「密碼錯誤」,沒人會往
    正規化去猜。

    **只收 `str`**:`bytes` 沒有「正規化」可言,收了就等於開一條繞過決策 18 的路,
    同一個密碼於是有兩種 KEK。空字串**允許**——P0 不強制密碼強度(決策 8)。

    UTF-8 編碼失敗(孤兒代理對,例如 Windows argv 經 `surrogateescape` 進來的位元組)
    自己接住:`UnicodeEncodeError` 的訊息會把**出錯的那個字元印出來**,那是密碼的
    一部分,直接違反鐵律 5。`from None` 連鎖也一併切掉。
    """
    if not isinstance(passphrase, str):
        raise ValueError("passphrase must be str")
    try:
        return unicodedata.normalize("NFC", passphrase).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("passphrase must be encodable as UTF-8") from None


def _scrypt(
    passphrase_bytes: bytes,
    salt: bytes,
    *,
    n: int,
    r: int,
    p: int,
    dklen: int = KEK_LEN,
) -> bytes:
    """scrypt 派生——**只呼叫 `cryptography`,永不手刻**(鐵律 1)。

    參數順序在此定死一次(`Scrypt(salt=..., length=..., n=..., r=..., p=...)`
    全部具名),因為「把 r 和 p 對調」「把 passphrase 和 salt 對調」都是自己跟自己
    完全自洽的錯法:round-trip 照樣全綠,只有 RFC 7914 的官方向量抓得到。
    `dklen` 只為那組向量(64B)存在;正規路徑一律預設的 32B。
    """
    return Scrypt(salt=salt, length=dklen, n=n, r=r, p=p).derive(passphrase_bytes)


class _SecretBytes:
    """裝金鑰的不透明盒子:**印不出內容、也醃不進 pickle**。

    `__repr__` 只管得住 `repr(kek)`。真正會漏的是這些:

        logging.debug("kek=%r", kek.__dict__)   # 繞過 __repr__
        repr(vars(kek))                         # [H4] 的測試就是打這一發
        pytest 失敗時的 locals 展開

    這些拿到的是**欄位值本身**,所以閉嘴的責任得落在值上。`__reduce__` 一併封掉:
    把 KEK 醃進 cache 檔就是「金鑰落地」(鐵律 5),而 pickle 不會問過任何人。
    """

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def reveal(self) -> bytes:
        """取出原始位元組——呼叫點應該少到可以一眼數完(本檔只有 `wrap`/`unwrap`)。"""
        return self._raw

    def __repr__(self) -> str:
        return f"<secret {len(self._raw)} bytes>"

    def __reduce__(self):  # noqa: D105 —— 見類別 docstring
        raise TypeError("secret key material must not be pickled")


class KeyEncapsulation(ABC):
    """把 DEK 包起來的抽象介面——**PQC 的插槽**(ADR-001 決策 2 / 鐵律 3)。

    P0 只有 `ScryptKEK`;P1 的 `MLKEMKek`(ML-KEM-1024)與 `HybridKEK`(scrypt ⊕
    ML-KEM 雙封裝)實作同一組方法,**信封層零改動**即證抽象成立。

    契約:

    - `kem_id`:寫進 header 的整數 id,向前相容用。宣告成抽象成員,子類以**類別
      屬性**覆寫(見 `ScryptKEK.kem_id`)。
    - `wrap(dek) -> bytes`:回不透明位元組;長度由各 KEM 自己定(scrypt-KEK 是 60B,
      ML-KEM 會長得多,故 header 的 `wrapped_dek_len` 是欄位而非常數)。
    - `unwrap(wrapped) -> bytes`:回 DEK;**失敗一律 `QVaultDecryptError`**,且不同
      失敗原因的訊息必須逐字相同(保證③,避免 oracle)。

    `nonce` 不在介面裡:wrap 用的 nonce 是各實作的內部細節,**由實作自己隨機產生**,
    不接受外部傳入(見模組 docstring)。
    """

    __slots__ = ()

    @property
    @abstractmethod
    def kem_id(self) -> int:
        """寫進 `.qvt` header 的 KEM id(scrypt-KEK = 1)。"""

    @abstractmethod
    def wrap(self, dek: bytes) -> bytes:
        """包裝 DEK,回 `wrapped_dek`(每次呼叫的輸出都必須不同)。"""

    @abstractmethod
    def unwrap(self, wrapped: bytes) -> bytes:
        """解開 `wrapped_dek` 回 DEK;驗證失敗 raise `QVaultDecryptError`。"""


class ScryptKEK(KeyEncapsulation):
    """P0 的 KEK:passphrase 經 scrypt 派生,再以 AES-256-GCM 包/解 DEK。

        kek = ScryptKEK(passphrase, salt)          # 15/8/1,加密路徑
        kek = ScryptKEK(passphrase, header.salt,   # 解密路徑:參數取自 header
                        log2n=header.kdf_log2n, r=header.kdf_r, p=header.kdf_p)

    `salt` **沒有預設值**:預設值就是常數 salt,而常數 salt = 全世界所有檔案共用
    同一把 KEK,一張彩虹表通吃、離線爆破成本由 O(檔案數) 降為 O(1)(決策 10)。
    連手滑的機會都不留。salt 該長什麼樣是 #4 的事(`secrets.token_bytes(16)`)。

    成本參數可覆寫**但只在正規界限內**(14..22 / 1..32 / 1..16)——解密舊檔要照
    header 走(決策 7)。要比正規下界更低(測試想跑得快)必須改用
    `insecure_for_tests()`,名字裡就寫著 insecure,grep 得到,而且不可能是手滑。
    """

    #: 類別屬性(不是實例欄位)——[L] 要求可證偽:`ScryptKEK.kem_id == 1`。
    kem_id = KEM_ID_SCRYPT

    def __init__(
        self,
        passphrase: str,
        salt: bytes,
        *,
        log2n: int = SCRYPT_LOG2N,
        r: int = SCRYPT_R,
        p: int = SCRYPT_P,
        _allow_insecure_params: bool = False,
    ) -> None:
        log2n_range = _TEST_LOG2N_RANGE if _allow_insecure_params else KDF_LOG2N_RANGE
        self.log2n = _check_int("kdf_log2n", log2n, *log2n_range)
        self.r = _check_int("kdf_r", r, *KDF_R_RANGE)
        self.p = _check_int("kdf_p", p, *KDF_P_RANGE)
        self.salt = _check_bytes_field("salt", salt, SALT_LEN)

        # 參數檢查全部先跑完才碰 KDF(決策 15):`log2n=63` 是 `Scrypt(n=2**63)`,
        # 也就是一個 60 byte 的畸形檔就能點的 OOM。
        # passphrase 只在這一行的作用域裡存在,派生完就沒有任何欄位指向它。
        self._kek = _SecretBytes(
            _scrypt(
                _passphrase_bytes(passphrase),
                self.salt,
                n=1 << self.log2n,
                r=self.r,
                p=self.p,
            )
        )

    @classmethod
    def insecure_for_tests(
        cls,
        passphrase: str,
        salt: bytes,
        *,
        log2n: int = 10,
        r: int = 1,
        p: int = 1,
    ) -> ScryptKEK:
        """**測試專用**:允許低於正規下界的成本參數,好讓測試不必每次燒 80ms。

        [M3] 的要求是「覆寫僅供測試,不得讓測試用的低參數繼承到預設路徑」。做法
        不是靠自律,是靠**結構**:低參數只有這個入口,而這個入口的名字是
        `insecure_for_tests`——`qvault_core/` 內只要有第二處提到它,測試就會失敗
        (`test_production_code_never_uses_the_insecure_hatch`)。正規建構子的預設值
        永遠是 15/8/1,本方法**不改動任何類別/模組層的預設值**,故呼叫過它之後
        `ScryptKEK(pw, salt)` 依然是 15/8/1。
        """
        return cls(
            passphrase, salt, log2n=log2n, r=r, p=p, _allow_insecure_params=True
        )

    def __repr__(self) -> str:
        """固定格式(決策 19 / [H4]):`<ScryptKEK kem_id=1>`,別的一律不印。

        `str()` 沒有另外定義——`object.__str__` 會轉呼叫這裡,兩者因此不可能漂移。
        """
        return f"<{type(self).__name__} kem_id={self.kem_id}>"

    def wrap(self, dek: bytes) -> bytes:
        """包 DEK,回 `wrap_nonce(12B) ‖ ct(32B) ‖ tag(16B)`(恰 60B)。

        `wrap_nonce` **每次重新隨機**(決策 11 / [C2]);同一把 KEK 對同一個 DEK
        連呼兩次,輸出必不同。隨機來源限 `secrets`(決策 20)。
        """
        dek_b = _check_dek(dek)
        wrap_nonce = secrets.token_bytes(WRAP_NONCE_LEN)
        return wrap_nonce + seal(self._kek.reveal(), wrap_nonce, dek_b, WRAP_AAD)

    def unwrap(self, wrapped: bytes) -> bytes:
        """驗證並解開 `wrapped_dek`,回 DEK。

        錯密碼、錯 salt、錯成本參數、被改過一個 byte——**全部**走 `aead.unseal` 的
        `QVaultDecryptError`,型別與訊息逐字相同([M4]);本層一個字都不加。
        """
        raw = _check_bytes_field("wrapped_dek", wrapped, WRAPPED_DEK_LEN)
        return unseal(
            self._kek.reveal(),
            raw[:WRAP_NONCE_LEN],
            raw[WRAP_NONCE_LEN:],
            WRAP_AAD,
        )
