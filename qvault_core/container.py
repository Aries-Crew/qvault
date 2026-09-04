"""`.qvt` v1 容器 header 的序列化 / 反序列化——**純 struct,不碰加密**。

格式的唯一事實源 = `docs/adr/ADR-001-crypto-core-architecture.md`(AGENTS.md
「`.qvt` 容器格式」:勿在他處另複製格式)。本檔只是那份佈局的可執行轉錄。

線格式(全部多位元組整數 big-endian):

    off  size  field
      0     4  magic            b"QVLT"
      4     1  version          = 1
      5     1  kdf_id           1 = scrypt
      6     1  aead_id          1 = AES-256-GCM
      7     1  kem_id           1 = scrypt-KEK
      8     1  kdf_log2n        scrypt N = 2**此值
      9     1  kdf_r
     10     1  kdf_p
     11    16  salt             每檔重新隨機(決策 10)
     27     7  nonce_prefix     STREAM nonce 前綴(每檔隨機)
     34     4  chunk_size       明文分塊大小
     38     2  wrapped_dek_len  kem_id=1 時恆為 60
     40   var  wrapped_dek      wrap_nonce(12) ‖ ct(32) ‖ tag(16)(決策 11)

kem_id=1 → header 長度恆 100B(定長 40B + wrapped_dek 60B)。

**AAD 的位元組界(決策 12 / [H5])**:每個 chunk 的 AAD == `serialize()` 的完整
輸出 == `raw[:body_offset]`(**含 `wrapped_dek`**);`deserialize()` 回傳的
`body_offset` 就是 AAD 長度。

**界限檢查先於配置與 KDF(決策 15 / [H1])**:header 每個欄位都是攻擊者可控,
而 KDF 參數與緩衝區大小在 AEAD tag 被驗證**之前**就要被使用。`deserialize()`
在切出任何以 header 值決定大小的位元組、以及回傳給呼叫端去呼叫 `Scrypt`
之前,就把下列全部檢完,任一不符即 `QVaultFormatError`。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import QVaultFormatError, QVaultVersionError

__all__ = [
    "MAGIC",
    "VERSION",
    "SUPPORTED_VERSIONS",
    "KDF_ID_SCRYPT",
    "AEAD_ID_AES256GCM",
    "KEM_ID_SCRYPT",
    "SALT_LEN",
    "NONCE_PREFIX_LEN",
    "NONCE_LEN",
    "WRAPPED_DEK_LEN",
    "HEADER_FIXED_SIZE",
    "HEADER_SIZE_KEM1",
    "FIELD_LAYOUT",
    "KDF_LOG2N_RANGE",
    "KDF_R_RANGE",
    "KDF_P_RANGE",
    "CHUNK_SIZE_RANGE",
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_INDEX",
    "FLAG_MORE",
    "FLAG_LAST",
    "QVaultHeader",
    "deserialize",
    "nonce_for",
    "body_chunk_count",
]

MAGIC = b"QVLT"
VERSION = 1
SUPPORTED_VERSIONS = frozenset({1})

# 演算法 id——P0 只認得 1;未知 id **不得靜默忽略**(決策 15)。
KDF_ID_SCRYPT = 1
AEAD_ID_AES256GCM = 1
KEM_ID_SCRYPT = 1

SALT_LEN = 16
NONCE_PREFIX_LEN = 7
NONCE_LEN = 12
WRAPPED_DEK_LEN = 60  # kem_id=1:wrap_nonce(12) ‖ ct(32) ‖ tag(16)

_FIXED_FMT = ">4sBBBBBBB16s7sIH"
HEADER_FIXED_SIZE = struct.calcsize(_FIXED_FMT)  # 40
HEADER_SIZE_KEM1 = HEADER_FIXED_SIZE + WRAPPED_DEK_LEN  # 100

# (欄位, offset, size)——線格式的可機讀轉錄,供邊界測試逐欄掃。
FIELD_LAYOUT: tuple[tuple[str, int, int], ...] = (
    ("magic", 0, 4),
    ("version", 4, 1),
    ("kdf_id", 5, 1),
    ("aead_id", 6, 1),
    ("kem_id", 7, 1),
    ("kdf_log2n", 8, 1),
    ("kdf_r", 9, 1),
    ("kdf_p", 10, 1),
    ("salt", 11, SALT_LEN),
    ("nonce_prefix", 27, NONCE_PREFIX_LEN),
    ("chunk_size", 34, 4),
    ("wrapped_dek_len", 38, 2),
    ("wrapped_dek", HEADER_FIXED_SIZE, WRAPPED_DEK_LEN),
)

# 界限(決策 15 / [H1])——含頭含尾。
KDF_LOG2N_RANGE = (14, 22)
KDF_R_RANGE = (1, 32)
KDF_P_RANGE = (1, 16)
CHUNK_SIZE_RANGE = (4096, 1048576)
DEFAULT_CHUNK_SIZE = 65536

# STREAM 計數器是 uint32_BE,故 chunk index 上限。
MAX_CHUNK_INDEX = 2**32 - 1
FLAG_MORE = 0x00
FLAG_LAST = 0x01

_UINT8_MAX = 0xFF
_UINT16_MAX = 0xFFFF
_UINT32_MAX = 0xFFFFFFFF


def _check_int(name: str, value: object, lo: int, hi: int) -> int:
    """整數欄位的型別 + 範圍檢查。

    型別也要自己檢——否則 `struct.pack` 會丟 `struct.error`,而 AC 明令
    `struct.error` 不得外洩。
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise QVaultFormatError(f"{name} must be an int")
    if not lo <= value <= hi:
        raise QVaultFormatError(f"{name} out of range: expected {lo}..{hi}")
    return value


def _check_bytes(name: str, value: object, size: int) -> bytes:
    """定長位元組欄位的型別 + 長度檢查(「定長欄位長度不符 → QVaultFormatError」)。"""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise QVaultFormatError(f"{name} must be bytes")
    raw = bytes(value)
    if len(raw) != size:
        raise QVaultFormatError(f"{name} must be exactly {size} bytes")
    return raw


def _check_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QVaultVersionError("version must be an int")
    if value not in SUPPORTED_VERSIONS:
        raise QVaultVersionError(f"unsupported .qvt version: {value}")
    return value


def _check_params(
    kdf_id: object,
    aead_id: object,
    kem_id: object,
    kdf_log2n: object,
    kdf_r: object,
    kdf_p: object,
    chunk_size: object,
    wrapped_dek_len: object,
) -> None:
    """[H1] 界限檢查——**在任何以 header 值決定大小的配置與 `Scrypt` 之前**跑完。

    這些值全部由攻擊者控制,且在 AEAD tag 被驗證之前就要被使用:一個 60 byte 的
    畸形檔設 `kdf_log2n=63` 就是 `Scrypt(n=2**63)` → OOM(決策 15)。
    """
    # 演算法 id:P0 只認得 1,未知 id 不得靜默忽略。
    if _check_int("kdf_id", kdf_id, 0, _UINT8_MAX) != KDF_ID_SCRYPT:
        raise QVaultFormatError("unknown kdf_id")
    if _check_int("aead_id", aead_id, 0, _UINT8_MAX) != AEAD_ID_AES256GCM:
        raise QVaultFormatError("unknown aead_id")
    if _check_int("kem_id", kem_id, 0, _UINT8_MAX) != KEM_ID_SCRYPT:
        raise QVaultFormatError("unknown kem_id")

    # KDF 成本參數:在 Scrypt 被呼叫之前釘死上限。
    _check_int("kdf_log2n", kdf_log2n, *KDF_LOG2N_RANGE)
    _check_int("kdf_r", kdf_r, *KDF_R_RANGE)
    _check_int("kdf_p", kdf_p, *KDF_P_RANGE)

    # 緩衝區大小:範圍 + 2 的冪。
    size = _check_int("chunk_size", chunk_size, *CHUNK_SIZE_RANGE)
    if size & (size - 1):
        raise QVaultFormatError("chunk_size must be a power of two")

    # kem_id 已確定 == 1 → wrapped_dek 恆 60B。
    if _check_int("wrapped_dek_len", wrapped_dek_len, 0, _UINT16_MAX) != WRAPPED_DEK_LEN:
        raise QVaultFormatError(
            f"wrapped_dek_len must be {WRAPPED_DEK_LEN} for kem_id={KEM_ID_SCRYPT}"
        )


@dataclass(frozen=True, slots=True, repr=False)
class QVaultHeader:
    """`.qvt` v1 的明文 header。

    `salt` / `nonce_prefix` / `wrapped_dek` **沒有預設值**——預設值就是常數 salt /
    常數 nonce 前綴,正好是決策 10、11 明令禁止的錯法,故連手滑的機會都不留。
    欄位在 **線上** 的順序見 `FIELD_LAYOUT`(依 ADR-001);這裡的建構子順序只是把
    無預設值的排前面,不影響位元佈局。
    """

    salt: bytes
    nonce_prefix: bytes
    wrapped_dek: bytes
    chunk_size: int = DEFAULT_CHUNK_SIZE
    version: int = VERSION
    kdf_id: int = KDF_ID_SCRYPT
    aead_id: int = AEAD_ID_AES256GCM
    kem_id: int = KEM_ID_SCRYPT
    kdf_log2n: int = 15
    kdf_r: int = 8
    kdf_p: int = 1
    magic: bytes = MAGIC

    def __repr__(self) -> str:
        """白名單 repr(決策 20 / [H4] 的同一條理由)。

        預設 dataclass repr 會把 `salt` / `nonce_prefix` / `wrapped_dek` 吐進
        `logging.exception` 與 pytest 的 locals 展開;wrapped DEK 進了終端或工單,
        攻擊者不需檔案就能離線爆密碼。此處只印 `inspect` 白名單那幾欄。
        """
        return (
            f"<QVaultHeader version={self.version} kdf_id={self.kdf_id} "
            f"aead_id={self.aead_id} kem_id={self.kem_id} "
            f"kdf_log2n={self.kdf_log2n} kdf_r={self.kdf_r} kdf_p={self.kdf_p} "
            f"chunk_size={self.chunk_size}>"
        )

    def _validate(self) -> None:
        """serialize 前的自檢——序列化不出一個自己 deserialize 不回來的 header。"""
        if _check_bytes("magic", self.magic, len(MAGIC)) != MAGIC:
            raise QVaultFormatError("bad magic")
        _check_version(self.version)
        _check_bytes("salt", self.salt, SALT_LEN)
        _check_bytes("nonce_prefix", self.nonce_prefix, NONCE_PREFIX_LEN)
        if not isinstance(self.wrapped_dek, (bytes, bytearray, memoryview)):
            raise QVaultFormatError("wrapped_dek must be bytes")
        # wrapped_dek 的長度是欄位值(wrapped_dek_len),故走 _check_params 的同一條規則。
        _check_params(
            self.kdf_id,
            self.aead_id,
            self.kem_id,
            self.kdf_log2n,
            self.kdf_r,
            self.kdf_p,
            self.chunk_size,
            len(bytes(self.wrapped_dek)),
        )

    def serialize(self) -> bytes:
        """回傳 header 的完整線格式位元組。

        這份輸出**就是** AAD(決策 12):`.qvt` 的 `offset 0 .. body_offset`。
        """
        self._validate()
        return struct.pack(
            _FIXED_FMT,
            bytes(self.magic),
            self.version,
            self.kdf_id,
            self.aead_id,
            self.kem_id,
            self.kdf_log2n,
            self.kdf_r,
            self.kdf_p,
            bytes(self.salt),
            bytes(self.nonce_prefix),
            self.chunk_size,
            len(self.wrapped_dek),
        ) + bytes(self.wrapped_dek)

    def aad(self) -> bytes:
        """每個 chunk 的 AEAD AAD == `serialize()` 全段(決策 12 / [H5])。

        只是 `serialize()` 的具名別名:這個位元組界一旦歧義,兩個實作會互不相容,
        而各自的 round-trip 與竄改測試都照樣通過。給它一個名字就不必再猜。
        """
        return self.serialize()

    @property
    def body_offset(self) -> int:
        """body(chunk 0)起點,亦即 AAD 長度。"""
        return HEADER_FIXED_SIZE + len(self.wrapped_dek)


def deserialize(data: bytes) -> tuple[QVaultHeader, int]:
    """解析 header,回傳 `(header, body_offset)`。

    `data` 可以比 header 長(正常情況就是整個 `.qvt`);多出來的位元組是 body,
    本函式不碰。`body_offset` 同時是 body 起點與 AAD 長度。

    只會丟 `QVaultFormatError` / `QVaultVersionError`——`struct.error`、
    `IndexError`、`MemoryError`、`OverflowError`、`UnicodeDecodeError` 一概不外洩。
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise QVaultFormatError("input must be bytes")
    try:
        buf = memoryview(data).cast("B")
    except (TypeError, ValueError):
        # 非連續 / 多維 memoryview——是壞輸入,不是壞格式,但一樣不該漏出原例外。
        raise QVaultFormatError("input must be a contiguous byte buffer") from None
    n = buf.nbytes

    # 1. magic——先認招牌,才談其他。
    if n < len(MAGIC):
        raise QVaultFormatError("truncated: input shorter than magic")
    if bytes(buf[: len(MAGIC)]) != MAGIC:
        raise QVaultFormatError("bad magic: not a .qvt container")

    # 2. version——未知版本是 QVaultVersionError,不是 FormatError。
    if n < len(MAGIC) + 1:
        raise QVaultFormatError("truncated: missing version")
    _check_version(buf[len(MAGIC)])

    # 3. 定長段必須完整才談欄位值。
    if n < HEADER_FIXED_SIZE:
        raise QVaultFormatError(
            f"truncated: fixed header needs {HEADER_FIXED_SIZE} bytes"
        )

    try:
        (
            magic,
            version,
            kdf_id,
            aead_id,
            kem_id,
            kdf_log2n,
            kdf_r,
            kdf_p,
            salt,
            nonce_prefix,
            chunk_size,
            wrapped_dek_len,
        ) = struct.unpack_from(_FIXED_FMT, buf, 0)
    except struct.error:  # pragma: no cover —— 長度已先檢,理應不可達
        raise QVaultFormatError("malformed fixed header") from None

    # 4. [H1] 界限檢查:在切出 wrapped_dek(唯一以 header 值決定大小的配置)之前,
    #    也在呼叫端拿 kdf_* 去餵 Scrypt 之前,全部檢完。
    _check_params(
        kdf_id, aead_id, kem_id, kdf_log2n, kdf_r, kdf_p, chunk_size, wrapped_dek_len
    )

    # 5. 到這裡 wrapped_dek_len 已確定 == 60,切片不可能爆記憶體。
    body_offset = HEADER_FIXED_SIZE + wrapped_dek_len
    if n < body_offset:
        raise QVaultFormatError("truncated: wrapped_dek shorter than declared")
    wrapped_dek = bytes(buf[HEADER_FIXED_SIZE:body_offset])

    header = QVaultHeader(
        salt=salt,
        nonce_prefix=nonce_prefix,
        wrapped_dek=wrapped_dek,
        chunk_size=chunk_size,
        version=version,
        kdf_id=kdf_id,
        aead_id=aead_id,
        kem_id=kem_id,
        kdf_log2n=kdf_log2n,
        kdf_r=kdf_r,
        kdf_p=kdf_p,
        magic=magic,
    )
    return header, body_offset


def nonce_for(prefix: bytes, index: int, is_last: bool) -> bytes:
    """STREAM 的 12B nonce = `prefix(7B) ‖ uint32_BE(index) ‖ flag(1B)`(決策 5)。

    `flag` = `0x01` 表示末塊(防截斷),其餘 `0x00`。`nonce_prefix` 每檔隨機 →
    `(prefix ‖ counter)` 全域唯一,nonce 永不重用——這是最關鍵的一條不變式。

    `index` 超出 uint32 或為負 → `ValueError`(這是呼叫端的程式錯誤,不是檔案格式
    壞掉,故不用 `QVaultFormatError`;`.qvt` 裡本來就沒有存 index 這個欄位)。
    """
    if not isinstance(prefix, (bytes, bytearray, memoryview)):
        raise ValueError("nonce prefix must be bytes")
    raw_prefix = bytes(prefix)
    if len(raw_prefix) != NONCE_PREFIX_LEN:
        raise ValueError(f"nonce prefix must be exactly {NONCE_PREFIX_LEN} bytes")
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("chunk index must be an int")
    if not 0 <= index <= MAX_CHUNK_INDEX:
        raise ValueError(f"chunk index out of range: expected 0..{MAX_CHUNK_INDEX}")
    return raw_prefix + index.to_bytes(4, "big") + bytes(
        [FLAG_LAST if is_last else FLAG_MORE]
    )


def body_chunk_count(orig_size: int, chunk_size: int) -> int:
    """body 的 chunk 總數,**含 chunk 0 的中繼資料塊**。

    空檔正規佈局(決策 14 / [H3]):`orig_size == 0` → 回 1,body **只有 chunk 0**,
    而那一塊同時是末塊(flag == `0x01`);**禁止**補一個零長度資料塊。
    """
    if isinstance(orig_size, bool) or not isinstance(orig_size, int) or orig_size < 0:
        raise QVaultFormatError("orig_size must be a non-negative int")
    size = _check_int("chunk_size", chunk_size, *CHUNK_SIZE_RANGE)
    if size & (size - 1):
        raise QVaultFormatError("chunk_size must be a power of two")
    return 1 + (orig_size + size - 1) // size
