"""`.qvt` v1 容器 header 的邊界測試(AC #1;設計見 ADR-001)。

本檔只測純 struct 層——不碰加密(那是 #2)。
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import random
import struct
import time

import pytest

from qvault_core.container import (
    CHUNK_SIZE_RANGE,
    FIELD_LAYOUT,
    HEADER_FIXED_SIZE,
    HEADER_SIZE_KEM1,
    KDF_LOG2N_RANGE,
    KDF_P_RANGE,
    KDF_R_RANGE,
    MAGIC,
    MAX_CHUNK_INDEX,
    NONCE_LEN,
    NONCE_PREFIX_LEN,
    SALT_LEN,
    VERSION,
    WRAPPED_DEK_LEN,
    QVaultHeader,
    body_chunk_count,
    deserialize,
    nonce_for,
)
from qvault_core.errors import QVaultError, QVaultFormatError, QVaultVersionError

# ---------------------------------------------------------------- 夾具

#: 每個欄位給一段**互不相同**的位元組,故欄位錯序 / 錯長度會立刻在線格式上現形。
SALT = bytes(range(0x10, 0x20))
NONCE_PREFIX = bytes(range(0x20, 0x27))
WRAPPED_DEK = bytes(range(0x30, 0x30 + WRAPPED_DEK_LEN))

#: 逐欄字面值寫死的線格式(**不由實作輸出反推**——反推的話欄位錯序也會「通過」)。
GOLDEN_FIELDS = (
    ("magic", "51564c54"),
    ("version", "01"),
    ("kdf_id", "01"),
    ("aead_id", "01"),
    ("kem_id", "01"),
    ("kdf_log2n", "0f"),  # 15
    ("kdf_r", "08"),
    ("kdf_p", "01"),
    ("salt", "101112131415161718191a1b1c1d1e1f"),
    ("nonce_prefix", "20212223242526"),
    ("chunk_size", "00010000"),  # 65536,big-endian(小端會是 00000100)
    ("wrapped_dek_len", "003c"),  # 60,big-endian(小端會是 3c00)
    (
        "wrapped_dek",
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b"
        "4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b",
    ),
)
GOLDEN_RAW = bytes.fromhex("".join(hexpart for _, hexpart in GOLDEN_FIELDS))

OFF = {name: offset for name, offset, _ in FIELD_LAYOUT}
SIZE = {name: size for name, _, size in FIELD_LAYOUT}


def make_header(**overrides) -> QVaultHeader:
    base = dict(
        salt=SALT,
        nonce_prefix=NONCE_PREFIX,
        wrapped_dek=WRAPPED_DEK,
        chunk_size=65536,
        version=VERSION,
        kdf_log2n=15,
        kdf_r=8,
        kdf_p=1,
    )
    base.update(overrides)
    return QVaultHeader(**base)


def splice(raw: bytes, offset: int, blob: bytes) -> bytes:
    """把 `blob` 蓋在線格式的 `offset` 上——繞過 dataclass 驗證,直接造畸形檔。"""
    return raw[:offset] + blob + raw[offset + len(blob) :]


@pytest.fixture
def raw() -> bytes:
    return make_header().serialize()


# ---------------------------------------------------------------- 佈局


def test_layout_constants():
    assert MAGIC == b"QVLT"
    assert HEADER_FIXED_SIZE == 40
    assert WRAPPED_DEK_LEN == 60
    assert HEADER_SIZE_KEM1 == 100
    assert (SALT_LEN, NONCE_PREFIX_LEN, NONCE_LEN) == (16, 7, 12)


def test_field_layout_is_contiguous_and_complete():
    """FIELD_LAYOUT 是線格式的機讀轉錄——不得有洞、不得重疊、總長恰 100。"""
    cursor = 0
    for name, offset, size in FIELD_LAYOUT:
        assert offset == cursor, f"{name} 的 offset 與前一欄不接續"
        cursor += size
    assert cursor == HEADER_SIZE_KEM1
    assert [name for name, _, _ in FIELD_LAYOUT] == [
        name for name, _ in GOLDEN_FIELDS
    ]


def test_serialize_matches_literal_wire_layout(raw):
    """逐欄依 ADR-001,多位元組整數一律 big-endian。"""
    assert len(raw) == HEADER_SIZE_KEM1
    assert raw == GOLDEN_RAW
    # 再逐欄斷言一次:整段相等若失敗,這裡直接指出是哪一欄。
    for name, hexpart in GOLDEN_FIELDS:
        expected = bytes.fromhex(hexpart)
        assert raw[OFF[name] : OFF[name] + SIZE[name]] == expected, name


def test_multibyte_fields_are_big_endian(raw):
    assert raw[OFF["chunk_size"] : OFF["chunk_size"] + 4] == (65536).to_bytes(4, "big")
    assert raw[OFF["wrapped_dek_len"] : OFF["wrapped_dek_len"] + 2] == (60).to_bytes(
        2, "big"
    )


# ---------------------------------------------------------------- round-trip


def test_roundtrip_structural_equality(raw):
    header, body_offset = deserialize(raw)
    assert header == make_header()
    assert body_offset == HEADER_SIZE_KEM1
    assert header.serialize() == raw


def test_roundtrip_over_parameter_space():
    for log2n in range(KDF_LOG2N_RANGE[0], KDF_LOG2N_RANGE[1] + 1):
        for chunk_size in (4096, 65536, 1048576):
            header = make_header(kdf_log2n=log2n, chunk_size=chunk_size)
            got, off = deserialize(header.serialize())
            assert got == header and off == HEADER_SIZE_KEM1


def test_body_bytes_are_untouched(raw):
    body = b"\xde\xad\xbe\xef" * 100
    header, body_offset = deserialize(raw + body)
    assert body_offset == HEADER_SIZE_KEM1
    assert (raw + body)[body_offset:] == body
    assert header == make_header()


def test_deserialize_accepts_bytes_like(raw):
    for view in (bytearray(raw), memoryview(raw)):
        header, off = deserialize(view)
        assert header == make_header() and off == HEADER_SIZE_KEM1


# ---------------------------------------------------------------- [H5] AAD 位元組界


def test_aad_is_full_serialize_output(raw):
    """AAD == serialize() 全段 == raw[:body_offset],含 wrapped_dek(決策 12)。"""
    header, body_offset = deserialize(raw + b"body bytes follow")
    aad = header.aad()
    assert aad == raw[:body_offset]
    assert len(aad) == 40 + 60 == body_offset
    assert aad == header.serialize()
    assert header.body_offset == body_offset
    # 「含 wrapped_dek」要能證偽:AAD 尾端就是 wrapped_dek。
    assert aad[-WRAPPED_DEK_LEN:] == WRAPPED_DEK


# ---------------------------------------------------------------- magic / version


@pytest.mark.parametrize(
    "bad", [b"QVLt", b"qvlt", b"\x00\x00\x00\x00", b"ZIP\x04", b"QVL\x00"]
)
def test_bad_magic_raises_format_error(raw, bad):
    with pytest.raises(QVaultFormatError):
        deserialize(splice(raw, OFF["magic"], bad))


@pytest.mark.parametrize("bad_version", [0, 2, 3, 127, 255])
def test_unknown_version_raises_version_error(raw, bad_version):
    with pytest.raises(QVaultVersionError):
        deserialize(splice(raw, OFF["version"], bytes([bad_version])))


def test_bad_magic_wins_over_bad_version(raw):
    """招牌都不對就不必談版本——先 FormatError。"""
    broken = splice(splice(raw, OFF["magic"], b"XXXX"), OFF["version"], b"\x63")
    with pytest.raises(QVaultFormatError):
        deserialize(broken)


# ---------------------------------------------------------------- [H1] 界限檢查

_ONE_BYTE_BOUNDS = [
    ("kdf_id", 0),
    ("kdf_id", 2),
    ("kdf_id", 255),
    ("aead_id", 0),
    ("aead_id", 2),
    ("aead_id", 255),
    ("kem_id", 0),
    ("kem_id", 2),  # P1 的 ML-KEM:P0 不得靜默接受
    ("kem_id", 3),  # P1 的 hybrid:同上
    ("kem_id", 255),
    ("kdf_log2n", 0),
    ("kdf_log2n", KDF_LOG2N_RANGE[0] - 1),
    ("kdf_log2n", KDF_LOG2N_RANGE[1] + 1),
    ("kdf_log2n", 63),
    ("kdf_log2n", 255),
    ("kdf_r", KDF_R_RANGE[0] - 1),
    ("kdf_r", KDF_R_RANGE[1] + 1),
    ("kdf_r", 255),
    ("kdf_p", KDF_P_RANGE[0] - 1),
    ("kdf_p", KDF_P_RANGE[1] + 1),
    ("kdf_p", 255),
]


@pytest.mark.parametrize("field,value", _ONE_BYTE_BOUNDS)
def test_single_byte_field_bounds(raw, field, value):
    with pytest.raises(QVaultFormatError):
        deserialize(splice(raw, OFF[field], bytes([value])))


@pytest.mark.parametrize("field,value", [("kdf_id", 1), ("aead_id", 1), ("kem_id", 1)])
def test_known_ids_accepted(raw, field, value):
    deserialize(splice(raw, OFF[field], bytes([value])))


@pytest.mark.parametrize(
    "chunk_size",
    [
        0,
        1,
        4095,
        4097,  # 範圍內但非 2 的冪
        65535,
        100000,
        CHUNK_SIZE_RANGE[1] + 1,
        2097152,  # 2 的冪但超過上限
        0xFFFFFFFF,  # AC 點名
    ],
)
def test_chunk_size_bounds(raw, chunk_size):
    with pytest.raises(QVaultFormatError):
        deserialize(splice(raw, OFF["chunk_size"], chunk_size.to_bytes(4, "big")))


@pytest.mark.parametrize("chunk_size", [4096, 8192, 65536, 524288, 1048576])
def test_chunk_size_accepted(raw, chunk_size):
    header, _ = deserialize(
        splice(raw, OFF["chunk_size"], chunk_size.to_bytes(4, "big"))
    )
    assert header.chunk_size == chunk_size


@pytest.mark.parametrize("declared", [0, 1, 32, 59, 61, 100, 0xFFFF])
def test_wrapped_dek_len_must_be_60(raw, declared):
    """kem_id=1 → wrapped_dek 恆 60B。宣告 61 時就算後面真的補了位元組也要拒絕。"""
    bad = splice(raw, OFF["wrapped_dek_len"], declared.to_bytes(2, "big"))
    with pytest.raises(QVaultFormatError):
        deserialize(bad + b"\x00" * 64)


def test_bounds_checked_before_scrypt(monkeypatch, raw):
    """[H1] `kdf_log2n=63` → 立刻 QVaultFormatError,且 `Scrypt` 從未被呼叫。

    容器層本來就不 import cryptography;monkeypatch 是為了把「沒呼叫」變成
    **可證偽**的斷言,而不是靠讀碼相信。
    """
    scrypt_mod = pytest.importorskip("cryptography.hazmat.primitives.kdf.scrypt")
    calls: list[tuple] = []

    class ExplodingScrypt:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("Scrypt 不得在界限檢查之前被建構")

    monkeypatch.setattr(scrypt_mod, "Scrypt", ExplodingScrypt)

    with pytest.raises(QVaultFormatError):
        deserialize(splice(raw, OFF["kdf_log2n"], b"\x3f"))  # 63
    with pytest.raises(QVaultFormatError):
        deserialize(splice(raw, OFF["chunk_size"], b"\xff\xff\xff\xff"))
    assert calls == []


def test_hostile_60_byte_file_is_cheap(raw):
    """決策 15 的那個例子:60 byte 的畸形檔不得換來一次 Scrypt(n=2**63)。"""
    hostile = splice(raw, OFF["kdf_log2n"], b"\x3f")[:60]
    started = time.monotonic()
    with pytest.raises(QVaultFormatError):
        deserialize(hostile)
    assert time.monotonic() - started < 1.0


def test_bounds_enforced_on_serialize_too():
    """serialize 不得吐出一個自己 deserialize 不回來的 header。"""
    cases = [
        (dict(magic=b"XXXX"), QVaultFormatError),
        (dict(magic=b"QVL"), QVaultFormatError),
        (dict(version=2), QVaultVersionError),
        (dict(kdf_id=2), QVaultFormatError),
        (dict(aead_id=0), QVaultFormatError),
        (dict(kem_id=2), QVaultFormatError),
        (dict(kdf_log2n=13), QVaultFormatError),
        (dict(kdf_log2n=23), QVaultFormatError),
        (dict(kdf_r=0), QVaultFormatError),
        (dict(kdf_p=17), QVaultFormatError),
        (dict(chunk_size=0), QVaultFormatError),
        (dict(chunk_size=65535), QVaultFormatError),
        (dict(chunk_size=0xFFFFFFFF), QVaultFormatError),
        (dict(chunk_size=2**40), QVaultFormatError),  # 溢位 uint32,不得漏出 struct.error
        (dict(salt=b"\x00" * 15), QVaultFormatError),
        (dict(salt=b"\x00" * 17), QVaultFormatError),
        (dict(salt="not bytes"), QVaultFormatError),
        (dict(nonce_prefix=b"\x00" * 6), QVaultFormatError),
        (dict(nonce_prefix=b"\x00" * 8), QVaultFormatError),
        (dict(wrapped_dek=b"\x00" * 59), QVaultFormatError),
        (dict(wrapped_dek=b"\x00" * 61), QVaultFormatError),
        (dict(wrapped_dek=None), QVaultFormatError),
        (dict(kdf_r="8"), QVaultFormatError),
        (dict(kdf_r=True), QVaultFormatError),
        (dict(version=None), QVaultVersionError),
    ]
    for overrides, expected in cases:
        header = dataclasses.replace(make_header(), **overrides)
        with pytest.raises(expected):
            header.serialize()


# ---------------------------------------------------------------- 截斷 / 逐欄竄改


def test_truncation_at_every_length_raises(raw):
    """輸入截斷 → QVaultFormatError(或版本先爆)——不得外洩 struct.error/IndexError。"""
    for n in range(HEADER_SIZE_KEM1):
        with pytest.raises((QVaultFormatError, QVaultVersionError)) as caught:
            deserialize(raw[:n])
        assert isinstance(caught.value, QVaultError)
    deserialize(raw)  # 恰好 100 byte 就該成功


def test_truncation_at_every_field_boundary(raw):
    """逐欄截一次:每個欄位的起點都是一個截斷點。"""
    for name, offset, _size in FIELD_LAYOUT:
        if offset == 0:
            continue
        with pytest.raises((QVaultFormatError, QVaultVersionError)):
            deserialize(raw[:offset])


def test_every_byte_flip_raises_or_changes_header(raw):
    """逐位元組改一次:要嘛 raise,要嘛解出**不同的** header。

    「既不 raise、解出來又跟原本相等」= 該 byte 被靜默忽略,那就是一個實作可以
    偷偷藏東西、或竄改被無視的洞。100 個 offset 一個都不放過。
    """
    original = make_header()
    for offset in range(HEADER_SIZE_KEM1):
        mutated = splice(raw, offset, bytes([raw[offset] ^ 0xFF]))
        try:
            header, body_offset = deserialize(mutated)
        except (QVaultFormatError, QVaultVersionError):
            continue
        assert header != original, f"offset {offset} 的變動被靜默忽略"
        assert body_offset == HEADER_SIZE_KEM1
        assert header.serialize() == mutated


def test_each_field_has_a_mutation_that_raises(raw):
    """AC「每欄位各改一次都 raise」——逐欄給一個必 raise 的改法。

    `salt` / `nonce_prefix` / `wrapped_dek` 是不透明位元組,任何 16/7/60 byte 值
    在**容器層**都合法,對它們「改一 byte 必 raise」在這一層無從實現;能在這層
    釘死的是「長度不符必 raise」。改一 byte 的偵測靠 header 作 AAD(決策 6/12),
    在 #2/#4 的 tamper 測試落地——本檔的 test_every_byte_flip_raises_or_changes_header
    已先證明那一 byte 確實進了 AAD(解出的 header 不同 → AAD 不同)。
    """
    raising = {
        "magic": splice(raw, OFF["magic"], b"XXXX"),
        "version": splice(raw, OFF["version"], b"\x02"),
        "kdf_id": splice(raw, OFF["kdf_id"], b"\x02"),
        "aead_id": splice(raw, OFF["aead_id"], b"\x02"),
        "kem_id": splice(raw, OFF["kem_id"], b"\x02"),
        "kdf_log2n": splice(raw, OFF["kdf_log2n"], b"\x3f"),
        "kdf_r": splice(raw, OFF["kdf_r"], b"\x00"),
        "kdf_p": splice(raw, OFF["kdf_p"], b"\x00"),
        "chunk_size": splice(raw, OFF["chunk_size"], b"\xff\xff\xff\xff"),
        "wrapped_dek_len": splice(raw, OFF["wrapped_dek_len"], b"\x00\x3b"),
        # 長度不符:三個不透明欄位在容器層唯一可判的錯法。
        "salt": raw[: OFF["salt"] + 1],
        "nonce_prefix": raw[: OFF["nonce_prefix"] + 1],
        "wrapped_dek": raw[:-1],
    }
    assert set(raising) == {name for name, _, _ in FIELD_LAYOUT}
    for name, mutated in raising.items():
        with pytest.raises((QVaultFormatError, QVaultVersionError)):
            deserialize(mutated)


@pytest.mark.parametrize(
    "junk", [b"", b"\x00", b"not a qvt file at all", b"QVL", b"QVLT"]
)
def test_short_junk_inputs(junk):
    with pytest.raises((QVaultFormatError, QVaultVersionError)):
        deserialize(junk)


@pytest.mark.parametrize("bad", [None, 42, "QVLT", ["QVLT"], object()])
def test_non_bytes_input_raises_format_error(bad):
    with pytest.raises(QVaultFormatError):
        deserialize(bad)


# ---------------------------------------------------------------- fuzz


def _fuzz_inputs(rng: random.Random, valid: bytes, count: int):
    """隨機 + 半合法的位元組串——半合法那幾種才逼得出界限檢查的洞。"""
    for i in range(count):
        mode = i % 4
        if mode == 0:  # 純隨機
            yield rng.randbytes(rng.randrange(0, 513))
        elif mode == 1:  # 合法 magic + 隨機尾巴
            yield MAGIC + rng.randbytes(rng.randrange(0, 509))
        elif mode == 2:  # 合法 header 上打 1..8 個隨機洞
            data = bytearray(valid)
            for _ in range(rng.randrange(1, 9)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            if rng.random() < 0.3:
                del data[rng.randrange(len(data)) :]
            yield bytes(data)
        else:  # 合法 header 隨機截斷 / 隨機加尾
            data = valid[: rng.randrange(0, len(valid) + 1)]
            yield data + rng.randbytes(rng.randrange(0, 64))


def test_fuzz_only_raises_qvault_errors():
    """[H1] fuzz:10,000 筆長度 0–512 的輸入,**只允許** Format/Version 兩種例外。

    出現 struct.error / MemoryError / OverflowError / UnicodeDecodeError 或掛住即失敗。
    seed 寫死 → 失敗可重現。
    """
    rng = random.Random(20260904)
    valid = make_header().serialize()
    started = time.monotonic()
    for index, data in enumerate(_fuzz_inputs(rng, valid, 10_000)):
        assert 0 <= len(data) <= 512
        try:
            header, body_offset = deserialize(data)
        except (QVaultFormatError, QVaultVersionError):
            continue
        except Exception as exc:  # noqa: BLE001 —— 這就是本測試要抓的東西
            pytest.fail(
                f"fuzz case #{index} (len={len(data)}) 丟出 "
                f"{type(exc).__name__}:{exc!r};只允許 QVaultFormatError/QVaultVersionError"
            )
        # 解得出來就必須是自洽的:body_offset 對得上、可原樣序列化回去。
        assert body_offset == HEADER_SIZE_KEM1
        assert header.serialize() == data[:body_offset]
    elapsed = time.monotonic() - started
    assert elapsed < 30, f"10,000 筆 fuzz 花了 {elapsed:.1f}s——疑似掛住"


# ---------------------------------------------------------------- [M1] nonce KAT


def test_nonce_kat_literals():
    """KAT 一律字面值——由實作輸出反推的話,欄位錯序也會「KAT 通過」。"""
    assert nonce_for(bytes(range(7)), 0, False) == bytes.fromhex(
        "000102030405060000000000"
    )
    assert nonce_for(bytes(range(7)), 1, True) == bytes.fromhex(
        "000102030405060000000101"
    )
    assert nonce_for(b"\xaa" * 7, 258, False) == bytes.fromhex(
        "aaaaaaaaaaaaaa0000010200"
    )


def test_nonce_counter_is_big_endian():
    """258 = 0x0102:大端 `00 00 01 02`,小端會是 `02 01 00 00`。"""
    assert nonce_for(b"\x00" * 7, 258, False)[7:11] == b"\x00\x00\x01\x02"
    assert nonce_for(b"\x00" * 7, MAX_CHUNK_INDEX, True)[7:11] == b"\xff\xff\xff\xff"


def test_nonce_length_is_always_12():
    for index in (0, 1, 255, 256, 65535, 2**31, MAX_CHUNK_INDEX):
        for is_last in (False, True):
            nonce = nonce_for(b"\x11" * 7, index, is_last)
            assert len(nonce) == NONCE_LEN == 12
            assert nonce[:7] == b"\x11" * 7
            assert nonce[11] == (0x01 if is_last else 0x00)


@pytest.mark.parametrize("index", [2**32, 2**32 + 1, 2**64, -1, -(2**40)])
def test_nonce_index_out_of_range_raises(index):
    with pytest.raises(ValueError):
        nonce_for(b"\x00" * 7, index, False)


@pytest.mark.parametrize("prefix", [b"", b"\x00" * 6, b"\x00" * 8, b"\x00" * 12, None, "1234567"])
def test_nonce_prefix_must_be_7_bytes(prefix):
    with pytest.raises(ValueError):
        nonce_for(prefix, 0, False)


def test_nonces_never_repeat_within_a_file():
    """不變式①:同一 prefix 下 (index, flag) 決定 nonce,計數器單調 → 不重用。"""
    prefix = b"\x5a" * 7
    nonces = [nonce_for(prefix, i, i == 999) for i in range(1000)]
    assert len(set(nonces)) == 1000
    # 末塊 flag 改變也會換一支 nonce:同一 index 的 flag=0/1 不得撞。
    assert nonce_for(prefix, 7, False) != nonce_for(prefix, 7, True)


# ---------------------------------------------------------------- [H3] 空檔正規佈局


def test_empty_file_body_is_chunk0_only():
    """orig_size == 0 → body 只有 chunk 0,且其 flag == 0x01;禁止補零長度資料塊。"""
    assert body_chunk_count(0, 65536) == 1
    last_index = body_chunk_count(0, 65536) - 1
    assert last_index == 0
    assert nonce_for(b"\x02" * 7, last_index, True)[11] == 0x01


@pytest.mark.parametrize(
    "orig_size,chunk_size,expected",
    [
        (0, 4096, 1),  # 空檔:只有 chunk 0
        (1, 4096, 2),
        (4095, 4096, 2),
        (4096, 4096, 2),  # 剛好整除:不補空塊
        (4097, 4096, 3),
        (65536 * 4, 65536, 5),
        (65536 * 4 + 1, 65536, 6),
    ],
)
def test_body_chunk_count(orig_size, chunk_size, expected):
    assert body_chunk_count(orig_size, chunk_size) == expected


@pytest.mark.parametrize(
    "orig_size,chunk_size",
    [(-1, 65536), (0, 0), (0, 4095), (0, 65535), (0, 2**32), (None, 65536), (0, None)],
)
def test_body_chunk_count_rejects_bad_input(orig_size, chunk_size):
    with pytest.raises(QVaultFormatError):
        body_chunk_count(orig_size, chunk_size)


# ---------------------------------------------------------------- 鐵律 / 衛生


def test_header_repr_hides_salt_nonce_prefix_and_wrapped_dek():
    """決策 20:wrapped DEK 進了 log/工單,攻擊者不需檔案就能離線爆密碼。"""
    header = make_header()
    for text in (repr(header), str(header), f"{header}"):
        assert SALT.hex() not in text
        assert NONCE_PREFIX.hex() not in text
        assert WRAPPED_DEK.hex() not in text
        assert "\\x" not in text
        assert "version=1" in text and "chunk_size=65536" in text


def test_header_is_frozen():
    header = make_header()
    with pytest.raises(dataclasses.FrozenInstanceError):
        header.chunk_size = 4096


def test_header_has_no_default_secrets():
    """salt / nonce_prefix / wrapped_dek 不得有預設值——預設值就是常數 salt(決策 10)。"""
    required = {
        f.name
        for f in dataclasses.fields(QVaultHeader)
        if f.default is dataclasses.MISSING
        and f.default_factory is dataclasses.MISSING
    }
    assert required == {"salt", "nonce_prefix", "wrapped_dek"}


def _package_sources() -> list[pathlib.Path]:
    return sorted(pathlib.Path("qvault_core").rglob("*.py"))


def test_no_import_random_in_package():
    """決策 20:隨機來源限 `secrets`,`qvault_core/` 內禁止 `import random`。"""
    assert _package_sources(), "找不到 qvault_core 原始碼"
    for path in _package_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            assert "random" not in names, f"{path} 匯入了 random"


def test_container_is_stdlib_only():
    """AC:只用 stdlib(struct/dataclasses);**不碰加密**(那是 #2)。"""
    tree = ast.parse(pathlib.Path("qvault_core/container.py").read_text("utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." if node.level else (node.module or "").split(".")[0])
    assert imported <= {"struct", "dataclasses", "__future__", "."}, imported
