"""檔案層的測試(AC #4;設計見 ADR-001 決策 5/9/12/13/14/16/17/20/21)。

三類必備測試(AGENTS.md 鐵律 4)在本檔的落點:
  round-trip → `test_roundtrip_*`(空檔、剛好整除、跨多塊、大檔、非 ASCII 檔名)
  tamper     → `test_tampered_*` / `test_truncated_*` / `test_wrong_passphrase_*`
  邊界       → 0 位元組、1 位元組、剛好一塊、255B 檔名、只留 header、只留 chunk 0

外加 **golden file**(`test_golden_*`):把 v1 的位元佈局逐位元組凍結,任何「自己
跟自己自洽」的格式漂移(chunk 0 補零改成補 0xff、AAD 少含 wrapped_dek、nonce
flag 反過來)都只有它擋得住。

**測試用的低成本 KDF**(`fast_kdf`)只換掉 `kek._scrypt` 這一個函式,`log2n/r/p`
與 header 欄位全部維持正規值——這樣測試跑得快,而 [M3]「解密讀 header 參數」
與 [M2] golden 兩條仍走**真正的** scrypt(那兩條刻意不吃這個夾具)。
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import logging
import os
import pathlib
import secrets
import stat
import tracemalloc

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qvault_core import aead as aead_mod
from qvault_core import kek as kek_mod
from qvault_core import vault as vault_mod
from qvault_core.aead import TAG_LEN, seal
from qvault_core.container import (
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE_KEM1,
    NONCE_PREFIX_LEN,
    SALT_LEN,
    QVaultHeader,
    deserialize,
    nonce_for,
)
from qvault_core.errors import (
    QVaultDecryptError,
    QVaultFormatError,
    QVaultVersionError,
)
from qvault_core.kek import SCRYPT_LOG2N, SCRYPT_P, SCRYPT_R, ScryptKEK
from qvault_core.vault import (
    CHUNK0_PLAINTEXT_LEN,
    CHUNK0_SEALED_LEN,
    MAX_NAME_BYTES,
    WINDOWS_RESERVED_NAMES,
    _sanitize_name,
    decrypt_file,
    encrypt_file,
)

# ---------------------------------------------------------------- 夾具與工具

PW = "correct horse battery staple"
MARKER_PW = "S3cr3t-pw-marker"
SMALL = 4096  # 合法的最小 chunk_size:五塊檔只要 ~16KB,不必生 320KB
FIXED_SALT = b"\x01" * SALT_LEN
FIXED_PREFIX = b"\x02" * NONCE_PREFIX_LEN
FIXED_DEK = b"\x03" * 32
FIXED_WRAP_NONCE = b"\x04" * 12


@pytest.fixture
def fast_kdf(monkeypatch):
    """把 scrypt 換成一個便宜但**參數敏感**的派生,讓測試不必每次燒 80ms。

    參數敏感是重點:`n`/`r`/`p`/`salt`/密碼任一不同就派生出不同的 KEK,所以
    「解密拿錯參數」這類錯誤照樣會現形。真正的 scrypt 正確性由 #3 的 RFC 7914
    向量保證,不是本票的事;而 [M2]/[M3] 兩條**不用**這個夾具。
    """

    def cheap(passphrase_bytes, salt, *, n, r, p, dklen=32):
        material = b"|".join(
            [passphrase_bytes, salt, str(n).encode(), str(r).encode(), str(p).encode()]
        )
        return hashlib.sha256(material).digest()[:dklen]

    monkeypatch.setattr(kek_mod, "_scrypt", cheap)


def make_file(directory: pathlib.Path, name: str, size: int) -> pathlib.Path:
    """生一個 `size` 位元組、內容逐位置相異的輸入檔(錯序/重排會現形)。"""
    path = directory / name
    pattern = bytes(range(256))
    body = (pattern * (size // 256 + 1))[:size]
    path.write_bytes(body)
    return path


def split_body(raw: bytes, chunk_size: int) -> tuple[bytes, list[bytes]]:
    """把 `.qvt` 切成 `(header, [chunk0, chunk1, ...])`——竄改測試的手術刀。

    切法**刻意與實作無關**:chunk 0 恆 `CHUNK0_SEALED_LEN`,其餘每塊
    `chunk_size + TAG_LEN`(末塊可短)。它同時也是「界線可由公開資訊推導」
    這條設計主張的獨立驗證——測試自己就能切,不必問實作。
    """
    _, body_offset = deserialize(raw)
    body = raw[body_offset:]
    parts: list[bytes] = []
    pos = 0
    while pos < len(body):
        limit = CHUNK0_SEALED_LEN if not parts else chunk_size + TAG_LEN
        take = min(limit, len(body) - pos)
        parts.append(body[pos : pos + take])
        pos += take
    return raw[:body_offset], parts


def build_qvt(
    path: pathlib.Path,
    *,
    name: bytes,
    data: bytes = b"",
    passphrase: str = PW,
    salt: bytes = FIXED_SALT,
    prefix: bytes = FIXED_PREFIX,
    dek: bytes = FIXED_DEK,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    log2n: int = 14,
    r: int = 8,
    p: int = 1,
    chunk0: bytes | None = None,
) -> pathlib.Path:
    """**測試自己的**編碼器:能造出 `encrypt_file` 拒絕產生的檔(惡意檔名等)。

    這是 [C4] 那十個夾具唯一的生法——`encrypt_file` 兩端套同一份淨化規則,
    不可能寫出內嵌 `"../../evil"` 的 `.qvt`,而 Zip Slip 的威脅模型本來就是
    「**別人**寄來的檔」。順帶當成格式的第二條獨立實作:
    `test_handmade_encoder_matches_encrypt_file` 把兩者釘在一起。
    """
    kek = ScryptKEK(passphrase, salt, log2n=log2n, r=r, p=p)
    header = QVaultHeader(
        salt=salt,
        nonce_prefix=prefix,
        wrapped_dek=kek.wrap(dek),
        chunk_size=chunk_size,
        kdf_log2n=log2n,
        kdf_r=r,
        kdf_p=p,
    )
    aad = header.serialize()
    if chunk0 is None:
        meta = len(name).to_bytes(2, "big") + name + len(data).to_bytes(8, "big")
        chunk0 = meta + bytes(CHUNK0_PLAINTEXT_LEN - len(meta))
    count = 1 + (len(data) + chunk_size - 1) // chunk_size
    blobs = [aad, seal(dek, nonce_for(prefix, 0, count == 1), chunk0, aad)]
    for index in range(1, count):
        block = data[(index - 1) * chunk_size : index * chunk_size]
        blobs.append(
            seal(dek, nonce_for(prefix, index, index == count - 1), block, aad)
        )
    path.write_bytes(b"".join(blobs))
    return path


def leftovers(directory: pathlib.Path) -> list[str]:
    """目錄裡的**全部**條目(含隱藏檔)——暫存檔叫 `.qvault-*`,故不能只看 glob。"""
    return sorted(entry.name for entry in directory.iterdir())


# ---------------------------------------------------------------- round-trip


@pytest.mark.parametrize(
    "size",
    [
        0,  # 空檔:body 只有 chunk 0,且它就是末塊(決策 14 / [H3])
        1,
        SMALL - 1,
        SMALL,  # 剛好整除
        SMALL + 1,
        SMALL * 5,  # 剛好整除、跨多塊
        SMALL * 5 + 7,
    ],
)
def test_roundtrip_over_sizes(tmp_path, fast_kdf, size):
    """round-trip:空檔 / 剛好整除 / 跨多塊,內容與檔名都要原封不動。"""
    src = make_file(tmp_path, "payload.bin", size)
    out = tmp_path / "payload.bin.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)

    dest = tmp_path / "restored"
    dest.mkdir()
    got = decrypt_file(out, dest, PW)

    assert got == dest / "payload.bin"  # 原檔名還原正確
    assert got.read_bytes() == src.read_bytes()


def test_roundtrip_with_default_chunk_size_across_chunks(tmp_path, fast_kdf):
    """預設 64 KiB 分塊也要跨得過去(SMALL 只是為了測試跑得快)。"""
    src = make_file(tmp_path, "big.bin", DEFAULT_CHUNK_SIZE * 2 + 123)
    out = tmp_path / "big.qvt"
    encrypt_file(src, out, PW)
    dest = tmp_path / "out"
    dest.mkdir()
    assert decrypt_file(out, dest, PW).read_bytes() == src.read_bytes()


def test_roundtrip_with_production_scrypt(tmp_path):
    """不吃 `fast_kdf`:正規 15/8/1 的完整一趟(慢,但一定要有一條真的跑)。"""
    src = make_file(tmp_path, "prod.bin", 3 * SMALL)
    out = tmp_path / "prod.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header, _ = deserialize(out.read_bytes())
    assert (header.kdf_log2n, header.kdf_r, header.kdf_p) == (
        SCRYPT_LOG2N,
        SCRYPT_R,
        SCRYPT_P,
    )
    dest = tmp_path / "out"
    dest.mkdir()
    assert decrypt_file(out, dest, PW).read_bytes() == src.read_bytes()


@pytest.mark.parametrize("name", ["a", "檔案 名-2024.txt", "🔒.bin", "x" * 255])
def test_roundtrip_preserves_the_original_name(tmp_path, fast_kdf, name):
    """原檔名還原正確:非 ASCII、空白、255 位元組上限都要走得通。"""
    src = tmp_path / name
    src.write_bytes(b"payload")
    out = tmp_path / "n.qvt"
    encrypt_file(src, out, PW)
    dest = tmp_path / "out"
    dest.mkdir()
    got = decrypt_file(out, dest, PW)
    assert got.name == name
    assert got.read_bytes() == b"payload"


def test_encrypt_file_returns_the_output_path(tmp_path, fast_kdf):
    src = make_file(tmp_path, "r.bin", 10)
    out = tmp_path / "r.qvt"
    assert encrypt_file(src, out, PW) == out


def test_qvt_never_contains_the_plaintext(tmp_path, fast_kdf):
    """最基本的一條:密文裡不得出現明文,也不得出現原檔名。"""
    src = tmp_path / "secret-name.txt"
    src.write_bytes(b"ATTACK AT DAWN" * 64)
    out = tmp_path / "c.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    raw = out.read_bytes()
    assert b"ATTACK AT DAWN" not in raw
    assert b"secret-name" not in raw
    assert PW.encode() not in raw


# ---------------------------------------------------------------- [C1] 每檔隨機


def test_two_encryptions_of_the_same_input_differ_everywhere(tmp_path, fast_kdf):
    """[C1] 同密碼、同內容、同檔名加密兩次 → 四者皆不同。

    這一條同時擋掉常數 salt、DEK 重用、nonce_prefix 派生三種錯法:只要其中
    任何一個由「密碼/內容/檔名」派生,對應的欄位就會相等。
    """
    src = make_file(tmp_path, "same.bin", 3 * SMALL)
    first = tmp_path / "a.qvt"
    second = tmp_path / "b.qvt"
    encrypt_file(src, first, PW, chunk_size=SMALL)
    encrypt_file(src, second, PW, chunk_size=SMALL)

    h1, off1 = deserialize(first.read_bytes())
    h2, off2 = deserialize(second.read_bytes())
    assert h1.salt != h2.salt
    assert h1.nonce_prefix != h2.nonce_prefix
    assert h1.wrapped_dek != h2.wrapped_dek
    assert first.read_bytes()[off1:] != second.read_bytes()[off2:]
    # 位元組數必須一樣——差別只能在金鑰材料,不能在長度(長度會洩內容)。
    assert first.stat().st_size == second.stat().st_size


def test_salt_and_prefix_come_from_secrets_token_bytes(tmp_path, monkeypatch, fast_kdf):
    """[C1] salt 與 nonce_prefix 的來源必須是 `secrets.token_bytes`(決策 20)。

    斷言的是**呼叫參數**:`token_bytes(16)`(salt)與 `token_bytes(7)`(prefix)
    都要出現。派生自密碼/時間/雜湊的實作根本不會呼叫它。
    """
    sizes: list[int] = []
    real = secrets.token_bytes

    def spy(size):
        sizes.append(size)
        return real(size)

    monkeypatch.setattr(secrets, "token_bytes", spy)
    src = make_file(tmp_path, "s.bin", 10)
    encrypt_file(src, tmp_path / "s.qvt", PW)
    assert SALT_LEN in sizes
    assert NONCE_PREFIX_LEN in sizes
    assert 32 in sizes  # gen_dek
    assert 12 in sizes  # ScryptKEK.wrap 的 wrap_nonce


def test_salt_is_not_derived_from_the_passphrase_or_the_name(tmp_path, fast_kdf):
    """同密碼 + 不同檔名 + 不同內容,salt 之間也不得有任何相等關係。"""
    salts = set()
    for i in range(8):
        src = tmp_path / f"n{i}.bin"
        src.write_bytes(bytes([i]) * 32)
        out = tmp_path / f"n{i}.qvt"
        encrypt_file(src, out, PW)
        header, _ = deserialize(out.read_bytes())
        salts.add(header.salt)
    assert len(salts) == 8


# ---------------------------------------------------------------- 加密流程


def test_header_fields_follow_the_spec(tmp_path, fast_kdf):
    """組出來的 header:三個 id、KDF 參數、chunk_size、salt/prefix 長度。"""
    src = make_file(tmp_path, "h.bin", 100)
    out = tmp_path / "h.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    raw = out.read_bytes()
    header, body_offset = deserialize(raw)

    assert body_offset == HEADER_SIZE_KEM1 == 100
    assert (header.version, header.kdf_id, header.aead_id, header.kem_id) == (1, 1, 1, 1)
    assert (header.kdf_log2n, header.kdf_r, header.kdf_p) == (
        SCRYPT_LOG2N,
        SCRYPT_R,
        SCRYPT_P,
    )
    assert header.chunk_size == SMALL
    assert len(header.salt) == SALT_LEN
    assert len(header.nonce_prefix) == NONCE_PREFIX_LEN
    assert len(header.wrapped_dek) == 60
    assert raw[:4] == b"QVLT"


def test_aad_is_the_whole_header_on_disk(tmp_path, monkeypatch, fast_kdf):
    """[H5] AAD 的位元組界 == `raw[:body_offset]`(**含 `wrapped_dek`**,決策 12)。

    這裡不繞路:拿固定的 DEK 直接用 `cryptography` 的 `AESGCM` 開 chunk 0,
    **只有**完整的 100B header 當 AAD 才開得起來。少一個位元組(99)、只取定長段
    (40)、或多接一個位元組都必須失敗——那正是「兩個實作各自 round-trip 全綠
    卻互不相容」的歧義點。
    """
    from cryptography.exceptions import InvalidTag

    fixed = {SALT_LEN: FIXED_SALT, NONCE_PREFIX_LEN: FIXED_PREFIX, 32: FIXED_DEK, 12: FIXED_WRAP_NONCE}
    monkeypatch.setattr(secrets, "token_bytes", lambda size: fixed[size])
    src = make_file(tmp_path, "aad.bin", 64)
    out = tmp_path / "aad.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    raw = out.read_bytes()
    header, body_offset = deserialize(raw)
    assert header.serialize() == raw[:body_offset] == raw[:HEADER_SIZE_KEM1]

    sealed0 = raw[body_offset : body_offset + CHUNK0_SEALED_LEN]
    nonce0 = nonce_for(FIXED_PREFIX, 0, False)
    assert AESGCM(FIXED_DEK).decrypt(nonce0, sealed0, raw[:body_offset])
    for bad_aad in (raw[:40], raw[:body_offset - 1], raw[: body_offset + 1], b""):
        with pytest.raises(InvalidTag):
            AESGCM(FIXED_DEK).decrypt(nonce0, sealed0, bad_aad)


@pytest.mark.parametrize("pos", [11, 27, 40, HEADER_SIZE_KEM1 - 1])
def test_flipping_a_header_byte_breaks_decryption(tmp_path, fast_kdf, pos):
    """header 任一位元組改動 → raise、無殘留(salt / nonce_prefix / wrapped_dek)。"""
    src = make_file(tmp_path, "hdr.bin", 64)
    out = tmp_path / "hdr.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    broken = bytearray(out.read_bytes())
    broken[pos] ^= 0x01
    victim = tmp_path / "hdr-bad.qvt"
    victim.write_bytes(bytes(broken))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


@pytest.mark.parametrize("pos", [34, 35, 36, 37])
def test_flipping_the_chunk_size_is_a_format_error(tmp_path, fast_kdf, pos):
    """chunk_size 的任一位元組改動在 KDF **之前**就被擋(決策 15 / [H1])。

    它與上面那條的差別正是決策 15 的重點:緩衝區大小與 KDF 參數在 tag 被驗證
    之前就要被使用,所以它們走界限檢查(`QVaultFormatError`),不走 AEAD。
    """
    src = make_file(tmp_path, "cs.bin", 64)
    out = tmp_path / "cs.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    broken = bytearray(out.read_bytes())
    broken[pos] ^= 0x01
    victim = tmp_path / "cs-bad.qvt"
    victim.write_bytes(bytes(broken))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultFormatError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


def test_chunk_layout_on_disk(tmp_path, fast_kdf):
    """落盤佈局:header ‖ chunk0(4112B) ‖ 資料塊(chunk_size+16,末塊可短)。"""
    src = make_file(tmp_path, "l.bin", 2 * SMALL + 5)
    out = tmp_path / "l.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header_raw, parts = split_body(out.read_bytes(), SMALL)

    assert len(header_raw) == HEADER_SIZE_KEM1
    assert len(parts) == 4  # chunk0 + 3 個資料塊
    assert len(parts[0]) == CHUNK0_SEALED_LEN
    assert len(parts[1]) == len(parts[2]) == SMALL + TAG_LEN
    assert len(parts[3]) == 5 + TAG_LEN
    assert out.stat().st_size == HEADER_SIZE_KEM1 + sum(len(p) for p in parts)


def test_empty_file_body_is_chunk0_only(tmp_path, fast_kdf):
    """決策 14:空檔的 body **只有** chunk 0,且它以 flag=0x01 開啟。"""
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")
    out = tmp_path / "empty.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    _, parts = split_body(out.read_bytes(), SMALL)
    assert len(parts) == 1
    assert len(parts[0]) == CHUNK0_SEALED_LEN
    assert out.stat().st_size == HEADER_SIZE_KEM1 + CHUNK0_SEALED_LEN


def test_handmade_encoder_matches_encrypt_file(tmp_path, monkeypatch):
    """測試自己的編碼器與實作**逐位元組相等**(否則後面的夾具都在測別的東西)。"""
    fixed = {SALT_LEN: FIXED_SALT, NONCE_PREFIX_LEN: FIXED_PREFIX, 32: FIXED_DEK, 12: FIXED_WRAP_NONCE}
    monkeypatch.setattr(secrets, "token_bytes", lambda size: fixed[size])
    src = tmp_path / "pair.bin"
    payload = bytes(range(256)) * 40  # 10240B → 3 塊(SMALL=4096)
    src.write_bytes(payload)
    produced = encrypt_file(src, tmp_path / "impl.qvt", PW, chunk_size=SMALL)
    handmade = build_qvt(
        tmp_path / "hand.qvt",
        name=b"pair.bin",
        data=payload,
        chunk_size=SMALL,
        log2n=SCRYPT_LOG2N,
    )
    assert produced.read_bytes() == handmade.read_bytes()


# ---------------------------------------------------------------- [M5] chunk 0


def test_chunk0_plaintext_layout(tmp_path, monkeypatch, fast_kdf):
    """[M5] chunk 0 明文 = `name_len(2B BE) ‖ name ‖ orig_size(8B BE)` + 補零。"""
    fixed = {SALT_LEN: FIXED_SALT, NONCE_PREFIX_LEN: FIXED_PREFIX, 32: FIXED_DEK, 12: FIXED_WRAP_NONCE}
    monkeypatch.setattr(secrets, "token_bytes", lambda size: fixed[size])
    src = make_file(tmp_path, "meta.txt", 1234)
    out = tmp_path / "meta.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)

    raw = out.read_bytes()
    header, body_offset = deserialize(raw)
    plaintext = AESGCM(FIXED_DEK).decrypt(
        nonce_for(FIXED_PREFIX, 0, False),
        raw[body_offset : body_offset + CHUNK0_SEALED_LEN],
        raw[:body_offset],
    )
    assert len(plaintext) == CHUNK0_PLAINTEXT_LEN
    assert plaintext[:2] == (8).to_bytes(2, "big")
    assert plaintext[2:10] == b"meta.txt"
    assert plaintext[10:18] == (1234).to_bytes(8, "big")
    assert plaintext[18:] == bytes(CHUNK0_PLAINTEXT_LEN - 18)  # 補零,無隱藏通道


@pytest.mark.parametrize(
    "chunk0, reason",
    [
        (bytes([0xFF, 0xFF]) + bytes(CHUNK0_PLAINTEXT_LEN - 2), "name_len 遠大於剩餘長度"),
        (
            (CHUNK0_PLAINTEXT_LEN - 9).to_bytes(2, "big") + bytes(CHUNK0_PLAINTEXT_LEN - 2),
            "name_len 讓 orig_size 放不下(差一)",
        ),
        (bytes(CHUNK0_PLAINTEXT_LEN), "name_len == 0 → 空檔名"),
        (
            (4).to_bytes(2, "big") + b"good" + bytes(8) + b"\x01" + bytes(CHUNK0_PLAINTEXT_LEN - 15),
            "補零區不是零(隱藏通道)",
        ),
        ((4).to_bytes(2, "big") + b"good" + bytes(8), "chunk 0 明文沒有補滿 4096"),
    ],
)
def test_malformed_chunk0_raises_format_error(tmp_path, fast_kdf, chunk0, reason):
    """[M5] chunk 0 佈局不符 → `QVaultFormatError`(**不是**解密錯誤)。

    這些檔都通得過 AEAD 驗證(是我們自己用對的金鑰封的),所以擋下它們的只能是
    佈局檢查本身——「通過認證」不等於「可信」(決策 17)。
    """
    victim = build_qvt(tmp_path / "m.qvt", name=b"x", chunk0=chunk0)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultFormatError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == [], reason


def test_chunk0_declaring_more_data_than_exists(tmp_path, fast_kdf):
    """[H2] `orig_size` 說有 999 位元組、實際只有 3 → `QVaultDecryptError`。"""
    meta = (5).to_bytes(2, "big") + b"a.txt" + (999).to_bytes(8, "big")
    victim = build_qvt(
        tmp_path / "lie.qvt",
        name=b"a.txt",
        data=b"abc",
        chunk0=meta + bytes(CHUNK0_PLAINTEXT_LEN - len(meta)),
    )
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


# ---------------------------------------------------------------- [C3] 原子性


def test_tampered_middle_chunk_leaves_nothing_behind(tmp_path, fast_kdf):
    """[C3] 竄改 5 塊檔的第 2 塊 → raise,且目標不存在、目錄內無殘留暫存檔。

    這是 ADR-001 保證① 的核心:串流解密若邊解邊寫,raise 之前就已經把前 k 塊
    **未經完整驗證**的明文留在磁碟上,那是一個可控的部分解密原語。
    """
    src = make_file(tmp_path, "five.bin", 4 * SMALL)  # chunk0 + 4 資料塊
    out = tmp_path / "five.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header_raw, parts = split_body(out.read_bytes(), SMALL)
    assert len(parts) == 5

    broken = bytearray(parts[2])
    broken[0] ^= 0x80  # 第 2 塊(chunk index 2)的密文第一個位元組
    victim = tmp_path / "five-bad.qvt"
    victim.write_bytes(header_raw + parts[0] + parts[1] + bytes(broken) + b"".join(parts[3:]))

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert not (dest / "five.bin").exists()
    assert leftovers(dest) == []


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4])
def test_tampering_any_chunk_is_detected(tmp_path, fast_kdf, index):
    """每一塊(含 chunk 0、含末塊)各改一個位元組 → 一律 raise、一律無殘留。"""
    src = make_file(tmp_path, "t.bin", 4 * SMALL)
    out = tmp_path / "t.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header_raw, parts = split_body(out.read_bytes(), SMALL)

    mutated = list(parts)
    blob = bytearray(mutated[index])
    blob[-1] ^= 0x01  # 動 tag 的最後一個位元組
    mutated[index] = bytes(blob)
    victim = tmp_path / "t-bad.qvt"
    victim.write_bytes(header_raw + b"".join(mutated))

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


def test_no_temp_file_survives_a_failure_mid_stream(tmp_path, fast_kdf, monkeypatch):
    """暫存檔在**寫到一半**掛掉時也要被清掉(不只 AEAD 失敗那條路)。"""
    src = make_file(tmp_path, "io.bin", 4 * SMALL)
    out = tmp_path / "io.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    dest = tmp_path / "out"
    dest.mkdir()

    calls = {"n": 0}
    real_write = vault_mod._write_all

    def exploding(fd, data):
        calls["n"] += 1
        if calls["n"] == 3:  # 已經寫過兩塊明文了
            raise OSError("disk full")
        return real_write(fd, data)

    monkeypatch.setattr(vault_mod, "_write_all", exploding)
    with pytest.raises(OSError):
        decrypt_file(out, dest, PW)
    assert leftovers(dest) == []


def test_failed_encryption_leaves_no_partial_qvt(tmp_path, fast_kdf, monkeypatch):
    """加密中途失敗也不留半個 `.qvt`——半成品被誤認成保險庫是最糟的失敗模式。"""
    src = make_file(tmp_path, "e.bin", 4 * SMALL)
    real_write = vault_mod._write_all
    calls = {"n": 0}

    def exploding(fd, data):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk full")
        return real_write(fd, data)

    monkeypatch.setattr(vault_mod, "_write_all", exploding)
    with pytest.raises(OSError):
        encrypt_file(src, tmp_path / "e.qvt", PW, chunk_size=SMALL)
    assert leftovers(tmp_path) == ["e.bin"]


def test_decrypt_is_a_replace_not_an_in_place_write(tmp_path, fast_kdf, monkeypatch):
    """明文只能經由 `os.replace()` 落到目標路徑(決策 16)。

    直接 `open(target, "wb")` 的實作會讓「解到一半失敗」在目標路徑上留下截斷的
    明文;這裡把 `os.replace` 拆掉,斷言目標**始終沒有被建立過**。
    """
    src = make_file(tmp_path, "rep.bin", 2 * SMALL)
    out = tmp_path / "rep.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    dest = tmp_path / "out"
    dest.mkdir()

    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    with pytest.raises(OSError):
        decrypt_file(out, dest, PW)
    assert not (dest / "rep.bin").exists()


# ---------------------------------------------------------------- [C4] 檔名淨化

EVIL_NAMES = [
    b"../../evil",
    b"/etc/passwd",
    b"..",
    b".",
    b"a\x00b",
    b"a\x1fb",
    b"C:evil.txt",
    b"CON",
    b"com1.txt",
    b"x.txt:hidden",
    b"evil.txt.",
    b"evil.txt ",
    b"",
    b"sub/dir.txt",
    b"back\\slash.txt",
    b"\xff\xfe not utf-8",
    b"x" * 256,
    "CON".encode().lower(),
    b"nul.log",
    b"LPT9.txt",
    b"aux",
]


@pytest.mark.parametrize("name", EVIL_NAMES, ids=lambda n: repr(n))
def test_hostile_embedded_names_are_rejected(tmp_path, fast_kdf, name):
    """[C4] 惡意檔名一律 raise,且 `out_dir` 內外都不得有任何檔案被建立。

    **三平台都跑**:淨化規則平台無關(決策 21)——在 Linux 生出來的惡意檔,
    等到 Windows 才發作是最糟的組合,所以這裡沒有任何 `skipif`。
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = build_qvt(tmp_path / "evil.qvt", name=name, data=b"pwned")
    dest = tmp_path / "dest"
    dest.mkdir()

    with pytest.raises(QVaultFormatError):
        decrypt_file(victim, dest, PW)

    assert leftovers(dest) == []
    assert leftovers(outside) == []
    assert sorted(leftovers(tmp_path)) == ["dest", "evil.qvt", "outside"]
    assert not (tmp_path.parent / "evil").exists()


@pytest.mark.parametrize(
    "name",
    ["ok.txt", "CONSOLE.txt", "com0.txt", "com10.txt", ".hidden", "a.b.c", "-", "x" * 255],
)
def test_benign_names_survive_sanitisation(name):
    """淨化不得誤殺:`CONSOLE`/`com0`/`com10` 都**不是**保留裝置名。"""
    assert _sanitize_name(name.encode()) == name


@pytest.mark.parametrize("name", [b"con.txt", b"Con.TXT", b"PRN", b"aux.bin", b"lpt1.dat"])
def test_reserved_device_names_are_case_insensitive(name):
    with pytest.raises(QVaultFormatError):
        _sanitize_name(name)


def test_sanitize_never_echoes_the_name(tmp_path):
    """例外訊息不得回填檔名——攻擊者控制的字串進 log/工單就是注入面。"""
    marker = "MARKER-INJECTED-NAME"
    with pytest.raises(QVaultFormatError) as excinfo:
        _sanitize_name(f"../{marker}".encode())
    assert marker not in str(excinfo.value)


def test_name_length_limit_is_measured_in_bytes():
    """255 是**位元組**上限:85 個三位元組字元剛好 255,86 個就爆。"""
    assert len(_sanitize_name(("字" * 85).encode())) == 85
    with pytest.raises(QVaultFormatError):
        _sanitize_name(("字" * 86).encode())
    assert len(("字" * 86).encode()) == 258 > MAX_NAME_BYTES


def test_encrypt_refuses_a_name_it_could_not_restore(tmp_path, fast_kdf):
    """兩端同一套規則:寫不出一個自己解不開的 `.qvt`(見 `.asp/pr/4.md`)。"""
    src = tmp_path / "trailing."
    src.write_bytes(b"data")
    with pytest.raises(QVaultFormatError):
        encrypt_file(src, tmp_path / "x.qvt", PW)
    assert not (tmp_path / "x.qvt").exists()


def test_symlinked_target_is_refused(tmp_path, fast_kdf):
    """`out_dir/name` 是一條指向外面的符號連結 → 拒絕(realpath 檢查)。"""
    src = tmp_path / "link-me.txt"
    src.write_bytes(b"payload")
    out = tmp_path / "link.qvt"
    encrypt_file(src, out, PW)

    dest = tmp_path / "dest"
    dest.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"original")
    (dest / "link-me.txt").symlink_to(outside)

    with pytest.raises(QVaultFormatError):
        decrypt_file(out, dest, PW, force=True)
    assert outside.read_bytes() == b"original"


def test_dangling_symlink_target_is_refused(tmp_path, fast_kdf):
    """**斷掉的**符號連結:`exists()` 是 False(它跟著連結走),所以「目標已存在」
    那道檢查放行——擋下它的只能是 realpath。攻擊者先放一條指向 `~/.ssh/` 的斷連結,
    再誘你解一個同名的 `.qvt`,少了這一層就會寫過去。
    """
    src = tmp_path / "dangle.txt"
    src.write_bytes(b"payload")
    out = encrypt_file(src, tmp_path / "dangle.qvt", PW)
    dest = tmp_path / "dest"
    dest.mkdir()
    outside = tmp_path / "not-there.txt"
    (dest / "dangle.txt").symlink_to(outside)
    assert not (dest / "dangle.txt").exists()  # 斷連結

    with pytest.raises(QVaultFormatError):
        decrypt_file(out, dest, PW)
    assert not outside.exists()
    assert leftovers(dest) == ["dangle.txt"]


def test_existing_target_is_refused_unless_forced(tmp_path, fast_kdf):
    """目標已存在**預設拒絕**;`force=True` 才覆寫(AC 的 `--force`)。"""
    src = tmp_path / "dup.txt"
    src.write_bytes(b"new content")
    out = tmp_path / "dup.qvt"
    encrypt_file(src, out, PW)

    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "dup.txt").write_bytes(b"do not clobber me")

    with pytest.raises(FileExistsError):
        decrypt_file(out, dest, PW)
    assert (dest / "dup.txt").read_bytes() == b"do not clobber me"
    assert leftovers(dest) == ["dup.txt"]

    assert decrypt_file(out, dest, PW, force=True).read_bytes() == b"new content"
    assert leftovers(dest) == ["dup.txt"]


def test_encrypt_refuses_to_clobber_its_output(tmp_path, fast_kdf):
    src = make_file(tmp_path, "c.bin", 16)
    out = tmp_path / "c.qvt"
    out.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        encrypt_file(src, out, PW)
    assert out.read_bytes() == b"precious"
    encrypt_file(src, out, PW, force=True)
    assert out.read_bytes() != b"precious"


def test_out_dir_must_be_a_directory(tmp_path, fast_kdf):
    src = make_file(tmp_path, "d.bin", 16)
    out = tmp_path / "d.qvt"
    encrypt_file(src, out, PW)
    with pytest.raises(NotADirectoryError):
        decrypt_file(out, tmp_path / "nope", PW)
    with pytest.raises(NotADirectoryError):
        decrypt_file(out, src, PW)


# ---------------------------------------------------------------- [H2] 截斷/重排


@pytest.fixture
def five_chunk_file(tmp_path, fast_kdf):
    """一個 5 塊檔(chunk0 + 4 資料塊)與它的切片。"""
    src = make_file(tmp_path, "five.bin", 4 * SMALL)
    out = tmp_path / "five.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header_raw, parts = split_body(out.read_bytes(), SMALL)
    assert len(parts) == 5
    return src, header_raw, parts


@pytest.mark.parametrize(
    "case",
    ["drop_last", "drop_last_two", "header_only", "header_and_chunk0", "extra_16_bytes", "replay_chunk"],
)
def test_truncation_and_reordering_are_detected(tmp_path, five_chunk_file, case):
    """[H2] 六種都要 raise——只測「刪末塊」是不夠的。

    - `drop_last` / `drop_last_two`:新的末塊當初是以 flag=0x00 封的,現在被以
      flag=0x01 開啟 → nonce 不同 → tag 失敗。
    - `header_only`:一個 chunk 都沒有(chunk 0 一定存在)。
    - `header_and_chunk0`:chunk 0 當初是 flag=0x00,現在成了唯一一塊。
    - `extra_16_bytes` / `replay_chunk`:末塊被推到「非末塊」的位置。
    """
    _, header_raw, parts = five_chunk_file
    body = {
        "drop_last": b"".join(parts[:-1]),
        "drop_last_two": b"".join(parts[:-2]),
        "header_only": b"",
        "header_and_chunk0": parts[0],
        "extra_16_bytes": b"".join(parts) + bytes(16),
        "replay_chunk": b"".join(parts) + parts[2],
    }[case]
    victim = tmp_path / f"{case}.qvt"
    victim.write_bytes(header_raw + body)

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


def test_swapping_two_chunks_is_detected(tmp_path, five_chunk_file):
    """重排:把第 1 塊與第 3 塊對調(兩塊等長,長度上完全看不出來)。"""
    _, header_raw, parts = five_chunk_file
    shuffled = [parts[0], parts[3], parts[2], parts[1], parts[4]]
    victim = tmp_path / "swap.qvt"
    victim.write_bytes(header_raw + b"".join(shuffled))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


def test_chunks_from_another_file_are_rejected(tmp_path, fast_kdf):
    """把另一個檔(同密碼)的資料塊接過來——AAD 綁 header,故 nonce_prefix 不同即失敗。"""
    a = make_file(tmp_path, "a.bin", 2 * SMALL)
    b = make_file(tmp_path, "b.bin", 2 * SMALL)
    encrypt_file(a, tmp_path / "a.qvt", PW, chunk_size=SMALL)
    encrypt_file(b, tmp_path / "b.qvt", PW, chunk_size=SMALL)
    head_a, parts_a = split_body((tmp_path / "a.qvt").read_bytes(), SMALL)
    _, parts_b = split_body((tmp_path / "b.qvt").read_bytes(), SMALL)

    victim = tmp_path / "mixed.qvt"
    victim.write_bytes(head_a + parts_a[0] + parts_b[1] + parts_a[2])
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert leftovers(dest) == []


def test_decrypt_opens_each_chunk_exactly_once(tmp_path, five_chunk_file, monkeypatch):
    """[H2] **禁止試誤法**:成功解一個 5 塊檔恰好呼叫 5 次 `unseal`。

    「先試 flag=0、失敗再試 flag=1」的實作在這裡會數到 6 次以上(而且它的
    round-trip 與竄改測試全綠——這是那條 AC 存在的理由)。
    """
    src, header_raw, parts = five_chunk_file
    out = tmp_path / "five.qvt"
    counter = {"n": 0}
    real = vault_mod.unseal

    def counting(*args, **kwargs):
        counter["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(vault_mod, "unseal", counting)
    dest = tmp_path / "out"
    dest.mkdir()
    assert decrypt_file(out, dest, PW).read_bytes() == src.read_bytes()
    assert counter["n"] == 5


def test_decrypt_stops_at_the_first_bad_chunk(tmp_path, five_chunk_file, monkeypatch):
    """壞掉的第 2 塊就地停手:恰好 3 次 `unseal`(chunk 0、1、2),不重試。"""
    _, header_raw, parts = five_chunk_file
    broken = bytearray(parts[2])
    broken[3] ^= 0x40
    victim = tmp_path / "bad.qvt"
    victim.write_bytes(header_raw + parts[0] + parts[1] + bytes(broken) + b"".join(parts[3:]))

    counter = {"n": 0}
    real = vault_mod.unseal

    def counting(*args, **kwargs):
        counter["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(vault_mod, "unseal", counting)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(victim, dest, PW)
    assert counter["n"] == 3


def test_vault_never_swallows_a_decrypt_error(tmp_path):
    """結構保證:`vault.py` 原始碼裡沒有任何 `except QVaultDecryptError`。

    試誤法**必然**要接住第一次的失敗;接不住就試不了。這條掃描把「不得試誤」
    從註解變成可執行的斷言。
    """
    tree = ast.parse(pathlib.Path("qvault_core/vault.py").read_text("utf-8"))
    caught = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            caught.extend(
                n.id for n in ast.walk(node.type) if isinstance(n, ast.Name)
            )
    assert "QVaultDecryptError" not in caught
    assert "QVaultError" not in caught


def test_is_last_is_derived_from_the_remaining_bytes(tmp_path, fast_kdf, monkeypatch):
    """[H2] 每一塊的 `is_last` 恰好是「這是不是最後一塊」,由剩餘位元組數推導。"""
    src = make_file(tmp_path, "flags.bin", 3 * SMALL)
    out = tmp_path / "flags.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)

    seen: list[tuple[int, bool]] = []
    real = vault_mod.nonce_for

    def spy(prefix, index, is_last):
        seen.append((index, is_last))
        return real(prefix, index, is_last)

    monkeypatch.setattr(vault_mod, "nonce_for", spy)
    dest = tmp_path / "out"
    dest.mkdir()
    decrypt_file(out, dest, PW)
    assert seen == [(0, False), (1, False), (2, False), (3, True)]


# ---------------------------------------------------------------- [M3] header 參數


def test_decrypt_reads_the_kdf_parameters_from_the_header(tmp_path):
    """[M3] 夾具以 `kdf_log2n=14` 產生(**真的** scrypt),`decrypt_file` 必須成功。

    硬編碼 15/8/1 的實作在這裡會派生出另一把 KEK,`unwrap` 當場失敗。
    """
    payload = b"header parameters, not hard-coded\n" * 3
    victim = build_qvt(tmp_path / "l14.qvt", name=b"l14.txt", data=payload, log2n=14)
    header, _ = deserialize(victim.read_bytes())
    assert header.kdf_log2n == 14 != SCRYPT_LOG2N

    dest = tmp_path / "out"
    dest.mkdir()
    got = decrypt_file(victim, dest, PW)
    assert got.name == "l14.txt"
    assert got.read_bytes() == payload


def test_decrypt_reads_the_chunk_size_from_the_header(tmp_path, fast_kdf):
    """chunk_size 同理:寫 8192 的檔不能用預設 65536 去切。"""
    src = make_file(tmp_path, "cs.bin", 8192 * 2 + 3)
    out = tmp_path / "cs.qvt"
    encrypt_file(src, out, PW, chunk_size=8192)
    header, _ = deserialize(out.read_bytes())
    assert header.chunk_size == 8192
    dest = tmp_path / "out"
    dest.mkdir()
    assert decrypt_file(out, dest, PW).read_bytes() == src.read_bytes()


# ---------------------------------------------------------------- [M2] golden

GOLDEN = pathlib.Path("tests/vectors/golden_v1.qvt")
GOLDEN_PW = "correct horse"
GOLDEN_NAME = "golden.txt"
GOLDEN_DATA = b"QVault golden vector v1\n"


def _write_golden(tmp_path, monkeypatch) -> pathlib.Path:
    """以 [M2] 指定的四個固定值 + 正規 15/8/1 重造 golden(不吃 `fast_kdf`)。"""
    fixed = {
        SALT_LEN: b"\x01" * SALT_LEN,
        NONCE_PREFIX_LEN: b"\x02" * NONCE_PREFIX_LEN,
        32: b"\x03" * 32,
        12: b"\x04" * 12,
    }
    monkeypatch.setattr(secrets, "token_bytes", lambda size: fixed[size])
    src = tmp_path / GOLDEN_NAME
    src.write_bytes(GOLDEN_DATA)
    out = tmp_path / "golden_v1.qvt"
    encrypt_file(src, out, GOLDEN_PW)
    return out


def test_golden_file_is_byte_for_byte_stable(tmp_path, monkeypatch):
    """[M2] 格式凍結:重造的位元組必須與 repo 內的 golden **逐位元組相等**。

    這條擋的是「兩邊都自洽」的格式漂移:chunk 0 的補零改成補 0xff、AAD 少含
    `wrapped_dek`、nonce 的 flag 反過來、`orig_size` 改成小端——每一種都能通過
    自己的 round-trip,只有這裡會死。
    """
    assert GOLDEN.exists(), "golden 向量不在 repo 內"
    assert _write_golden(tmp_path, monkeypatch).read_bytes() == GOLDEN.read_bytes()


def test_golden_file_still_decrypts(tmp_path):
    """[M2] golden 必須解得回來(否則凍結的是一個壞格式)。"""
    dest = tmp_path / "out"
    dest.mkdir()
    got = decrypt_file(GOLDEN, dest, GOLDEN_PW)
    assert got.name == GOLDEN_NAME
    assert got.read_bytes() == GOLDEN_DATA


def test_golden_file_header_is_the_documented_layout():
    """golden 的 header 逐欄對帳(位移寫死,對得上 ADR-001 的表)。"""
    raw = GOLDEN.read_bytes()
    assert raw[0:4] == b"QVLT"
    assert raw[4:11] == bytes([1, 1, 1, 1, SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P])
    assert raw[11:27] == b"\x01" * 16
    assert raw[27:34] == b"\x02" * 7
    assert int.from_bytes(raw[34:38], "big") == DEFAULT_CHUNK_SIZE
    assert int.from_bytes(raw[38:40], "big") == 60
    assert raw[40:52] == b"\x04" * 12  # wrap_nonce
    assert len(raw) == HEADER_SIZE_KEM1 + CHUNK0_SEALED_LEN + len(GOLDEN_DATA) + TAG_LEN


def test_golden_file_wrong_passphrase_still_fails(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(GOLDEN, dest, GOLDEN_PW + "!")
    assert leftovers(dest) == []


# ---------------------------------------------------------------- [M9] 權限


@pytest.mark.skipif(os.name == "nt", reason="Windows 上 chmod 近乎 no-op([M9] 已列為已知上限)")
def test_outputs_are_owner_only(tmp_path, fast_kdf):
    """[M9] `.qvt` 與還原的明文都是 `0o600`。"""
    src = make_file(tmp_path, "perm.bin", 2 * SMALL)
    out = tmp_path / "perm.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    dest = tmp_path / "out"
    dest.mkdir()
    got = decrypt_file(out, dest, PW)
    assert stat.S_IMODE(got.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="Windows 上 chmod 近乎 no-op([M9] 已列為已知上限)")
def test_temp_file_is_owner_only_while_it_exists(tmp_path, fast_kdf, monkeypatch):
    """[M9] 暫存檔**在存在的當下**就是 `0o600`(不是事後才 chmod)。"""
    src = make_file(tmp_path, "tmp.bin", 3 * SMALL)
    out = tmp_path / "tmp.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    dest = tmp_path / "out"
    dest.mkdir()

    modes: list[int] = []
    real = vault_mod._write_all

    def peeking(fd, data):
        for entry in dest.iterdir():
            modes.append(stat.S_IMODE(entry.stat().st_mode))
        return real(fd, data)

    monkeypatch.setattr(vault_mod, "_write_all", peeking)
    decrypt_file(out, dest, PW)
    assert modes and set(modes) == {0o600}


@pytest.mark.skipif(os.name == "nt", reason="Windows 上 chmod 近乎 no-op")
def test_force_overwrite_resets_a_permissive_mode(tmp_path, fast_kdf):
    """覆寫一個 0o666 的舊檔之後,權限必須變回 0o600(replace 帶著暫存檔的模式)。"""
    src = tmp_path / "mode.txt"
    src.write_bytes(b"fresh")
    out = tmp_path / "mode.qvt"
    encrypt_file(src, out, PW)
    dest = tmp_path / "out"
    dest.mkdir()
    victim = dest / "mode.txt"
    victim.write_bytes(b"old")
    os.chmod(victim, 0o666)
    got = decrypt_file(out, dest, PW, force=True)
    assert stat.S_IMODE(got.stat().st_mode) == 0o600


# ---------------------------------------------------------------- [H4] 不洩密


def test_debug_logging_leaks_no_secrets(tmp_path, fast_kdf, caplog):
    """[H4] root level=DEBUG 跑完整一趟,buffer 不含密碼、DEK、KEK 的任何形式。"""
    records: list[str] = []

    class Memory(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    handler = Memory()
    root = logging.getLogger()
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.DEBUG)

    deks: list[bytes] = []
    real_gen = vault_mod.gen_dek

    def spy():
        dek = real_gen()
        deks.append(dek)
        return dek

    try:
        import unittest.mock as _mock  # noqa: PLC0415 —— 只在本測試需要

        with _mock.patch.object(vault_mod, "gen_dek", spy):
            src = tmp_path / "logged.bin"
            src.write_bytes(b"payload" * 100)
            out = tmp_path / "logged.qvt"
            encrypt_file(src, out, MARKER_PW, chunk_size=SMALL)
            dest = tmp_path / "out"
            dest.mkdir()
            decrypt_file(out, dest, MARKER_PW)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)

    buffer = "\n".join(records) + "\n" + caplog.text
    assert MARKER_PW not in buffer
    assert deks, "沒有攔到 DEK,測試是空砲"
    for dek in deks:
        assert dek.hex() not in buffer
        assert dek.hex().upper() not in buffer
        assert repr(dek) not in buffer
    header, _ = deserialize(out.read_bytes())
    assert header.wrapped_dek.hex() not in buffer
    assert header.salt.hex() not in buffer


def test_failure_traceback_leaks_nothing(tmp_path, fast_kdf):
    """錯密碼的 traceback 不得帶出密碼、也不得帶出 `InvalidTag` 的脈絡。"""
    import traceback

    src = tmp_path / "tb.bin"
    src.write_bytes(b"x" * 64)
    out = tmp_path / "tb.qvt"
    encrypt_file(src, out, MARKER_PW)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError) as excinfo:
        decrypt_file(out, dest, MARKER_PW + "!")
    text = "".join(traceback.format_exception(excinfo.value))
    assert MARKER_PW not in text
    assert "InvalidTag" not in text
    assert excinfo.value.__cause__ is None


# ---------------------------------------------------------------- [L] nonce 不重用


class _Recorder:
    """記下每一次 `AESGCM.encrypt` 實際用的 `(key, nonce, aad)`。"""

    calls: list[tuple[bytes, bytes, bytes]] = []

    def __init__(self, key):
        self._key = bytes(key)
        self._inner = AESGCM(key)

    def encrypt(self, nonce, plaintext, aad):
        type(self).calls.append((self._key, bytes(nonce), bytes(aad)))
        return self._inner.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce, ciphertext, aad):
        return self._inner.decrypt(nonce, ciphertext, aad)


def test_chunk_nonces_are_unique_and_match_nonce_for(tmp_path, fast_kdf, monkeypatch):
    """[L] nonce 不重用**用測試證明**:5 塊檔的每個 nonce 都等於 `nonce_for(...)`。

    順帶釘住 wrap 的 nonce 不會與任何 chunk nonce 相同(那是另一把金鑰,但
    重用一個常數 nonce 的實作會在這裡撞上)。
    """
    _Recorder.calls = []
    monkeypatch.setattr(aead_mod, "AESGCM", _Recorder)

    src = make_file(tmp_path, "n1.bin", 4 * SMALL)
    out = tmp_path / "n1.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header, body_offset = deserialize(out.read_bytes())
    aad = out.read_bytes()[:body_offset]

    chunk_calls = [c for c in _Recorder.calls if c[2] == aad]
    assert len(chunk_calls) == 5
    nonces = [c[1] for c in chunk_calls]
    assert nonces == [nonce_for(header.nonce_prefix, i, i == 4) for i in range(5)]
    assert len(set(nonces)) == 5
    assert len({c[0] for c in chunk_calls}) == 1  # 全部同一把 DEK

    wrap_calls = [c for c in _Recorder.calls if c[2] != aad]
    assert len(wrap_calls) == 1
    assert wrap_calls[0][1] not in nonces

    # 第二個檔:兩檔的 nonce 集合交集為空。
    _Recorder.calls = []
    src2 = make_file(tmp_path, "n2.bin", 4 * SMALL)
    out2 = tmp_path / "n2.qvt"
    encrypt_file(src2, out2, PW, chunk_size=SMALL)
    header2, off2 = deserialize(out2.read_bytes())
    aad2 = out2.read_bytes()[:off2]
    nonces2 = [c[1] for c in _Recorder.calls if c[2] == aad2]
    assert len(nonces2) == 5
    assert set(nonces) & set(nonces2) == set()


def test_last_chunk_flag_is_one_and_others_zero(tmp_path, fast_kdf, monkeypatch):
    """末塊的 nonce flag == 0x01,其餘 == 0x00(防截斷的那一位)。"""
    _Recorder.calls = []
    monkeypatch.setattr(aead_mod, "AESGCM", _Recorder)
    src = make_file(tmp_path, "f.bin", 2 * SMALL)
    out = tmp_path / "f.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    _, body_offset = deserialize(out.read_bytes())
    aad = out.read_bytes()[:body_offset]
    nonces = [c[1] for c in _Recorder.calls if c[2] == aad]
    assert [n[-1] for n in nonces] == [0x00, 0x00, 0x01]
    assert [int.from_bytes(n[7:11], "big") for n in nonces] == [0, 1, 2]


def test_empty_file_chunk0_is_flagged_last(tmp_path, fast_kdf, monkeypatch):
    """決策 14:空檔的 chunk 0 自己就是末塊,flag == 0x01。"""
    _Recorder.calls = []
    monkeypatch.setattr(aead_mod, "AESGCM", _Recorder)
    src = tmp_path / "z.bin"
    src.write_bytes(b"")
    out = tmp_path / "z.qvt"
    encrypt_file(src, out, PW)
    _, body_offset = deserialize(out.read_bytes())
    aad = out.read_bytes()[:body_offset]
    nonces = [c[1] for c in _Recorder.calls if c[2] == aad]
    assert len(nonces) == 1
    assert nonces[0][-1] == 0x01


# ---------------------------------------------------------------- [L] 串流


def test_large_file_streams_within_a_bounded_peak(tmp_path, fast_kdf):
    """[L] 64 MiB 檔加解密,`tracemalloc` 峰值 < `8 * chunk_size + 4 MiB`。

    整檔載入記憶體的實作在這裡會炸到 64 MiB 以上——這正是本票票文的那一句
    「不整檔載入記憶體」。
    """
    size = 64 * 1024 * 1024
    chunk = DEFAULT_CHUNK_SIZE
    src = tmp_path / "huge.bin"
    block = bytes(range(256)) * 256  # 64 KiB
    with open(src, "wb") as fh:
        for _ in range(size // len(block)):
            fh.write(block)
    assert src.stat().st_size == size

    out = tmp_path / "huge.qvt"
    dest = tmp_path / "out"
    dest.mkdir()

    tracemalloc.start()
    try:
        encrypt_file(src, out, PW)
        restored = decrypt_file(out, dest, PW)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 8 * chunk + 4 * 1024 * 1024, f"峰值 {peak} 太高"
    assert restored.stat().st_size == size
    assert out.stat().st_size > size  # 密文確實寫滿了


# ---------------------------------------------------------------- 錯密碼 / 壞檔


def test_wrong_passphrase_raises_and_writes_nothing(tmp_path, fast_kdf):
    src = make_file(tmp_path, "w.bin", 3 * SMALL)
    out = tmp_path / "w.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError):
        decrypt_file(out, dest, PW + "x")
    assert leftovers(dest) == []


def test_wrong_passphrase_and_tamper_are_indistinguishable(tmp_path, fast_kdf):
    """保證③ / [M4]:錯密碼與竄改的型別、訊息逐字相同,本層一個字都不加。"""
    src = make_file(tmp_path, "o.bin", 2 * SMALL)
    out = tmp_path / "o.qvt"
    encrypt_file(src, out, PW, chunk_size=SMALL)
    header_raw, parts = split_body(out.read_bytes(), SMALL)
    broken = bytearray(parts[1])
    broken[0] ^= 0x01
    victim = tmp_path / "o-bad.qvt"
    victim.write_bytes(header_raw + parts[0] + bytes(broken) + b"".join(parts[2:]))

    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(QVaultDecryptError) as wrong_pw:
        decrypt_file(out, dest, "nope")
    with pytest.raises(QVaultDecryptError) as tampered:
        decrypt_file(victim, dest, PW)
    assert type(wrong_pw.value) is type(tampered.value)
    assert str(wrong_pw.value) == str(tampered.value) == "AEAD authentication failed"


@pytest.mark.parametrize(
    "raw, expected",
    [
        (b"", QVaultFormatError),
        (b"QVL", QVaultFormatError),
        (b"NOPE" + bytes(96), QVaultFormatError),
        (b"QVLT" + bytes([9]) + bytes(95), QVaultVersionError),
        (b"QVLT" + bytes([1, 1, 1, 1, 63, 8, 1]) + bytes(93), QVaultFormatError),
        (b"QVLT" + bytes([1, 1, 1, 1, 15, 8, 1]) + bytes(20), QVaultFormatError),
    ],
    ids=["empty", "short", "bad-magic", "bad-version", "insane-log2n", "truncated-header"],
)
def test_malformed_container_raises_before_any_kdf(tmp_path, monkeypatch, raw, expected):
    """壞 header 一律在 KDF 之前擋下(決策 15):`Scrypt` **一次都不能被呼叫**。"""
    called = {"n": 0}

    def tripwire(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("KDF 不該被呼叫")

    monkeypatch.setattr(kek_mod, "_scrypt", tripwire)
    victim = tmp_path / "bad.qvt"
    victim.write_bytes(raw)
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(expected):
        decrypt_file(victim, dest, PW)
    assert called["n"] == 0
    assert leftovers(dest) == []


def test_missing_input_raises_oserror(tmp_path, fast_kdf):
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(FileNotFoundError):
        decrypt_file(tmp_path / "nope.qvt", dest, PW)
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "nope.bin", tmp_path / "x.qvt", PW)
    assert leftovers(tmp_path) == ["out"]


def test_encrypt_rejects_an_illegal_chunk_size(tmp_path, fast_kdf):
    """chunk_size 的界限由 `QVaultHeader` 把關(決策 15),vault 不自己另立一套。"""
    src = make_file(tmp_path, "cs.bin", 32)
    for bad in (0, 100, 4095, 6000, 2 * 1024 * 1024):
        with pytest.raises(QVaultFormatError):
            encrypt_file(src, tmp_path / f"cs-{bad}.qvt", PW, chunk_size=bad)
    assert leftovers(tmp_path) == ["cs.bin"]


def test_non_str_passphrase_is_rejected(tmp_path, fast_kdf):
    """密碼只收 `str`(決策 18:`bytes` 沒有 NFC 正規化可言)——沿用 #3 的規矩。"""
    src = make_file(tmp_path, "p.bin", 16)
    with pytest.raises(ValueError):
        encrypt_file(src, tmp_path / "p.qvt", b"bytes-pw")
    assert leftovers(tmp_path) == ["p.bin"]


def test_nfd_and_nfc_passphrases_interoperate(tmp_path, fast_kdf):
    """[M6] 決策 18 的跨平台後果:macOS 的 NFD 與 Linux 的 NFC 必須解得開同一個檔。"""
    import unicodedata

    nfc = unicodedata.normalize("NFC", "café-密碼")
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd
    src = tmp_path / "nfc.bin"
    src.write_bytes(b"unicode")
    out = tmp_path / "nfc.qvt"
    encrypt_file(src, out, nfc)
    dest = tmp_path / "out"
    dest.mkdir()
    assert decrypt_file(out, dest, nfd).read_bytes() == b"unicode"


# ---------------------------------------------------------------- 鐵律 / API 契約


def test_vault_imports_only_stdlib_and_siblings():
    """鐵律 1/2:`vault.py` 不得自己碰密碼原語,也不得引入新相依。"""
    tree = ast.parse(pathlib.Path("qvault_core/vault.py").read_text("utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." if node.level else (node.module or "").split(".")[0])
    assert imported <= {"os", "secrets", "tempfile", "pathlib", "__future__", "."}, imported
    assert "cryptography" not in imported  # AES/GCM/scrypt 一律經 aead/kek


def test_vault_does_not_touch_the_insecure_test_hatch():
    """[M3] 的結構保證(#3 的 `test_production_code_never_uses_the_insecure_hatch`
    已在掃全套件,這裡再對 `vault.py` 明寫一次,讓失敗訊息落在本票的檔案上)。"""
    text = pathlib.Path("qvault_core/vault.py").read_text("utf-8")
    assert "insecure" not in text.lower()
    assert "_allow_insecure_params" not in text


def test_public_signatures_match_the_ac():
    """[M8] 簽章:`encrypt_file(inp, out, passphrase)`、`decrypt_file(inp, out_dir, passphrase)`。"""
    enc = inspect.signature(encrypt_file)
    assert list(enc.parameters)[:3] == ["inp", "out", "passphrase"]
    dec = inspect.signature(decrypt_file)
    assert list(dec.parameters)[:3] == ["inp", "out_dir", "passphrase"]
    assert dec.parameters["force"].default is False
    assert enc.parameters["chunk_size"].default == DEFAULT_CHUNK_SIZE
    assert dec.return_annotation == "Path"


def test_package_exports_the_file_layer():
    import qvault_core

    assert qvault_core.encrypt_file is encrypt_file
    assert qvault_core.decrypt_file is decrypt_file
    assert {"encrypt_file", "decrypt_file"} <= set(qvault_core.__all__)


def test_constants_agree_with_the_spec():
    assert CHUNK0_PLAINTEXT_LEN == 4096
    assert CHUNK0_SEALED_LEN == CHUNK0_PLAINTEXT_LEN + TAG_LEN == 4112
    assert MAX_NAME_BYTES == 255
    assert len(WINDOWS_RESERVED_NAMES) == 4 + 9 + 9
    assert {"CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9"} <= WINDOWS_RESERVED_NAMES
    assert "COM0" not in WINDOWS_RESERVED_NAMES
