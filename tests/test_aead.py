"""AES-256-GCM 信封核心的測試(AC #2;設計見 ADR-001「密碼架構」與決策 5/6/19/20)。

三類必備測試(AGENTS.md 鐵律 4)在本檔的落點:
  round-trip → `test_roundtrip_*`
  tamper     → `test_tampered_*` / `test_wrong_*` / `test_truncated_*`
  邊界       → 空明文、空 AAD、只有 tag、超長 AAD、型別錯

外加 AC 指名的 **NIST 官方 KAT**(`test_nist_kat_*`)——KAT 是「沒有手刻 AES/GCM」
與「位元組界沒搞錯」的唯一硬證據:跨實作對得上才算數。
"""

from __future__ import annotations

import ast
import builtins
import pathlib
import re
import secrets
import traceback

import pytest

from qvault_core import aead, container
from qvault_core.aead import (
    DEK_LEN,
    KEY_LEN,
    NONCE_LEN,
    TAG_LEN,
    gen_dek,
    seal,
    unseal,
)
from qvault_core.container import QVaultHeader, deserialize
from qvault_core.errors import QVaultDecryptError, QVaultError

# ---------------------------------------------------------------- 夾具

KEY = bytes(range(0x40, 0x60))  # 32B,逐 byte 相異 → 錯序會現形
NONCE = bytes(range(0x10, 0x1C))  # 12B
PLAINTEXT = b"attack at dawn -- and bring the QVault"
AAD = b"header-bytes"


def flip(data: bytes, index: int) -> bytes:
    """把第 `index` 個 byte 的最低位翻掉(改一 byte,值必定不同)。"""
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


# ---------------------------------------------------------------- NIST KAT
#
# **字面值,不由實作輸出反推**(AC #1 的 [M1] 同一條理由:反推的話連欄位錯序都會
# 「KAT 通過」)。來源:
#   TC13–TC16 = McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)" 的
#               官方測試案例,亦即 NIST SP 800-38D 採用的那組(AES-256 段)。
#   CAVP      = NIST CAVP `gcmEncryptExtIV256.rsp`
#               [Keylen=256, IVlen=96, PTlen=0, AADlen=0, Taglen=128] Count=0。
# 這幾組把「AES-256 + 96-bit IV + 128-bit tag」的四種組合都蓋到:
# 空明文空 AAD、單塊明文、多塊明文無 AAD、多塊明文**有 AAD**(最貼近 QVault 的用法)。

NIST_KAT = (
    (
        "GCM-spec TC13 (空明文、空 AAD)",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    ),
    (
        "GCM-spec TC14 (單塊全零明文)",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    ),
    (
        "GCM-spec TC15 (64B 明文、無 AAD)",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95"
        "956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48"
        "590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c",
    ),
    (
        "GCM-spec TC16 (60B 明文 + 20B AAD)",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95"
        "956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48"
        "590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
    (
        "NIST CAVP gcmEncryptExtIV256 Count=0",
        "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        "516c33929df5a3284ff463d7",
        "",
        "",
        "",
        "bdc1ac884d332457a1d2664f168c76f0",
    ),
)

KAT_IDS = [case[0] for case in NIST_KAT]


@pytest.mark.parametrize("name,key,iv,pt,aad,ct,tag", NIST_KAT, ids=KAT_IDS)
def test_nist_kat_seal_matches_published_vector(name, key, iv, pt, aad, ct, tag):
    """`seal` 的輸出**逐位元組**等於官方向量的 `ct ‖ tag`。"""
    got = seal(bytes.fromhex(key), bytes.fromhex(iv), bytes.fromhex(pt), bytes.fromhex(aad))
    assert got.hex() == ct + tag


@pytest.mark.parametrize("name,key,iv,pt,aad,ct,tag", NIST_KAT, ids=KAT_IDS)
def test_nist_kat_unseal_matches_published_vector(name, key, iv, pt, aad, ct, tag):
    """反向也對:官方 `ct ‖ tag` 解回官方明文(證明 tag 真的被驗、而不是被忽略)。"""
    got = unseal(
        bytes.fromhex(key), bytes.fromhex(iv), bytes.fromhex(ct + tag), bytes.fromhex(aad)
    )
    assert got == bytes.fromhex(pt)


@pytest.mark.parametrize("name,key,iv,pt,aad,ct,tag", NIST_KAT, ids=KAT_IDS)
def test_nist_kat_layout_is_ct_then_tag(name, key, iv, pt, aad, ct, tag):
    """線上佈局固定為 `ct ‖ tag(16B)`——tag 在**後**,且長度恆 16。

    這條擋的是「tag 放前面」或「回 (ct, tag) 元組」之類的位元組界歧義:兩種寫法
    自己跟自己 round-trip 都會過,但與別的實作互不相容(#1 的 [H5] 同一種病)。
    """
    sealed = seal(bytes.fromhex(key), bytes.fromhex(iv), bytes.fromhex(pt), bytes.fromhex(aad))
    assert sealed[: len(sealed) - TAG_LEN].hex() == ct
    assert sealed[len(sealed) - TAG_LEN :].hex() == tag
    assert len(sealed) == len(bytes.fromhex(pt)) + TAG_LEN


# ---------------------------------------------------------------- round-trip


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4095, 4096, 65536])
def test_roundtrip_over_plaintext_sizes(size):
    """含**空明文**與跨 AES 區塊界的邊界大小。"""
    pt = secrets.token_bytes(size)
    sealed = seal(KEY, NONCE, pt, AAD)
    assert len(sealed) == size + TAG_LEN
    assert unseal(KEY, NONCE, sealed, AAD) == pt


@pytest.mark.parametrize("aad", [b"", b"\x00", bytes(range(256)), b"x" * 100000])
def test_roundtrip_over_aad_sizes(aad):
    """空 AAD 與超長 AAD;`.qvt` 的 AAD 是 100B header,兩端都留餘裕。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, aad)
    assert unseal(KEY, NONCE, sealed, aad) == PLAINTEXT


def test_roundtrip_accepts_bytes_like_inputs():
    """`bytearray` / `memoryview` 與 `bytes` 等價(長度以位元組算,不以元素算)。"""
    sealed = seal(bytearray(KEY), memoryview(NONCE), bytearray(PLAINTEXT), memoryview(AAD))
    assert sealed == seal(KEY, NONCE, PLAINTEXT, AAD)
    assert unseal(memoryview(KEY), bytearray(NONCE), bytearray(sealed), AAD) == PLAINTEXT


def test_seal_is_deterministic_and_never_invents_a_nonce():
    """同樣輸入 → 同樣輸出,且回傳值裡**沒有** nonce。

    這條釘死決策 5:nonce 由呼叫端的 `nonce_for` 給。若 `seal` 自產隨機 nonce
    (ROADMAP 那行交付的字面簽章),STREAM 的「prefix ‖ counter 全域唯一」與末塊
    flag 防截斷就同時失效,而 round-trip 測試照樣全綠。
    """
    a = seal(KEY, NONCE, PLAINTEXT, AAD)
    b = seal(KEY, NONCE, PLAINTEXT, AAD)
    assert a == b
    assert len(a) == len(PLAINTEXT) + TAG_LEN  # 沒有多出 12B nonce
    assert NONCE not in a


def test_different_nonces_give_different_ciphertexts():
    n2 = container.nonce_for(NONCE[:7], 1, True)
    n1 = container.nonce_for(NONCE[:7], 0, False)
    assert seal(KEY, n1, PLAINTEXT, AAD) != seal(KEY, n2, PLAINTEXT, AAD)


# ---------------------------------------------------------------- tamper


@pytest.mark.parametrize("index", range(len(PLAINTEXT) + TAG_LEN))
def test_tampered_sealed_byte_raises(index):
    """`ct` 與 `tag` 的**每一個 byte** 各改一次 → 必 raise(不得靜默回錯資料)。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, flip(sealed, index), AAD)


@pytest.mark.parametrize("index", range(len(AAD)))
def test_tampered_aad_byte_raises(index):
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, sealed, flip(AAD, index))


@pytest.mark.parametrize("bad_aad", [b"", AAD + b"\x00", AAD[:-1], b"header-byte"])
def test_aad_length_changes_raise(bad_aad):
    """AAD 少一段 / 多一段 / 整個沒有 → 一樣 raise(AAD 位元組界不得有彈性)。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, sealed, bad_aad)


@pytest.mark.parametrize("index", range(KEY_LEN))
def test_wrong_key_raises(index):
    """金鑰的每一個 byte 各改一次 → 必 raise。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(flip(KEY, index), NONCE, sealed, AAD)


@pytest.mark.parametrize("index", range(NONCE_LEN))
def test_wrong_nonce_raises(index):
    """nonce 的每一個 byte 各改一次 → 必 raise(含末塊 flag 那一 byte,即防截斷)。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, flip(NONCE, index), sealed, AAD)


def test_swapped_chunk_nonce_raises():
    """把塊 0 的密文拿去用塊 1 的 nonce 解 → raise(重排偵測的底層保證)。"""
    prefix = b"\x11" * 7
    sealed0 = seal(KEY, container.nonce_for(prefix, 0, False), PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, container.nonce_for(prefix, 1, False), sealed0, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, container.nonce_for(prefix, 0, True), sealed0, AAD)


@pytest.mark.parametrize("length", list(range(0, len(PLAINTEXT) + TAG_LEN)))
def test_truncated_sealed_raises(length):
    """**每一個**截斷長度(含 0、含短於 tag)都 raise,絕不回部分明文。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, sealed[:length], AAD)


@pytest.mark.parametrize("suffix", [b"\x00", b"\xff" * 16, PLAINTEXT])
def test_extended_sealed_raises(suffix):
    """尾端多接垃圾 → raise(#4 的 [H2] 在本層的對應保證)。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, sealed + suffix, AAD)


def test_empty_plaintext_still_authenticates():
    """空明文 = 只有 16B tag;改它一 byte 一樣 raise(#4 的空檔佈局靠這條)。"""
    sealed = seal(KEY, NONCE, b"", AAD)
    assert len(sealed) == TAG_LEN
    assert unseal(KEY, NONCE, sealed, AAD) == b""
    with pytest.raises(QVaultDecryptError):
        unseal(KEY, NONCE, flip(sealed, 0), AAD)


# ---------------------------------------------------------------- 無 oracle / 不洩密


def _failures() -> dict[str, QVaultDecryptError]:
    """五種失敗路徑各抓一個例外物件回來。"""
    sealed = seal(KEY, NONCE, PLAINTEXT, AAD)
    cases = {
        "ct": (KEY, NONCE, flip(sealed, 0), AAD),
        "tag": (KEY, NONCE, flip(sealed, len(sealed) - 1), AAD),
        "nonce": (KEY, flip(NONCE, 0), sealed, AAD),
        "aad": (KEY, NONCE, sealed, flip(AAD, 0)),
        "key": (flip(KEY, 0), NONCE, sealed, AAD),
        "truncated": (KEY, NONCE, sealed[:8], AAD),
    }
    out = {}
    for name, args in cases.items():
        try:
            unseal(*args)
        except QVaultDecryptError as exc:
            out[name] = exc
        else:  # pragma: no cover —— 上面每一條都必須 raise
            pytest.fail(f"{name} 沒有 raise")
    return out


def test_all_failure_paths_are_indistinguishable():
    """六種失敗的 `type(exc)` 與 `str(exc)` **逐字元相同**(保證③,避免 oracle)。"""
    failures = _failures()
    types = {type(exc) for exc in failures.values()}
    messages = {str(exc) for exc in failures.values()}
    assert types == {QVaultDecryptError}
    assert len(messages) == 1, messages
    assert issubclass(QVaultDecryptError, QVaultError)


#: 走 `cryptography` 的 tag 驗證(`except InvalidTag`)那條路的失敗原因。
#: `truncated` 不在其中——它在呼叫 AEAD 之前就被擋下,沒有原例外可壓。
_AEAD_PATHS = ("ct", "tag", "nonce", "aad", "key")


def test_invalid_tag_is_not_chained():
    """決策 19:`raise ... from None`——不外洩 `InvalidTag`,traceback 不帶原例外。"""
    failures = _failures()
    for name, exc in failures.items():
        assert exc.__cause__ is None, name
        assert exc.__context__ is None or exc.__suppress_context__, name
        rendered = "".join(traceback.format_exception(exc))
        assert "InvalidTag" not in rendered, name
        assert "cryptography" not in rendered, name
        assert "During handling" not in rendered, name
    for name in _AEAD_PATHS:
        # 這五條真的經過 `except InvalidTag`,故 `from None` 必須留下痕跡。
        assert failures[name].__suppress_context__ is True, name


def test_failure_never_leaks_key_or_plaintext():
    """鐵律 5:例外訊息 / traceback **永不**含金鑰或明文(hex 與 raw 兩種形式都查)。"""
    marker_key = bytes.fromhex("5ec4e7") + secrets.token_bytes(KEY_LEN - 3)
    marker_pt = b"S3cr3t-plaintext-marker"
    sealed = seal(marker_key, NONCE, marker_pt, AAD)
    with pytest.raises(QVaultDecryptError) as info:
        unseal(marker_key, NONCE, flip(sealed, 0), AAD)
    rendered = "".join(traceback.format_exception(info.value)) + str(info.value) + repr(info.value)
    for needle in (
        marker_key.hex(),
        repr(marker_key),
        str(marker_key),
        marker_pt.decode(),
        repr(marker_pt),
    ):
        assert needle not in rendered


# ---------------------------------------------------------------- gen_dek


def test_gen_dek_length_and_type():
    dek = gen_dek()
    assert type(dek) is bytes
    assert len(dek) == DEK_LEN == KEY_LEN == 32


def test_gen_dek_is_unique_per_call():
    """1000 次全部相異——擋掉「模組層產一次就重用」這種會毀掉整個信封的寫法。"""
    deks = {gen_dek() for _ in range(1000)}
    assert len(deks) == 1000


def test_gen_dek_uses_secrets_token_bytes(monkeypatch):
    """AC:`gen_dek()` == `secrets.token_bytes(32)`(隨機來源限 `secrets`)。"""
    calls = []

    def fake_token_bytes(n):
        calls.append(n)
        return b"\x07" * n

    monkeypatch.setattr(aead.secrets, "token_bytes", fake_token_bytes)
    assert gen_dek() == b"\x07" * 32
    assert calls == [32]


def test_gen_dek_output_works_as_a_key():
    dek = gen_dek()
    assert unseal(dek, NONCE, seal(dek, NONCE, PLAINTEXT, AAD), AAD) == PLAINTEXT


# ---------------------------------------------------------------- 參數契約


@pytest.mark.parametrize("bad", [b"", b"\x00" * 31, b"\x00" * 33, KEY + b"\x00"])
def test_wrong_length_key_raises_value_error(bad):
    """長度錯的金鑰是**呼叫端 bug**,不是解密失敗——不得報成「密碼錯誤」。"""
    with pytest.raises(ValueError):
        seal(bad, NONCE, PLAINTEXT, AAD)
    with pytest.raises(ValueError):
        unseal(bad, NONCE, seal(KEY, NONCE, PLAINTEXT, AAD), AAD)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 11, b"\x00" * 13, b"\x00" * 16])
def test_wrong_length_nonce_raises_value_error(bad):
    with pytest.raises(ValueError):
        seal(KEY, bad, PLAINTEXT, AAD)
    with pytest.raises(ValueError):
        unseal(KEY, bad, seal(KEY, NONCE, PLAINTEXT, AAD), AAD)


@pytest.mark.parametrize("arg", ["key", "nonce", "plaintext", "aad"])
@pytest.mark.parametrize("bad", [None, "str", 42, ["bytes"]])
def test_non_bytes_arguments_raise_value_error(arg, bad):
    """尤其 `aad=None`:若被默許,忘了傳 header 的呼叫端會**靜默**失去 header 綁定
    (決策 6),而 round-trip 與竄改測試照樣全綠。空 AAD 必須明寫 `b""`。"""
    args = {"key": KEY, "nonce": NONCE, "plaintext": PLAINTEXT, "aad": AAD}
    args[arg] = bad
    with pytest.raises(ValueError):
        seal(**args)


def test_value_errors_are_not_decrypt_errors():
    """參數錯不得偽裝成 `QVaultDecryptError`(否則 CLI 把程式 bug 報成密碼錯)。"""
    with pytest.raises(ValueError) as info:
        unseal(b"short", NONCE, b"\x00" * 32, AAD)
    assert not isinstance(info.value, QVaultError)


def test_sealed_shorter_than_tag_is_a_decrypt_error():
    """密文是唯一由檔案來的參數:它太短是**竄改**,必須走解密錯誤而非 ValueError。"""
    for length in range(TAG_LEN):
        with pytest.raises(QVaultDecryptError):
            unseal(KEY, NONCE, b"\x00" * length, AAD)


# ---------------------------------------------------------------- 與 #1 的介面對齊


def test_constants_agree_with_container():
    """本檔的常數與 `.qvt` 格式必須對得上,否則 #4 會在位元組界上對不起來。

    `aead` 不 import `container`(ADR 的相依圖裡兩者是兄弟),故改用測試把兩份
    數字釘在一起——這是「不建立相依」與「不留第二份帳」的折衷。
    """
    assert NONCE_LEN == container.NONCE_LEN
    assert container.WRAPPED_DEK_LEN == NONCE_LEN + KEY_LEN + TAG_LEN  # 12+32+16 = 60


def test_header_aad_binding_detects_field_tampering():
    """**#1 的交接條件**:`salt` / `nonce_prefix` / `wrapped_dek` 各改一 byte →
    解密必 raise `QVaultDecryptError`。

    #1 的純 struct 層對這三個不透明欄位無從判斷「壞掉」,把偵測交接給本層的 AAD
    綁定(見 `.asp/pr/1.md`「做不到 / 打了折的」第 1 條)。這裡用真的 header 走完
    序列化 → 竄改 → 反序列化 → 解密,證明那條交接真的落地。
    """
    header = QVaultHeader(
        salt=bytes(range(0x10, 0x20)),
        nonce_prefix=bytes(range(0x20, 0x27)),
        wrapped_dek=bytes(range(0x30, 0x6C)),
    )
    raw = header.serialize()
    aad = header.aad()
    assert aad == raw[: header.body_offset]  # [H5] 的位元組界

    key = gen_dek()
    nonce = container.nonce_for(header.nonce_prefix, 0, True)
    sealed = seal(key, nonce, PLAINTEXT, aad)
    assert unseal(key, nonce, sealed, aad) == PLAINTEXT

    layout = {name: (off, size) for name, off, size in container.FIELD_LAYOUT}
    for field in ("salt", "nonce_prefix", "wrapped_dek"):
        offset, size = layout[field]
        for index in (offset, offset + size - 1):  # 欄位頭尾各一 byte
            tampered_header, body_offset = deserialize(flip(raw, index))
            tampered_aad = tampered_header.aad()
            assert tampered_aad != aad, field
            assert body_offset == header.body_offset
            with pytest.raises(QVaultDecryptError):
                unseal(key, nonce, sealed, tampered_aad)


# ---------------------------------------------------------------- 鐵律的可執行斷言


def _package_sources() -> list[pathlib.Path]:
    return sorted(pathlib.Path("qvault_core").rglob("*.py"))


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add("." if node.level else (node.module or "").split(".")[0])
    return names


def test_no_import_random_anywhere_in_package():
    """[L] 決策 20:`qvault_core/` 內禁止 `import random`,隨機值限 `secrets`。

    AST 與 grep **兩種**都做(AC 寫「以 AST 或 grep 斷言」):AST 擋得住
    `import random as r`,grep 再補上 AST 看不到的動態載入(`__import__("random")`、
    `importlib.import_module("random")`)。grep 只認**取用**的形式,不認散文——
    否則 docstring 裡引用禁令本身就會誤報(而拿掉那段說明只是讓禁令更難懂)。
    """
    sources = _package_sources()
    assert sources, "找不到 qvault_core 原始碼"
    patterns = (
        re.compile(r"^\s*(?:import|from)\s+random\b", re.MULTILINE),
        re.compile(r"""(?:__import__|import_module)\s*\(\s*["']random["']"""),
        re.compile(r"\brandom\s*\."),
    )
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "random" not in _imported_names(ast.parse(text)), f"{path} 匯入了 random"
        for pattern in patterns:
            hit = pattern.search(text)
            assert hit is None, f"{path} 取用了 random:{hit.group(0)!r}"


def test_aead_only_uses_vetted_crypto_library():
    """鐵律 1:只用 `cryptography`,不手刻 AES/GCM(以 AST 白名單斷言 import)。"""
    tree = ast.parse(pathlib.Path("qvault_core/aead.py").read_text("utf-8"))
    assert _imported_names(tree) <= {"secrets", "cryptography", "__future__", "."}


def test_seal_and_unseal_delegate_to_aesgcm(monkeypatch):
    """把 `AESGCM` 換掉,`seal`/`unseal` 就得跟著壞——證明沒有另一條自刻路徑。

    只有真的呼叫 `cryptography` 才會失敗;若哪天有人把 GCM 手刻進來當備援,
    本測試會綠得很可疑,故同時斷言呼叫參數。
    """
    calls = []

    class FakeAESGCM:
        def __init__(self, key):
            calls.append(("init", key))

        def encrypt(self, nonce, data, aad):
            calls.append(("encrypt", nonce, data, aad))
            return b"sentinel"

        def decrypt(self, nonce, data, aad):
            calls.append(("decrypt", nonce, data, aad))
            return b"plain"

    monkeypatch.setattr(aead, "AESGCM", FakeAESGCM)
    assert seal(KEY, NONCE, PLAINTEXT, AAD) == b"sentinel"
    assert unseal(KEY, NONCE, b"\x00" * 32, AAD) == b"plain"
    assert calls == [
        ("init", KEY),
        ("encrypt", NONCE, PLAINTEXT, AAD),
        ("init", KEY),
        ("decrypt", NONCE, b"\x00" * 32, AAD),
    ]


def test_names_are_seal_and_unseal_not_open():
    """[L] 不得用 `open` 命名——模組層的 `open` 會遮蔽內建 `open`,

    而這個套件正要拿內建 `open` 去讀寫 `.qvt`。
    """
    tree = ast.parse(pathlib.Path("qvault_core/aead.py").read_text("utf-8"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    assert {"seal", "unseal", "gen_dek"} <= defined
    assert "open" not in defined
    assert not hasattr(aead, "open")
    assert "open" not in aead.__all__
    assert builtins.open is open  # 沒有人把內建的換掉


def test_public_api_is_exported_from_package_root():
    import qvault_core

    for name in ("seal", "unseal", "gen_dek", "KEY_LEN", "DEK_LEN", "TAG_LEN"):
        assert name in qvault_core.__all__
        assert getattr(qvault_core, name) is getattr(aead, name)
