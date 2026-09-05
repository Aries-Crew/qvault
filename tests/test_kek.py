"""scrypt KEK 的測試(AC #3;設計見 ADR-001 決策 2/7/10/11/18/19/20)。

三類必備測試(AGENTS.md 鐵律 4)在本檔的落點:
  round-trip → `test_roundtrip_*`
  tamper     → `test_tampered_*` / `test_wrong_*`
  邊界       → 空密碼、非 ASCII 密碼、長度不符、成本參數越界、ABC 契約

外加 **RFC 7914 官方 KAT**(`test_rfc7914_*`):scrypt 的參數順序寫錯(r/p 對調、
passphrase/salt 對調)是自己跟自己完全自洽的錯法——round-trip 與竄改測試全綠,
只有官方向量抓得到。向量是**抄進來的字面值**,不由實作輸出反推(#1 [M1] 同一條)。
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import logging
import pathlib
import pickle
import traceback
import unicodedata

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qvault_core import aead, container, kek as kek_mod
from qvault_core.aead import DEK_LEN, gen_dek
from qvault_core.container import QVaultHeader, deserialize
from qvault_core.errors import QVaultDecryptError, QVaultFormatError
from qvault_core.kek import (
    KDF_LOG2N_RANGE,
    KDF_P_RANGE,
    KDF_R_RANGE,
    KEK_LEN,
    KEM_ID_SCRYPT,
    SALT_LEN,
    SCRYPT_LOG2N,
    SCRYPT_P,
    SCRYPT_R,
    WRAP_AAD,
    WRAP_NONCE_LEN,
    WRAPPED_DEK_LEN,
    KeyEncapsulation,
    ScryptKEK,
    _passphrase_bytes,
    _scrypt,
)

# ---------------------------------------------------------------- 夾具

#: [H4] 指名的密碼標記——凡是「不得出現」的斷言都用它,才看得出真的沒漏。
MARKER_PW = "S3cr3t-pw-marker"
SALT = bytes(range(0x10, 0x20))  # 16B,逐 byte 相異 → 錯序會現形
OTHER_SALT = bytes(range(0x30, 0x40))
DEK = bytes(range(0x40, 0x60))  # 32B


def weak(passphrase: str = MARKER_PW, salt: bytes = SALT, **kwargs) -> ScryptKEK:
    """測試用的低成本 KEK(0.3ms vs 正規 15/8/1 的 80ms)。

    正規參數的路徑另有 `test_default_cost_parameters_are_15_8_1` 等數條真的跑
    15/8/1;其餘測試沒有必要為了同一段程式碼重燒 KDF。
    """
    return ScryptKEK.insecure_for_tests(passphrase, salt, **kwargs)


def flip(data: bytes, index: int) -> bytes:
    """把第 `index` 個 byte 的最低位翻掉(改一 byte,值必定不同)。"""
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def capture(fn, *args) -> Exception:
    """跑 `fn(*args)`,回它丟出的例外(沒丟就是測試該死)。"""
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001 —— 就是要抓任何東西來比對
        return exc
    raise AssertionError("expected an exception, got none")


# ---------------------------------------------------------------- RFC 7914 KAT
#
# 來源:RFC 7914 §12 "Test Vectors for scrypt"(scrypt 的規範文件本身)。
# 三組向量把「參數順序」的每一種對調都釘死:
#   v1 空密碼 + 空 salt(N=16, r=1, p=1)
#   v2 密碼與 salt **不同字串**、r=8 而 p=16(r/p 對調會現形)
#   v3 N=16384、r=8、p=1 —— 與 P0 的 15/8/1 只差一個 N,最貼近正式參數
# 每組的 dkLen 都是 64B;QVault 用 32B,而 scrypt 的輸出是 PBKDF2 的截斷,
# 32B 就是 64B 的前綴(`test_rfc7914_kek_length_output_is_the_vector_prefix` 釘住)。

RFC7914_KAT = (
    (
        "RFC 7914 §12 vector 1 (空密碼、空 salt、N=16/r=1/p=1)",
        b"",
        b"",
        16,
        1,
        1,
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    ),
    (
        "RFC 7914 §12 vector 2 (N=1024/r=8/p=16 —— r 與 p 對調會現形)",
        b"password",
        b"NaCl",
        1024,
        8,
        16,
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    ),
    (
        "RFC 7914 §12 vector 3 (N=16384/r=8/p=1 —— 與 P0 參數只差一個 N)",
        b"pleaseletmein",
        b"SodiumChloride",
        16384,
        8,
        1,
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
        "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    ),
)


@pytest.mark.parametrize("name,pw,salt,n,r,p,expected", RFC7914_KAT)
def test_rfc7914_scrypt_matches_published_vector(name, pw, salt, n, r, p, expected):
    assert _scrypt(pw, salt, n=n, r=r, p=p, dklen=64).hex() == expected


@pytest.mark.parametrize("name,pw,salt,n,r,p,expected", RFC7914_KAT)
def test_rfc7914_kek_length_output_is_the_vector_prefix(
    name, pw, salt, n, r, p, expected
):
    """預設 dklen 恰為 32(= KEK 長度),且就是官方向量的前 32 byte。"""
    derived = _scrypt(pw, salt, n=n, r=r, p=p)
    assert len(derived) == KEK_LEN == 32
    assert derived == bytes.fromhex(expected)[:KEK_LEN]


def test_scrypt_arguments_are_not_interchangeable():
    """把 passphrase 與 salt 對調、把 r 與 p 對調,結果都必須不同(向量才有意義)。"""
    base = _scrypt(b"password", b"NaCl", n=1024, r=8, p=1)
    assert _scrypt(b"NaCl", b"password", n=1024, r=8, p=1) != base
    assert _scrypt(b"password", b"NaCl", n=1024, r=1, p=8) != base


def test_scrypt_delegates_to_cryptography(monkeypatch):
    """只呼叫 `cryptography` 的 `Scrypt`,且參數具名對位(鐵律 1)。"""
    seen = {}

    class Recorder:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def derive(self, key_material):
            seen["key_material"] = key_material
            return b"K" * KEK_LEN

    monkeypatch.setattr(kek_mod, "Scrypt", Recorder)
    out = _scrypt(b"pw", SALT, n=1 << 15, r=8, p=1)

    assert out == b"K" * KEK_LEN
    assert seen == {
        "salt": SALT,
        "length": KEK_LEN,
        "n": 1 << 15,
        "r": 8,
        "p": 1,
        "key_material": b"pw",
    }


# ---------------------------------------------------------------- 建構子 → scrypt


def test_constructor_feeds_scrypt_the_header_parameters(monkeypatch):
    """`n = 2**log2n`、`r`、`p`、`dklen=32`、salt 原封不動、密碼經 NFC+UTF-8。"""
    seen = {}

    def fake_scrypt(pw_bytes, salt, *, n, r, p, dklen=KEK_LEN):
        seen.update(pw_bytes=pw_bytes, salt=salt, n=n, r=r, p=p, dklen=dklen)
        return b"K" * KEK_LEN

    monkeypatch.setattr(kek_mod, "_scrypt", fake_scrypt)
    ScryptKEK("密碼🔑", SALT, log2n=16, r=4, p=2)

    assert seen == {
        "pw_bytes": unicodedata.normalize("NFC", "密碼🔑").encode("utf-8"),
        "salt": SALT,
        "n": 1 << 16,
        "r": 4,
        "p": 2,
        "dklen": KEK_LEN,
    }


def test_constructor_derives_exactly_once(monkeypatch):
    """建構時派生一次並留住;每次 `wrap` 重跑 KDF 會讓 #4 的大檔加密慢到不能用。"""
    calls = []
    monkeypatch.setattr(
        kek_mod,
        "_scrypt",
        lambda *a, **k: (calls.append(1), b"K" * KEK_LEN)[1],
    )
    kek = ScryptKEK(MARKER_PW, SALT)
    for _ in range(5):
        kek.unwrap(kek.wrap(DEK))
    assert calls == [1]


def test_default_cost_parameters_are_15_8_1():
    """[M3] 正規建構子的預設值恆為 15/8/1(這一條真的跑一次 scrypt)。"""
    assert (SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P) == (15, 8, 1)
    kek = ScryptKEK(MARKER_PW, SALT)
    assert (kek.log2n, kek.r, kek.p) == (15, 8, 1)
    assert kek.salt == SALT


def test_signature_defaults_are_literal_15_8_1():
    """[M3] 預設值釘在簽章上——測試沒有任何管道可以「順手」把它調低。"""
    params = inspect.signature(ScryptKEK.__init__).parameters
    assert params["log2n"].default == 15
    assert params["r"].default == 8
    assert params["p"].default == 1
    assert params["salt"].default is inspect.Parameter.empty  # 決策 10:不給常數 salt


# ---------------------------------------------------------------- [C2] wrap 線格式


def test_wrapped_dek_is_exactly_60_bytes():
    assert len(weak().wrap(DEK)) == 60 == WRAPPED_DEK_LEN


def test_wrap_nonce_differs_between_two_calls_on_the_same_kek():
    """[C2] 同一 KEK 實例、同一 DEK,連呼兩次 → 前 12B 不同(nonce 不得重用)。"""
    kek = weak()
    first, second = kek.wrap(DEK), kek.wrap(DEK)
    assert first[:WRAP_NONCE_LEN] != second[:WRAP_NONCE_LEN]
    assert first != second


def test_wrap_nonces_are_all_distinct_over_many_calls():
    kek = weak()
    nonces = {kek.wrap(DEK)[:WRAP_NONCE_LEN] for _ in range(64)}
    assert len(nonces) == 64
    assert bytes(WRAP_NONCE_LEN) not in nonces  # 零 nonce 明令禁止


def test_wrap_nonce_is_not_derived_from_salt_or_passphrase():
    """禁止「重用 header 的 nonce_prefix」與任何由 salt/密碼派生的 nonce。"""
    kek = weak()
    for _ in range(16):
        nonce = kek.wrap(DEK)[:WRAP_NONCE_LEN]
        assert nonce != SALT[:WRAP_NONCE_LEN]
        assert nonce != kek.salt[:WRAP_NONCE_LEN]
        assert nonce not in SALT
        assert nonce != MARKER_PW.encode()[:WRAP_NONCE_LEN]


def test_wrap_takes_its_nonce_from_secrets_token_bytes(monkeypatch):
    """[C2] `wrap_nonce = secrets.token_bytes(12)`(隨機來源限 `secrets`,決策 20)。"""
    calls = []
    real = kek_mod.secrets.token_bytes

    def spy(n):
        calls.append(n)
        return real(n)

    monkeypatch.setattr(kek_mod.secrets, "token_bytes", spy)
    weak().wrap(DEK)
    assert calls == [WRAP_NONCE_LEN] == [12]


def test_wrap_layout_is_nonce_then_ct_then_tag(monkeypatch):
    """佈局逐位元組對帳:`wrap_nonce ‖ ct ‖ tag`,AAD 是常數 `b"QVLT-dek-v1"`。

    期望值走 `cryptography` 的 `AESGCM` **直接算**,不經 `qvault_core.aead`——
    這樣「把 ct 與 tag 對調」「AAD 寫錯」「nonce 沒串在最前面」都會現形。
    """
    fixed_nonce = bytes(range(0xA0, 0xAC))
    monkeypatch.setattr(kek_mod.secrets, "token_bytes", lambda n: fixed_nonce)

    kek = weak()
    kek_bytes = kek._kek.reveal()
    expected_ct_tag = AESGCM(kek_bytes).encrypt(fixed_nonce, DEK, b"QVLT-dek-v1")

    wrapped = kek.wrap(DEK)
    assert wrapped == fixed_nonce + expected_ct_tag
    assert wrapped[:12] == fixed_nonce
    assert len(wrapped[12:44]) == DEK_LEN  # ct 恰 32B(GCM 是串流密碼,不擴張)
    assert len(wrapped[44:]) == aead.TAG_LEN  # tag 恰 16B


def test_wrap_aad_is_the_documented_constant():
    """[C2] AAD **常數** `b"QVLT-dek-v1"`——字面值,不由實作反推。"""
    assert WRAP_AAD == b"QVLT-dek-v1"


@pytest.mark.parametrize(
    "wrong_aad",
    [b"", b"QVLT-dek-v2", b"qvlt-dek-v1", b"QVLT-dek-v1 ", b"QVLT-chunk-v1"],
)
def test_unwrap_rejects_material_sealed_under_another_aad(monkeypatch, wrong_aad):
    kek = weak()
    nonce = bytes(range(WRAP_NONCE_LEN))
    forged = nonce + AESGCM(kek._kek.reveal()).encrypt(nonce, DEK, wrong_aad)
    assert len(forged) == WRAPPED_DEK_LEN
    with pytest.raises(QVaultDecryptError):
        kek.unwrap(forged)


def test_wrap_output_never_contains_the_dek():
    """密文不得是明文——「忘了加密」在 round-trip 測試裡看起來完全正常。"""
    wrapped = weak().wrap(DEK)
    assert DEK not in wrapped
    assert wrapped[WRAP_NONCE_LEN : WRAP_NONCE_LEN + DEK_LEN] != DEK


def test_wrap_is_indistinguishable_across_keks_for_the_same_dek():
    """不同密碼包同一個 DEK → 密文不同(KEK 真的有進到加密裡)。"""
    a = weak(MARKER_PW, SALT).wrap(DEK)
    b = weak("another-pw", SALT).wrap(DEK)
    assert a[WRAP_NONCE_LEN:] != b[WRAP_NONCE_LEN:]


# ---------------------------------------------------------------- round-trip


def test_roundtrip_returns_the_same_dek():
    kek = weak()
    assert kek.unwrap(kek.wrap(DEK)) == DEK


def test_roundtrip_with_production_parameters():
    """正規 15/8/1 的真實路徑(其餘測試用低參數,但這條不能沒有)。"""
    kek = ScryptKEK(MARKER_PW, SALT)
    dek = gen_dek()
    assert ScryptKEK(MARKER_PW, SALT).unwrap(kek.wrap(dek)) == dek


def test_roundtrip_across_two_instances_of_the_same_passphrase_and_salt():
    """加密與解密是兩個 process、兩個實例:同密碼同 salt 必須派生出同一把 KEK。"""
    wrapped = weak().wrap(DEK)
    assert weak().unwrap(wrapped) == DEK


@pytest.mark.parametrize(
    "passphrase",
    ["", "x", MARKER_PW, "密碼🔑", "café", "a" * 4096, "pw with \n newline \t tab"],
)
def test_roundtrip_over_passphrase_shapes(passphrase):
    """邊界:空密碼(決策 8:P0 不強制強度)、單字元、非 ASCII、超長、含控制字元。"""
    kek = weak(passphrase)
    assert weak(passphrase).unwrap(kek.wrap(DEK)) == DEK


@pytest.mark.parametrize("dek", [bytes(DEK_LEN), b"\xff" * DEK_LEN, bytes(range(32))])
def test_roundtrip_over_dek_shapes(dek):
    kek = weak()
    assert kek.unwrap(kek.wrap(dek)) == dek


def test_wrap_accepts_bytes_like_dek():
    kek = weak()
    assert kek.unwrap(kek.wrap(bytearray(DEK))) == DEK
    assert kek.unwrap(bytearray(kek.wrap(DEK))) == DEK


# ---------------------------------------------------------------- tamper


@pytest.mark.parametrize("index", range(WRAPPED_DEK_LEN))
def test_tampered_wrapped_dek_byte_raises(index):
    """60 個 byte **逐一**翻位元(nonce / ct / tag 三段全覆蓋)→ 一律 raise。"""
    kek = weak()
    wrapped = kek.wrap(DEK)
    with pytest.raises(QVaultDecryptError):
        kek.unwrap(flip(wrapped, index))


def test_wrong_passphrase_raises():
    wrapped = weak(MARKER_PW).wrap(DEK)
    with pytest.raises(QVaultDecryptError):
        weak(MARKER_PW + "x").unwrap(wrapped)


def test_wrong_salt_raises():
    """[C1] 的另一半:salt 不同 = KEK 不同,即使密碼對也解不開。"""
    wrapped = weak(MARKER_PW, SALT).wrap(DEK)
    with pytest.raises(QVaultDecryptError):
        weak(MARKER_PW, OTHER_SALT).unwrap(wrapped)


def test_wrong_cost_parameters_raise():
    """成本參數也進 KDF:header 的 kdf_* 被改 → 解不開(而不是靜默用錯 KEK)。"""
    base = {"log2n": 10, "r": 1, "p": 1}
    wrapped = weak(**base).wrap(DEK)
    for changed in ({"log2n": 11}, {"r": 2}, {"p": 2}):
        with pytest.raises(QVaultDecryptError):
            weak(**{**base, **changed}).unwrap(wrapped)


def test_swapped_halves_of_wrapped_dek_raise():
    """位元組界重組(把 nonce 與 tag 搬位)也必須擋下。"""
    kek = weak()
    wrapped = kek.wrap(DEK)
    forged = wrapped[-WRAP_NONCE_LEN:] + wrapped[WRAP_NONCE_LEN:-WRAP_NONCE_LEN] + wrapped[:WRAP_NONCE_LEN]
    with pytest.raises(QVaultDecryptError):
        kek.unwrap(forged)


def test_wrapped_dek_from_another_kek_raises():
    kek_a, kek_b = weak(MARKER_PW), weak("other-pw")
    with pytest.raises(QVaultDecryptError):
        kek_a.unwrap(kek_b.wrap(DEK))


@pytest.mark.parametrize("length", [0, 1, 12, 43, 59, 61, 120])
def test_wrong_length_wrapped_dek_raises_format_error(length):
    """長度不符是**格式**壞掉(欄位定長 60),不是驗證失敗——與 #1 同一條規矩。"""
    kek = weak()
    with pytest.raises(QVaultFormatError):
        kek.unwrap(bytes(length))


@pytest.mark.parametrize("bad", [None, "x" * WRAPPED_DEK_LEN, 60, [0] * 60])
def test_non_bytes_wrapped_dek_raises_format_error(bad):
    with pytest.raises(QVaultFormatError):
        weak().unwrap(bad)


@pytest.mark.parametrize(
    "bad", [None, "not bytes", 32, bytes(31), bytes(33), b"", bytes(60)]
)
def test_wrong_dek_raises_value_error(bad):
    """DEK 來自 `gen_dek()`,不是檔案:長度/型別錯是**呼叫端的 bug**(#2 同一條)。"""
    with pytest.raises(ValueError) as exc:
        weak().wrap(bad)
    assert not isinstance(exc.value, QVaultFormatError)
    assert not isinstance(exc.value, QVaultDecryptError)


# ---------------------------------------------------------------- [M4] 無 oracle


def _failure_paths() -> dict[str, Exception]:
    """所有「解不開」的路徑,各取一個例外回來逐字比對。"""
    kek = weak(MARKER_PW, SALT)
    wrapped = kek.wrap(DEK)
    return {
        "wrong passphrase": capture(weak("wrong-pw", SALT).unwrap, wrapped),
        "wrong salt": capture(weak(MARKER_PW, OTHER_SALT).unwrap, wrapped),
        "wrong cost params": capture(weak(MARKER_PW, SALT, log2n=11).unwrap, wrapped),
        "tampered nonce byte": capture(kek.unwrap, flip(wrapped, 0)),
        "tampered ct byte": capture(kek.unwrap, flip(wrapped, 30)),
        "tampered tag byte": capture(kek.unwrap, flip(wrapped, 59)),
        "foreign wrapped_dek": capture(kek.unwrap, weak("other").wrap(DEK)),
    }


def test_all_failure_paths_are_indistinguishable():
    """[M4] 錯密碼與改 1 byte —— `type(exc)` 與 `str(exc)` **逐字元**相同。"""
    failures = _failure_paths()
    types = {name: type(exc) for name, exc in failures.items()}
    messages = {name: str(exc) for name, exc in failures.items()}

    assert set(types.values()) == {QVaultDecryptError}, types
    assert len(set(messages.values())) == 1, messages
    # 逐字元:訊息就是 #2 那一句,本層一個字都沒加。
    assert set(messages.values()) == {"AEAD authentication failed"}
    assert {len(m) for m in messages.values()} == {len("AEAD authentication failed")}


def test_failure_is_not_chained():
    """`raise ... from None`(決策 19)——traceback 不得帶出 `InvalidTag` 與脈絡。"""
    exc = _failure_paths()["wrong passphrase"]
    assert exc.__cause__ is None
    assert exc.__suppress_context__
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert "InvalidTag" not in text
    assert "During handling" not in text


# ---------------------------------------------------------------- [H4] 金鑰不可印


def test_repr_is_the_fixed_string():
    kek = weak()
    assert repr(kek) == "<ScryptKEK kem_id=1>"
    assert str(kek) == "<ScryptKEK kem_id=1>"
    assert f"{kek}" == "<ScryptKEK kem_id=1>"
    assert "%r" % (kek,) == "<ScryptKEK kem_id=1>"
    assert "%s" % (kek,) == "<ScryptKEK kem_id=1>"


def test_scrypt_kek_is_not_a_dataclass():
    """[H4] 明令「不得使用預設 dataclass repr」——連 dataclass 都不是,更穩。"""
    assert not dataclasses.is_dataclass(ScryptKEK)
    assert "__repr__" in vars(ScryptKEK)  # 自己定義的,不是繼承來的


def test_passphrase_never_appears_in_repr_or_vars():
    """[H4] 指名的三個管道:`repr(kek)`、`str(kek)`、`repr(vars(kek))`。"""
    kek = weak(MARKER_PW)
    for text in (repr(kek), str(kek), repr(vars(kek)), repr(kek.__dict__)):
        assert MARKER_PW not in text
        assert MARKER_PW.encode().hex() not in text


def test_passphrase_is_not_retained_anywhere_on_the_instance():
    """更強的一條:密碼**根本沒被存下來**——派生完就出了作用域。"""
    kek = weak(MARKER_PW)
    for value in vars(kek).values():
        assert value != MARKER_PW
        assert value != MARKER_PW.encode()
        assert MARKER_PW not in repr(value)


def test_key_material_never_appears_in_vars():
    """`__repr__` 管不到 `repr(vars(kek))` 與 `logging.debug("%r", kek.__dict__)`。"""
    kek = weak(MARKER_PW)
    text = repr(vars(kek))
    kek_bytes = kek._kek.reveal()
    assert kek_bytes.hex() not in text
    assert repr(kek_bytes) not in text
    assert text.count("<secret 32 bytes>") == 1


def test_traceback_of_failed_unwrap_leaks_nothing():
    """[H4] `"".join(traceback.format_exception(exc))` 不含密碼、DEK hex、KEK hex。"""
    kek = weak(MARKER_PW)
    wrapped = kek.wrap(DEK)
    exc = capture(weak("wrong-pw").unwrap, flip(wrapped, 20))
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    for secret in (
        MARKER_PW,
        DEK.hex(),
        DEK.hex().upper(),
        repr(DEK),
        kek._kek.reveal().hex(),
        repr(kek._kek.reveal()),
        wrapped.hex(),
    ):
        assert secret not in text


def test_logging_at_debug_leaks_nothing(caplog):
    """`logging.exception` / `%r` 的整條路徑跑一遍,buffer 不得含任何金鑰材料。"""
    kek = weak(MARKER_PW)
    wrapped = kek.wrap(DEK)
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("qvault.test").debug("kek=%r dict=%r", kek, kek.__dict__)
        try:
            weak("wrong-pw").unwrap(wrapped)
        except QVaultDecryptError:
            logging.getLogger("qvault.test").exception("unwrap failed")

    buffer = caplog.text
    assert "unwrap failed" in buffer  # 確定真的有寫進去(否則本測試是空砲)
    for secret in (MARKER_PW, DEK.hex(), kek._kek.reveal().hex(), wrapped.hex()):
        assert secret not in buffer


def test_key_material_cannot_be_pickled():
    """醃進 cache 檔就是「金鑰落地」(鐵律 5),而 pickle 不會問過任何人。"""
    with pytest.raises(TypeError):
        pickle.dumps(weak())
    with pytest.raises(TypeError):
        pickle.dumps(weak()._kek)


def test_unicode_encode_failure_does_not_echo_the_passphrase():
    """孤兒代理對:`UnicodeEncodeError` 會把出錯的字元印出來,那是密碼的一部分。"""
    exc = capture(weak, "pw-\udcff-tail")
    assert isinstance(exc, ValueError)
    assert exc.__cause__ is None
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert "\\udcff" not in text and "\udcff" not in text
    assert "pw-" not in text


# ---------------------------------------------------------------- [M6] NFC 正規化


def test_passphrase_bytes_are_nfc_utf8():
    assert _passphrase_bytes("密碼🔑") == "密碼🔑".encode("utf-8")
    assert _passphrase_bytes("café") == unicodedata.normalize("NFC", "café").encode()


def test_nfd_and_nfc_passphrases_derive_the_same_kek():
    """[M6] macOS 給 NFD、Windows/Linux 給 NFC——同一個密碼必須開得了同一個檔。"""
    nfc = unicodedata.normalize("NFC", "café-密碼")
    nfd = unicodedata.normalize("NFD", "café-密碼")
    assert nfc != nfd  # 否則本測試是空砲
    assert _passphrase_bytes(nfc) == _passphrase_bytes(nfd)

    wrapped = weak(nfd).wrap(DEK)
    assert weak(nfc).unwrap(wrapped) == DEK


def test_non_ascii_passphrase_roundtrip():
    """[M6] 指名的密碼 `"密碼🔑"`(含 BMP 外的 emoji)。"""
    kek = weak("密碼🔑")
    assert weak("密碼🔑").unwrap(kek.wrap(DEK)) == DEK
    with pytest.raises(QVaultDecryptError):
        weak("密碼🔒").unwrap(kek.wrap(DEK))


@pytest.mark.parametrize("bad", [b"bytes-pw", bytearray(b"pw"), None, 12345])
def test_non_str_passphrase_raises_value_error(bad):
    """`bytes` 沒有「正規化」可言——收了就是開一條繞過決策 18 的路。"""
    with pytest.raises(ValueError):
        ScryptKEK(bad, SALT, log2n=14)


# ---------------------------------------------------------------- [M3] 低參數不外流


def test_insecure_hatch_does_not_change_the_default_path():
    """[M3] 用過低參數入口之後,正規建構子仍是 15/8/1(沒有全域狀態被改)。"""
    weak(log2n=1, r=1, p=1)
    assert (SCRYPT_LOG2N, SCRYPT_R, SCRYPT_P) == (15, 8, 1)
    params = inspect.signature(ScryptKEK.__init__).parameters
    assert (params["log2n"].default, params["r"].default, params["p"].default) == (
        15,
        8,
        1,
    )


def test_production_code_never_uses_the_insecure_hatch():
    """[M3] 結構保證:`qvault_core/` 內只有 `kek.py` 提得起這個名字。

    #4 的 `encrypt_file` 一旦想「借」測試的低參數跑快一點,本測試立刻死。
    """
    offenders = []
    for path in sorted(pathlib.Path("qvault_core").rglob("*.py")):
        if path.name == "kek.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "insecure_for_tests" in text or "_allow_insecure_params" in text:
            offenders.append(str(path))
    assert offenders == []


def test_insecure_hatch_is_the_only_way_below_the_floor():
    """正規建構子不接受低於下界的參數,連手滑都不行。"""
    with pytest.raises(QVaultFormatError):
        ScryptKEK(MARKER_PW, SALT, log2n=10)
    kek = ScryptKEK.insecure_for_tests(MARKER_PW, SALT, log2n=10)
    assert kek.log2n == 10


@pytest.mark.parametrize(
    "kwargs",
    [
        {"log2n": 13},
        {"log2n": 23},
        {"log2n": 63},
        {"log2n": 0},
        {"log2n": -1},
        {"r": 0},
        {"r": 33},
        {"p": 0},
        {"p": 17},
        {"log2n": 15.0},
        {"r": True},
        {"p": "8"},
    ],
)
def test_out_of_range_cost_parameters_raise_before_the_kdf_runs(monkeypatch, kwargs):
    """[H1] 同一條理由:`log2n=63` 就是 `Scrypt(n=2**63)` → OOM。KDF 不得被碰到。"""

    def explode(*args, **kw):  # pragma: no cover —— 被呼叫就是測試失敗
        raise AssertionError("Scrypt must not be called for out-of-range parameters")

    monkeypatch.setattr(kek_mod, "_scrypt", explode)
    with pytest.raises(QVaultFormatError):
        ScryptKEK(MARKER_PW, SALT, **kwargs)


@pytest.mark.parametrize("kwargs", [{"log2n": 0}, {"log2n": 23}, {"r": 33}, {"p": 0}])
def test_insecure_hatch_still_range_checks(kwargs):
    """放寬只往「更快」的方向:上界不動(往更貴的方向放寬 = 開一條 OOM 的路)。"""
    with pytest.raises(QVaultFormatError):
        ScryptKEK.insecure_for_tests(MARKER_PW, SALT, **kwargs)


@pytest.mark.parametrize(
    "bad", [None, "x" * SALT_LEN, bytes(15), bytes(17), b"", 16, [0] * 16]
)
def test_bad_salt_raises_format_error(bad):
    with pytest.raises(QVaultFormatError):
        ScryptKEK(MARKER_PW, bad, log2n=14)


def test_salt_is_normalised_to_bytes():
    kek = weak(MARKER_PW, bytearray(SALT))
    assert kek.salt == SALT and isinstance(kek.salt, bytes)


# ---------------------------------------------------------------- [L] ABC 契約


def test_abstract_base_cannot_be_instantiated():
    with pytest.raises(TypeError):
        KeyEncapsulation()


@pytest.mark.parametrize("missing", ["kem_id", "wrap", "unwrap"])
def test_subclass_missing_a_member_cannot_be_instantiated(missing):
    """[L] 缺 `wrap` 的子類實體化 → `TypeError`(缺 `unwrap`/`kem_id` 同理)。"""
    members = {
        "kem_id": 7,
        "wrap": lambda self, dek: b"",
        "unwrap": lambda self, wrapped: b"",
    }
    del members[missing]
    incomplete = type("Incomplete", (KeyEncapsulation,), members)
    with pytest.raises(TypeError):
        incomplete()


def test_complete_subclass_instantiates_and_satisfies_the_protocol():
    """P1 的 `MLKEMKek` 只要補齊三個成員就能上——這是「插槽」的可證偽版本。"""

    class FakeKEM(KeyEncapsulation):
        kem_id = 2

        def wrap(self, dek):
            return b"wrapped:" + dek

        def unwrap(self, wrapped):
            return wrapped.removeprefix(b"wrapped:")

    fake = FakeKEM()
    assert isinstance(fake, KeyEncapsulation)
    assert fake.kem_id == 2
    assert fake.unwrap(fake.wrap(DEK)) == DEK


def test_abstract_members_are_exactly_the_documented_contract():
    assert KeyEncapsulation.__abstractmethods__ == frozenset(
        {"kem_id", "wrap", "unwrap"}
    )


def test_scrypt_kek_kem_id_is_one_and_a_class_attribute():
    """[L] `ScryptKEK.kem_id == 1` 且**為類別屬性**(不是每個實例各存一份)。"""
    assert ScryptKEK.kem_id == 1 == KEM_ID_SCRYPT
    assert vars(ScryptKEK)["kem_id"] == 1
    assert "kem_id" not in vars(weak())
    assert isinstance(weak(), KeyEncapsulation)
    assert issubclass(ScryptKEK, KeyEncapsulation)


def test_wrap_signature_matches_the_abstract_contract():
    """`wrap(dek)` / `unwrap(wrapped)`——參數名進 ADR,別的實作照抄。"""
    assert list(inspect.signature(ScryptKEK.wrap).parameters) == ["self", "dek"]
    assert list(inspect.signature(ScryptKEK.unwrap).parameters) == ["self", "wrapped"]
    assert list(inspect.signature(KeyEncapsulation.wrap).parameters) == ["self", "dek"]


def test_wrap_does_not_accept_a_caller_supplied_nonce():
    """nonce **不在介面裡**:留一個參數就留了一條「呼叫端傳常數進來」的路。"""
    with pytest.raises(TypeError):
        weak().wrap(DEK, bytes(12))
    assert "nonce" not in inspect.signature(ScryptKEK.wrap).parameters


# ---------------------------------------------------------------- 與 #1/#2 的對帳


def test_constants_agree_with_container():
    """`kek` 不 import `container`(相依圖是兄弟),兩份常數用測試釘在一起。"""
    assert WRAPPED_DEK_LEN == container.WRAPPED_DEK_LEN == 60
    assert SALT_LEN == container.SALT_LEN == 16
    assert KEM_ID_SCRYPT == container.KEM_ID_SCRYPT == 1
    assert KDF_LOG2N_RANGE == container.KDF_LOG2N_RANGE
    assert KDF_R_RANGE == container.KDF_R_RANGE
    assert KDF_P_RANGE == container.KDF_P_RANGE
    assert WRAP_NONCE_LEN == container.NONCE_LEN == aead.NONCE_LEN == 12
    assert KEK_LEN == aead.KEY_LEN == 32
    assert WRAPPED_DEK_LEN == WRAP_NONCE_LEN + DEK_LEN + aead.TAG_LEN


def test_header_default_cost_fields_match_the_kek_defaults():
    """header 的 kdf_* 預設(#1)與 KEK 的預設(本票)必須是同一組數字。"""
    header = QVaultHeader(
        salt=SALT, nonce_prefix=bytes(7), wrapped_dek=bytes(WRAPPED_DEK_LEN)
    )
    assert (header.kdf_log2n, header.kdf_r, header.kdf_p) == (
        SCRYPT_LOG2N,
        SCRYPT_R,
        SCRYPT_P,
    )
    assert header.kem_id == KEM_ID_SCRYPT


def test_wrapped_dek_fits_the_header_and_survives_a_roundtrip():
    """[C2] wrap 的輸出真的塞得進 header,而且 deserialize 後解得回同一個 DEK。"""
    kek = weak()
    wrapped = kek.wrap(DEK)
    raw = QVaultHeader(
        salt=kek.salt, nonce_prefix=bytes(range(7)), wrapped_dek=wrapped
    ).serialize()

    header, body_offset = deserialize(raw)
    assert body_offset == 100  # 40 定長 + 60 wrapped_dek
    assert raw[38:40] == (60).to_bytes(2, "big")  # wrapped_dek_len 欄位
    assert kek.unwrap(header.wrapped_dek) == DEK


@pytest.mark.parametrize("declared", [0, 59, 61, 0xFFFF])
def test_header_rejects_wrapped_dek_len_other_than_60(declared):
    """[C2] `kem_id==1` 時 `wrapped_dek_len` 必須 == 60,否則 `QVaultFormatError`。"""
    kek = weak()
    raw = QVaultHeader(
        salt=kek.salt, nonce_prefix=bytes(range(7)), wrapped_dek=kek.wrap(DEK)
    ).serialize()
    forged = raw[:38] + declared.to_bytes(2, "big") + raw[40:]
    with pytest.raises(QVaultFormatError):
        deserialize(forged)


@pytest.mark.parametrize("size", [59, 61])
def test_header_rejects_a_wrapped_dek_of_the_wrong_size(size):
    with pytest.raises(QVaultFormatError):
        QVaultHeader(
            salt=SALT, nonce_prefix=bytes(7), wrapped_dek=bytes(size)
        ).serialize()


def test_tampering_the_header_does_not_break_unwrap():
    """wrap 的 AAD 是**常數**(決策 11):`wrapped_dek` 不綁 header,不循環。

    chunk 的 AAD 才是 header 全段(決策 12)——改 header 由 #4 的 chunk 驗證擋下,
    不是由 unwrap 擋。這一條把「AAD 該用哪個」的選擇釘成可證偽。
    """
    kek = weak()
    wrapped = kek.wrap(DEK)
    header = QVaultHeader(
        salt=kek.salt, nonce_prefix=bytes(range(7)), wrapped_dek=wrapped
    )
    raw = bytearray(header.serialize())
    raw[27] ^= 0x01  # 改 nonce_prefix 的第一個 byte
    tampered, _ = deserialize(bytes(raw))
    assert kek.unwrap(tampered.wrapped_dek) == DEK


# ---------------------------------------------------------------- 鐵律的可執行斷言


def _imported_names(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # `from .aead import ...` 是套件內部,記成 "."(`node.level > 0`);
            # 只有絕對 import 才需要進白名單比對。
            names.add("." if node.level else (node.module or "").split(".")[0])
    return names


def test_kek_only_uses_vetted_crypto_library():
    """[鐵律 1] scrypt / AES-GCM 一律走 `cryptography`,不手刻,也不偷用 hashlib。"""
    source = pathlib.Path("qvault_core/kek.py").read_text(encoding="utf-8")
    imported = _imported_names(ast.parse(source))
    assert imported <= {"secrets", "unicodedata", "abc", "cryptography", "__future__", "."}
    assert "hashlib" not in imported  # stdlib 的 scrypt 也不行(鐵律 1 指名 cryptography)
    assert "random" not in imported


def test_public_api_is_exported_from_package_root():
    import qvault_core

    assert qvault_core.ScryptKEK is ScryptKEK
    assert qvault_core.KeyEncapsulation is KeyEncapsulation
    assert qvault_core.WRAP_AAD == WRAP_AAD
    for name in ("KeyEncapsulation", "ScryptKEK", "WRAP_AAD"):
        assert name in qvault_core.__all__


def test_module_exports_are_complete():
    for name in kek_mod.__all__:
        assert hasattr(kek_mod, name), name
