"""檔案層:`file` → `file.qvt` 的加密,與 `.qvt` → 原檔的還原(STREAM 分塊 AEAD)。

本檔是 ADR-001 相依圖裡 `cli → vault → {container, aead, kek}` 的中間那層:
**編排**,不發明。格式來自 `container`、AEAD 來自 `aead`、DEK 的包/解來自 `kek`,
本檔只負責「照著順序把它們接起來,並且一次只在記憶體裡放一塊」。

## 兩個函式

    encrypt_file(inp, out, passphrase)              -> Path   # 寫出 .qvt
    decrypt_file(inp, out_dir, passphrase)          -> Path   # 寫出還原的原檔

`decrypt_file` 的第二個參數是**目錄**([M8]):檔名不由呼叫端指定,而是從 chunk 0
解出來、經 `_sanitize_name` 淨化後才決定,回傳實際寫出的路徑。

## chunk 0 為什麼**定長 4096**(與 AC 字面的差異,見 `.asp/pr/4.md`)

ADR 決策 13 寫 chunk 0 明文 = `name_len(2B BE) ‖ name_utf8 ‖ orig_size(8B BE)`,
「總長 ≤ 4096」。本實作把它**補零填到剛好 4096B**,理由有二,缺一不可:

1. **不補滿就解不開。** [H2] 要求 `is_last` 由剩餘位元組數推導、**禁止**試誤法,
   於是解密端必須在**解密之前**就知道每一塊的位元組界。資料塊有 `chunk_size`
   可推(見 `_chunk_limit`),chunk 0 卻是 `2 + name_len + 8`——而 `name_len` 正好
   在還沒解開的那一塊裡面。header 沒有任何欄位記 chunk 0 的長度,唯一能讓兩端
   對齊的常數就是 ADR 自己寫的那個 4096。
2. **不補滿就洩檔名長度。** 決策 9 把原檔名加密進 `.qvt` 是為了「不洩檔名」;
   若 chunk 0 隨檔名長短伸縮,任何人 `ls -l` 一下就能從 `.qvt` 的位元組數反推出
   `name_len`(其餘各項長度都是已知常數)。補到定長,這條旁通道就消失。

「總長 ≤ 4096」因此成為 `2 + name_len + 8 ≤ 4096` 的上界檢查(`_pack_chunk0` /
`_parse_chunk0` 兩端都檢),而**尾端填充必須全為零**——留一段「解密端不看」的
位元組,等於在一個宣稱「格式固定」的容器裡開一條隱藏通道。

## 解密的兩條硬規矩

- **原子性(決策 16 / [C3])**:明文一律先寫進**目標目錄下**的暫存檔(`0o600`),
  等到全部 chunk 都驗過、末塊確實以 flag=`0x01` 開啟、還原長度也對得上
  `orig_size` 之後,才 `os.replace()` 到目標;中途任一步失敗都 `os.unlink`
  暫存檔再 raise。否則串流解密會在 raise 之前把前 k 塊**未經完整驗證的明文**
  留在磁碟上,那就是一個可控的部分解密原語。
- **檔名是不可信輸入(決策 17/21 / [C4])**:chunk 0 通過了 AEAD 驗證只證明
  「簽發者持有密碼」,**不證明簽發者善意**——別人寄來的 `.qvt` 本來就是他自己
  加密的。故檔名一律經 `_sanitize_name` 全套檢查,違反任一條就 raise,
  **不修正、不回退**(修正成一個合法名 = 替攻擊者挑一個他能寫的位置)。

## 記憶體上限

加解密都只以「一塊」為單位:`chunk_size`(預設 64 KiB)的明文加上同尺寸的密文,
與檔案大小無關(AC 的 `tracemalloc` 那條測的就是這件事)。故 64 MiB 與 64 GiB
的峰值一樣。
"""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from .aead import TAG_LEN, gen_dek, seal, unseal
from .container import (
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE_KEM1,
    MAX_CHUNK_INDEX,
    NONCE_PREFIX_LEN,
    SALT_LEN,
    QVaultHeader,
    body_chunk_count,
    deserialize,
    is_last_chunk,
    nonce_for,
)
from .errors import QVaultDecryptError, QVaultFormatError
from .kek import ScryptKEK

__all__ = [
    "CHUNK0_PLAINTEXT_LEN",
    "CHUNK0_SEALED_LEN",
    "MAX_NAME_BYTES",
    "WINDOWS_RESERVED_NAMES",
    "encrypt_file",
    "decrypt_file",
]

#: chunk 0 的明文長度——**定長**,見模組 docstring 的兩條理由。
CHUNK0_PLAINTEXT_LEN = 4096

#: chunk 0 落盤的位元組數(明文 + GCM tag)。解密端靠這個常數切出第一塊。
CHUNK0_SEALED_LEN = CHUNK0_PLAINTEXT_LEN + TAG_LEN  # 4112

#: `name_len(2B)` + `orig_size(8B)` 的固定開銷。
_CHUNK0_OVERHEAD = 2 + 8

#: 還原檔名的長度上限(決策 17:UTF-8 編碼後的**位元組**數,不是字元數)。
MAX_NAME_BYTES = 255

#: Windows 保留裝置名(決策 21)——**三平台一律套用**。
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

#: 檔名禁止出現的字元:路徑分隔(兩種平台都擋)、磁碟機/替代資料流的 `:`。
#: 控制字元 `\x00`–`\x1f` 另以範圍判斷。
_FORBIDDEN_NAME_CHARS = frozenset("/\\:")

#: 串流結構壞掉(截斷、重排、多接、長度對不上)的統一訊息。
#:
#: 與 `aead` 的 `"AEAD authentication failed"` **刻意不同**:這一類判斷全部只用
#: **公開資訊**——`.qvt` 在磁碟上的位元組數、以及**已經通過 AEAD 驗證**之後才拿到
#: 的 `orig_size`。攻擊者 `ls -l` 就知道長度對不對,訊息裡不含任何他還不知道的事,
#: 故不構成 oracle;而所有真的「解不開」的路徑(錯密碼、改一個 byte)仍逐字共用
#: `aead` 那一句(保證③ / [M4]),本層一個字都不加。
_STREAM_BROKEN = "chunk stream is truncated, reordered or incomplete"


# ---------------------------------------------------------------- 檔名淨化


def _sanitize_name(raw: bytes) -> str:
    """把 chunk 0 裡的檔名位元組變成一個**可以安全寫進 `out_dir` 的**檔名。

    全部檢查都對**整個字串**做,而不是對 `os.path.basename()` 的結果做——
    這是 [C4] 最容易寫錯的一步:`basename("../../evil")` 是 `"evil"`,四項
    「不含 `/`、非空、非 `.`/`..`」全部通過,於是攻擊者送 `../../evil` 進來,
    實作「修正」成 `evil` 並且**寫出去**,測試還是綠的。AC 明文寫著這種檔案
    必須 **raise**,不得回退成寫入原始字串,更不該替他挑一個能寫的位置。
    `basename` 因此退居**最後一道等值斷言**(`basename(name) == name`),
    只用來擋「本平台認得、而上面規則沒列到」的分隔符。

    淨化規則**平台無關**(決策 21):在 Linux 上跑也要擋 Windows 的四類,否則
    今天在 Linux 生出來的惡意 `.qvt`,等到別人在 Windows 解才發作。

    例外訊息**不回填檔名**——那是攻擊者控制的字串,進了 log / 工單就是注入面,
    而且檔名本身也是決策 9 要保護的中繼資料(鐵律 5 的同一條理由)。
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise QVaultFormatError("embedded file name must be bytes")
    data = bytes(raw)

    # 長度:UTF-8 **位元組**數。先於 decode,免得先吃下一個 4KB 的字串。
    if not data:
        raise QVaultFormatError("embedded file name is empty")
    if len(data) > MAX_NAME_BYTES:
        raise QVaultFormatError(
            f"embedded file name longer than {MAX_NAME_BYTES} bytes"
        )

    # UTF-8 strict:`errors="replace"` 會把壞位元組變成 U+FFFD,等於替攻擊者
    # 造一個新檔名(而且 `\x00` 之類會消失)。
    try:
        name = data.decode("utf-8")
    except UnicodeDecodeError:
        raise QVaultFormatError("embedded file name is not valid UTF-8") from None

    if name in (".", ".."):
        raise QVaultFormatError("embedded file name is a directory reference")

    for ch in name:
        if ch in _FORBIDDEN_NAME_CHARS:
            raise QVaultFormatError(
                "embedded file name contains a path separator or drive/stream marker"
            )
        if ord(ch) <= 0x1F:
            raise QVaultFormatError("embedded file name contains a control character")

    # Windows 專屬三類(決策 21;控制字元已在上面一起擋掉)。
    if name.endswith(".") or name.endswith(" "):
        raise QVaultFormatError("embedded file name ends with a dot or space")
    if name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        raise QVaultFormatError("embedded file name is a reserved device name")

    # 最後一道:本平台的 basename 必須就是它自己。
    if os.path.basename(name) != name:
        raise QVaultFormatError("embedded file name is not a bare file name")
    return name


def _resolve_target(out_dir: Path, name: str) -> Path:
    """`out_dir/name`,並斷言 realpath 之後仍在 `realpath(out_dir)` **之下**。

    `_sanitize_name` 已經保證 `name` 是個裸檔名,這一層擋的是另一種逃逸:
    `out_dir/name` 自己是一條**指向外面的符號連結**(攻擊者先放好連結,再誘使
    你解一個同名的 `.qvt`)。`realpath` 會把連結解開,於是 dirname 不再等於
    `realpath(out_dir)`,當場拒絕。
    """
    real_dir = Path(os.path.realpath(out_dir))
    target = real_dir / name
    real_target = Path(os.path.realpath(target))
    if real_target.parent != real_dir or real_target.name != name:
        raise QVaultFormatError("resolved output path escapes the output directory")
    return target


# ---------------------------------------------------------------- chunk 0


def _pack_chunk0(name: str, orig_size: int) -> bytes:
    """`name_len(2B BE) ‖ name_utf8 ‖ orig_size(8B BE)` 補零到 `CHUNK0_PLAINTEXT_LEN`。"""
    name_b = name.encode("utf-8")
    if len(name_b) + _CHUNK0_OVERHEAD > CHUNK0_PLAINTEXT_LEN:
        raise QVaultFormatError("file name does not fit in chunk 0")
    if orig_size < 0 or orig_size > 2**64 - 1:
        raise QVaultFormatError("orig_size does not fit in 8 bytes")
    body = (
        len(name_b).to_bytes(2, "big") + name_b + orig_size.to_bytes(8, "big")
    )
    return body + bytes(CHUNK0_PLAINTEXT_LEN - len(body))


def _parse_chunk0(plaintext: bytes) -> tuple[bytes, int]:
    """chunk 0 的明文 → `(name_bytes, orig_size)`;佈局不符一律 `QVaultFormatError`。

    這裡的輸入**已經通過 AEAD 驗證**,但那只代表「持密碼者寫的」,不代表善意
    (決策 17)——所以每個欄位仍逐項檢,`name_len` 與剩餘長度不符即 [M5] 那條。
    """
    if len(plaintext) != CHUNK0_PLAINTEXT_LEN:
        raise QVaultFormatError("chunk 0 has the wrong plaintext length")
    name_len = int.from_bytes(plaintext[:2], "big")
    end = 2 + name_len
    if end + 8 > CHUNK0_PLAINTEXT_LEN:
        raise QVaultFormatError("chunk 0 name_len disagrees with the remaining length")
    name_b = plaintext[2:end]
    orig_size = int.from_bytes(plaintext[end : end + 8], "big")
    padding = plaintext[end + 8 :]
    if padding != bytes(len(padding)):
        raise QVaultFormatError("chunk 0 padding is not zero")
    return name_b, orig_size


# ---------------------------------------------------------------- 串流工具


def _chunk_limit(index: int, chunk_size: int) -> int:
    """第 `index` 塊**落盤**的位元組數上限(= 非末塊時的確切長度)。

    chunk 0 是定長的中繼資料塊,資料塊則是 `chunk_size` 明文 + 16B tag。
    解密端只靠這個函式與剩餘位元組數決定界線,**不試誤**([H2])。
    """
    return CHUNK0_SEALED_LEN if index == 0 else chunk_size + TAG_LEN


def _read_exactly(fh, size: int) -> bytes:
    """讀滿 `size` 個位元組;讀不滿代表檔案在腳下變短了。"""
    buf = fh.read(size)
    if len(buf) != size:
        raise QVaultFormatError("input file ended earlier than its declared size")
    return buf


def _open_private(directory: Path) -> tuple[int, Path]:
    """在 `directory` 下開一個 `0o600` 的暫存檔,回 `(fd, path)`。

    `mkstemp` 建立時就是 `0o600` 且 `O_EXCL`(不會撞到既有檔案、不會有讓別人
    先看到寬鬆權限的時間窗);後面那行 `chmod` 只是把 [M9] 寫成可讀的斷言。
    **同目錄**是必要條件:`os.replace()` 只在同一個檔案系統上才是原子的。
    """
    fd, raw = tempfile.mkstemp(dir=str(directory), prefix=".qvault-", suffix=".part")
    path = Path(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows 上 chmod 近乎 no-op([M9] 已列為已知上限);不得因此中斷,
        # 也不得因此跳過其他硬化——mkstemp 本身已是 0o600 + O_EXCL。
        pass
    return fd, path


def _write_all(fd: int, data: bytes) -> None:
    """把 `data` **全部**寫進 `fd`。

    `os.write()` 允許部分寫入(訊號打斷、大緩衝區),而部分寫入在這裡是靜默的
    資料損毀:`.qvt` 少幾個位元組要到解密時才發作,還原的明文少幾個位元組則
    連 `orig_size` 那條斷言都可能剛好躲過(若同時少讀)。故一律迴圈寫滿。
    """
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _discard(fd: int | None, path: Path | None) -> None:
    """關閉並刪除暫存檔——失敗路徑上**絕不**留下未驗證的明文(決策 16)。"""
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    if path is not None:
        try:
            os.unlink(path)
        except OSError:
            pass


# ---------------------------------------------------------------- 加密


def encrypt_file(
    inp: str | os.PathLike[str],
    out: str | os.PathLike[str],
    passphrase: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    force: bool = False,
) -> Path:
    """把 `inp` 加密成 `.qvt` 寫到 `out`,回傳 `Path(out)`。

    流程逐字照 AC:gen DEK → `ScryptKEK.wrap` → 組 header →
    `nonce_prefix = secrets.token_bytes(7)` → chunk 0 = 加密的中繼資料 →
    chunk 1..n = 資料,每塊 nonce = `nonce_for`、**AAD = header 全段** → 寫檔。

    `salt` 與 `nonce_prefix` **每檔重新產生**(決策 10 / [C1])。常數 salt 等於
    全世界所有檔案共用一把 KEK,一張 scrypt 彩虹表通吃;`nonce_prefix` 一旦跨檔
    重複,`(prefix ‖ counter)` 就不再唯一,而 GCM 的 nonce 重用會洩明文差值、
    進而解出 GHASH 子鑰。兩者一律取自 `secrets`(決策 20),**不由**密碼/檔名/
    路徑/時間/任何雜湊派生。

    KDF 成本參數不開放覆寫:正規路徑恆為 `ScryptKEK` 的預設 15/8/1,且 header
    寫的就是**這個 KEK 實例自己的**參數([M3];兩邊取同一個來源,結構上不可能漂)。

    `chunk_size` 只影響分塊,合法值由 `QVaultHeader` 把關(`[4096, 1048576]`
    且為 2 的冪);寫進 header,解密端照著讀。

    `out` 已存在時**預設拒絕**(`force=True` 才覆寫)——見 `.asp/pr/4.md`。
    """
    inp_path = Path(inp)
    out_path = Path(out)

    # 原檔名要能被**還原端**接受,否則就是寫出一個自己解不開的檔:淨化規則
    # 兩端同一套,寧可在加密時當場說清楚,也不要留到解密才發作。
    try:
        name_bytes = inp_path.name.encode("utf-8")
    except UnicodeEncodeError:
        raise QVaultFormatError("input file name is not encodable as UTF-8") from None
    try:
        name = _sanitize_name(name_bytes)
    except QVaultFormatError as exc:
        # 訊息要可操作:使用者拿到的是「改個名字再試」,不是一句佈局術語。
        # `exc` 的訊息**不含檔名**(`test_sanitize_never_echoes_the_name` 守著),
        # 故照抄不會把攻擊者/使用者的字串帶進 log。
        raise QVaultFormatError(
            f"input file name cannot be restored on every platform ({exc}); "
            "rename the file and encrypt again"
        ) from None

    if out_path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing output: {out_path}")

    fd: int | None = None
    tmp_path: Path | None = None
    try:
        with open(inp_path, "rb") as src:
            orig_size = os.fstat(src.fileno()).st_size
            chunk_count = body_chunk_count(orig_size, chunk_size)
            if chunk_count - 1 > MAX_CHUNK_INDEX:
                raise QVaultFormatError("input file needs more chunks than uint32 allows")

            dek = gen_dek()
            kek = ScryptKEK(passphrase, secrets.token_bytes(SALT_LEN))
            header = QVaultHeader(
                salt=kek.salt,
                nonce_prefix=secrets.token_bytes(NONCE_PREFIX_LEN),
                wrapped_dek=kek.wrap(dek),
                chunk_size=chunk_size,
                kdf_log2n=kek.log2n,
                kdf_r=kek.r,
                kdf_p=kek.p,
                kem_id=ScryptKEK.kem_id,
            )
            aad = header.aad()  # 決策 12:AAD == header 全段,每塊都用同一份

            fd, tmp_path = _open_private(out_path.parent)
            _write_all(fd, aad)
            _write_all(
                fd,
                seal(
                    dek,
                    nonce_for(header.nonce_prefix, 0, is_last_chunk(0, chunk_count)),
                    _pack_chunk0(name, orig_size),
                    aad,
                ),
            )

            remaining = orig_size
            for index in range(1, chunk_count):
                take = min(chunk_size, remaining)
                data = _read_exactly(src, take)
                remaining -= take
                _write_all(
                    fd,
                    seal(
                        dek,
                        nonce_for(
                            header.nonce_prefix,
                            index,
                            is_last_chunk(index, chunk_count),
                        ),
                        data,
                        aad,
                    ),
                )
            if src.read(1):
                raise QVaultFormatError("input file grew while it was being encrypted")

            os.fsync(fd)
            os.close(fd)
            fd = None

            # `os.replace` **自己**也會失敗:`out` 是個目錄(IsADirectoryError)、
            # sticky-bit 目錄裡的同名檔屬於他人(EPERM)、跨裝置(EXDEV)。失敗的
            # 那一刻暫存檔已經是完整的資料,它必須跟其他步驟走同一條清理路徑——
            # 決策 16 的「**任一步**失敗必須 unlink 暫存檔後 raise」包含最後這一步。
            os.replace(tmp_path, out_path)
            tmp_path = None  # 已改名,`_discard` 不該再碰這個路徑
    except BaseException:
        _discard(fd, tmp_path)
        raise

    return out_path


# ---------------------------------------------------------------- 解密


def decrypt_file(
    inp: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    passphrase: str,
    *,
    force: bool = False,
) -> Path:
    """把 `.qvt` 還原到 `out_dir`,回傳實際寫出的路徑([M8])。

    檔名取自 chunk 0 並經 `_sanitize_name` 淨化;目標已存在**預設拒絕**
    (`force=True` 才覆寫)。

    整條路徑的三個不變式,少一個都是 AC 明列的洞:

    1. **原子性**:明文只落在 `out_dir` 下的 `0o600` 暫存檔,全部驗完才
       `os.replace()`;任一步失敗即 unlink 再 raise(決策 16 / [C3])。
    2. **`is_last` 由剩餘位元組數推導**,末塊必須真的以 flag=`0x01` 開啟,
       且還原長度必須等於 chunk 0 宣告的 `orig_size`([H2])。
    3. **KDF 參數取自 header**,不是硬編碼的 15/8/1([M3])——`deserialize`
       已先把它們的界限檢完(決策 15),`Scrypt` 才會被呼叫。
    """
    inp_path = Path(inp)
    dir_path = Path(out_dir)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"output directory does not exist: {dir_path}")

    fd: int | None = None
    tmp_path: Path | None = None
    try:
        with open(inp_path, "rb") as src:
            total = os.fstat(src.fileno()).st_size
            header, body_offset = deserialize(src.read(HEADER_SIZE_KEM1))
            aad = header.serialize()[:body_offset]
            src.seek(body_offset)

            # KDF 參數一律讀 header([M3]);失敗直接讓 kek 的 QVaultDecryptError
            # 往上走,本層一個字都不加(保證③ / [M4])。
            dek = ScryptKEK(
                passphrase,
                header.salt,
                log2n=header.kdf_log2n,
                r=header.kdf_r,
                p=header.kdf_p,
            ).unwrap(header.wrapped_dek)

            remaining = total - body_offset
            if remaining <= 0:
                # 只有 header:一個 chunk 都沒有(chunk 0 一定存在)。
                raise QVaultDecryptError(_STREAM_BROKEN)

            index = 0
            saw_last = False
            written = 0
            orig_size: int | None = None
            target: Path | None = None

            while remaining > 0:
                if index > MAX_CHUNK_INDEX:
                    raise QVaultDecryptError(_STREAM_BROKEN)
                limit = _chunk_limit(index, header.chunk_size)
                is_last = remaining <= limit  # [H2]:由剩餘位元組數推導,不試誤
                take = remaining if is_last else limit
                plaintext = unseal(
                    dek,
                    nonce_for(header.nonce_prefix, index, is_last),
                    _read_exactly(src, take),
                    aad,
                )
                remaining -= take
                saw_last = is_last

                if index == 0:
                    name_bytes, orig_size = _parse_chunk0(plaintext)
                    target = _resolve_target(dir_path, _sanitize_name(name_bytes))
                    if target.exists() and not force:
                        raise FileExistsError(
                            f"refusing to overwrite existing output: {target}"
                        )
                    # 暫存檔在**確定目標**之後才建立:淨化沒過的檔案,連一個
                    # 空的暫存檔都不該在受害者的目錄裡出現過。
                    fd, tmp_path = _open_private(target.parent)
                else:
                    _write_all(fd, plaintext)
                    written += len(plaintext)
                index += 1

            # [H2] 迴圈結束後的三條斷言。`index` 至少是 1(remaining > 0 已保證
            # 至少跑一圈),仍明寫出來:這三條是「刪末塊 / 多接一塊 / 重排」唯一
            # 的守門人,不該靠讀者自己從迴圈條件推。
            if index < 1 or not saw_last:
                raise QVaultDecryptError(_STREAM_BROKEN)
            if orig_size is None or written != orig_size:
                raise QVaultDecryptError(_STREAM_BROKEN)

            os.fsync(fd)
            os.close(fd)
            fd = None

            # `os.replace` **自己**也會失敗:`out` 是個目錄(IsADirectoryError)、
            # sticky-bit 目錄裡的同名檔屬於他人(EPERM)、跨裝置(EXDEV)。失敗的
            # 那一刻暫存檔已經是完整的資料,它必須跟其他步驟走同一條清理路徑——
            # 決策 16 的「**任一步**失敗必須 unlink 暫存檔後 raise」包含最後這一步。
            os.replace(tmp_path, target)
            tmp_path = None  # 已改名,`_discard` 不該再碰這個路徑
    except BaseException:
        _discard(fd, tmp_path)
        raise

    try:
        os.chmod(target, 0o600)  # [M9];Windows 上近乎 no-op,見 _open_private
    except OSError:
        pass
    return target
