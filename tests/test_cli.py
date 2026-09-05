"""CLI 的測試(AC #5;設計見 ADR-001「模組切法」與 `qvault_core/cli.py` 的 docstring)。

三類必備測試(AGENTS.md 鐵律 4)在本檔的落點:
  round-trip → `test_roundtrip_*`(空檔、多塊、非 ASCII 檔名、預設 out-dir)
  tamper     → `test_wrong_passphrase_*` / `test_tampered_*` / `test_truncated_*`
  邊界       → 缺檔、壞 magic、壞 version、目標已存在、`--out-dir` 不是目錄、
               空密碼、兩次不一致、Ctrl-C、沒有 stdin

外加兩條**結構性**測試,守的是「不會在測試裡自己現形」的規矩:
  `test_no_option_anywhere_takes_a_passphrase`  —— 密碼不得進 argv
  `test_cli_never_reads_the_secret_header_fields` —— [M7] 白名單(AST 掃描)

`fast_kdf` 與 `tests/test_vault.py` 的那個是同一招(只換掉 `kek._scrypt`,
`log2n/r/p/salt` 與 header 欄位全維持正規值),讓一輪 encrypt→decrypt 不必燒
兩次 80ms 的 scrypt;走**真** scrypt 的測試(golden 向量、entry point 的
subprocess 那條)刻意不吃這個夾具。
"""

from __future__ import annotations

import ast
import hashlib
import os
import pathlib
import subprocess
import sys

import pytest

from qvault_core import cli
from qvault_core import kek as kek_mod
from qvault_core.container import HEADER_SIZE_KEM1, deserialize

# ---------------------------------------------------------------- 夾具與工具

PW = "correct horse battery staple"
WRONG_PW = "incorrect horse battery staple"
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"
GOLDEN_PW = "correct horse"

#: [M7] 一個 byte 都不准出現在 `inspect` 輸出裡的 header 欄位。
SECRET_FIELDS = ("salt", "nonce_prefix", "wrapped_dek")


@pytest.fixture
def fast_kdf(monkeypatch):
    """把 scrypt 換成便宜但**參數敏感**的派生(同 `test_vault.py`)。

    參數敏感是重點:密碼/salt/n/r/p 任一不同就派生出不同的 KEK,所以「錯密碼」
    這類測試仍然會如實地失敗在 AEAD 驗證上。
    """

    def cheap(passphrase_bytes, salt, *, n, r, p, dklen=32):
        material = b"|".join(
            [passphrase_bytes, salt, str(n).encode(), str(r).encode(), str(p).encode()]
        )
        return hashlib.sha256(material).digest()[:dklen]

    monkeypatch.setattr(kek_mod, "_scrypt", cheap)


class _Prompter:
    """假的 `getpass`:記下每一次提問,依序吐出測試預先餵的答案。

    多問一次就 `AssertionError`——「`encrypt` 到底有沒有問第二次」這種事要由
    測試證明,不是靠讀程式碼相信。
    """

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.queue: list[str] = []

    def feed(self, *passphrases: str) -> "_Prompter":
        self.queue.extend(passphrases)
        return self

    def __call__(self, label: str = "") -> str:
        self.prompts.append(label)
        if not self.queue:
            raise AssertionError("CLI asked for more passphrases than the test fed")
        return self.queue.pop(0)


@pytest.fixture
def ask(monkeypatch):
    """接管 `getpass.getpass`;測試用 `ask.feed(...)` 排隊答案。"""
    prompter = _Prompter()
    monkeypatch.setattr(cli.getpass, "getpass", prompter)
    return prompter


def make_file(directory: pathlib.Path, name: str, size: int) -> pathlib.Path:
    """生一個 `size` 位元組、內容逐位置相異的輸入檔。"""
    path = directory / name
    pattern = bytes(range(256))
    path.write_bytes((pattern * (size // 256 + 1))[:size])
    return path


def encrypt_via_cli(ask, path: pathlib.Path, passphrase: str = PW, *args: str) -> int:
    ask.feed(passphrase, passphrase)
    return cli.main(["encrypt", str(path), *args])


def clean_failure(capsys, code: int) -> str:
    """斷言「非零 exit + stderr 恰好一行 `qvault: …` + 沒有 traceback」,回那一行。"""
    captured = capsys.readouterr()
    assert code != 0, "失敗的操作必須以非零 exit 收場"
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    lines = [line for line in captured.err.splitlines() if line]
    assert len(lines) == 1, f"錯誤輸出不是一行:{lines!r}"
    assert lines[0].startswith("qvault: "), lines[0]
    return lines[0]


def leftovers(directory: pathlib.Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


# ---------------------------------------------------------------- round-trip


@pytest.mark.parametrize("size", [0, 1, 4096, 70000])
def test_roundtrip_over_sizes(tmp_path, fast_kdf, ask, size):
    """CLI encrypt→decrypt round-trip:空檔、單 byte、剛好一塊、跨多塊。"""
    src = make_file(tmp_path, "payload.bin", size)
    original = src.read_bytes()
    assert encrypt_via_cli(ask, src) == 0

    qvt = tmp_path / "payload.bin.qvt"
    assert qvt.is_file(), "encrypt 必須產生 <f>.qvt"
    assert src.read_bytes() == original, "encrypt 不得動到原檔"

    dest = tmp_path / "out"
    dest.mkdir()
    ask.feed(PW)
    assert cli.main(["decrypt", str(qvt), "--out-dir", str(dest)]) == 0
    assert (dest / "payload.bin").read_bytes() == original


def test_encrypt_appends_the_suffix_and_prints_the_path(tmp_path, fast_kdf, ask, capsys):
    """`<f>` → `<f>.qvt`(**加**後綴,不是換副檔名);stdout 是那個路徑。"""
    src = make_file(tmp_path, "secret.txt", 10)
    assert encrypt_via_cli(ask, src) == 0
    out = capsys.readouterr().out.strip()
    assert out == str(tmp_path / "secret.txt.qvt")
    assert (tmp_path / "secret.txt.qvt").is_file()
    assert not (tmp_path / "secret.qvt").exists()


def test_decrypt_restores_the_original_name_not_the_stem(tmp_path, fast_kdf, ask):
    """檔名來自 chunk 0,不是把 `.qvt` 砍掉猜的——用一個**改過名字**的容器證明。"""
    src = make_file(tmp_path, "real-name.bin", 64)
    assert encrypt_via_cli(ask, src) == 0
    renamed = tmp_path / "anything-else.qvt"
    (tmp_path / "real-name.bin.qvt").rename(renamed)

    dest = tmp_path / "out"
    dest.mkdir()
    ask.feed(PW)
    assert cli.main(["decrypt", str(renamed), "--out-dir", str(dest)]) == 0
    assert leftovers(dest) == ["real-name.bin"]


def test_decrypt_defaults_to_the_current_directory(tmp_path, fast_kdf, ask, monkeypatch):
    """`--out-dir` 沒給就是 `.`。"""
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    here = tmp_path / "cwd"
    here.mkdir()
    monkeypatch.chdir(here)
    ask.feed(PW)
    assert cli.main(["decrypt", str(tmp_path / "payload.bin.qvt")]) == 0
    assert (here / "payload.bin").read_bytes() == src.read_bytes()


def test_roundtrip_with_a_non_ascii_name(tmp_path, fast_kdf, ask):
    """非 ASCII 檔名(決策 9 把檔名加密進 chunk 0)也要原封不動回來。"""
    src = make_file(tmp_path, "機密-報告.txt", 100)
    assert encrypt_via_cli(ask, src) == 0
    dest = tmp_path / "out"
    dest.mkdir()
    ask.feed(PW)
    assert cli.main(["decrypt", str(tmp_path / "機密-報告.txt.qvt"), "--out-dir", str(dest)]) == 0
    assert leftovers(dest) == ["機密-報告.txt"]


def test_decrypt_prints_the_path_it_actually_wrote(tmp_path, fast_kdf, ask, capsys):
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    capsys.readouterr()
    dest = tmp_path / "out"
    dest.mkdir()
    ask.feed(PW)
    assert cli.main(["decrypt", str(tmp_path / "payload.bin.qvt"), "--out-dir", str(dest)]) == 0
    assert pathlib.Path(capsys.readouterr().out.strip()).read_bytes() == src.read_bytes()


# ---------------------------------------------------------------- 密碼


def test_encrypt_asks_twice_and_decrypt_once(tmp_path, fast_kdf, ask):
    """encrypt 二次確認;decrypt 只問一次(多問一次 `_Prompter` 會當場炸)。"""
    src = make_file(tmp_path, "payload.bin", 16)
    assert encrypt_via_cli(ask, src) == 0
    assert len(ask.prompts) == 2

    ask.prompts.clear()
    dest = tmp_path / "out"
    dest.mkdir()
    ask.feed(PW)
    assert cli.main(["decrypt", str(tmp_path / "payload.bin.qvt"), "--out-dir", str(dest)]) == 0
    assert len(ask.prompts) == 1


def test_encrypt_rejects_mismatched_confirmation(tmp_path, fast_kdf, ask, capsys):
    """兩次不一致 → 不產生任何檔案(打錯字的密碼 = 誰也解不開的檔)。"""
    src = make_file(tmp_path, "payload.bin", 16)
    ask.feed(PW, PW + "x")
    line = clean_failure(capsys, cli.main(["encrypt", str(src)]))
    assert "match" in line
    assert leftovers(tmp_path) == ["payload.bin"]


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
def test_empty_passphrase_is_refused(tmp_path, fast_kdf, ask, capsys, command):
    """[L] 空密碼直接拒絕——空字串不是弱,是無。"""
    src = make_file(tmp_path, "payload.bin", 16)
    if command == "decrypt":
        assert encrypt_via_cli(ask, src) == 0
        capsys.readouterr()
        target, extra = tmp_path / "payload.bin.qvt", ["--out-dir", str(tmp_path)]
    else:
        target, extra = src, []
    ask.prompts.clear()
    ask.feed("")
    line = clean_failure(capsys, cli.main([command, str(target), *extra]))
    assert "empty" in line
    # 只問一次就收工:空字串不必再問確認,也不必燒一次 KDF。
    assert len(ask.prompts) == 1


def test_no_option_anywhere_takes_a_passphrase():
    """密碼**不得**進 argv:掃過所有子解析器的所有選項字串與 metavar。

    進了 argv 的密碼會躺在 shell history、`ps aux` 與 CI log 裡;這條擋的是
    「加個 `--password` 比較好測」那種手滑。
    """
    banned = ("pass", "pw", "secret", "key", "phrase")
    parser = cli._build_parser()
    seen = 0
    for action in parser._actions:  # noqa: SLF001 —— 只有這條路能列舉子解析器
        choices = getattr(action, "choices", None) or {}
        subparsers = [p for p in choices.values() if hasattr(p, "_actions")]
        for sub in [parser, *subparsers]:
            for sub_action in sub._actions:  # noqa: SLF001
                seen += 1
                names = [*sub_action.option_strings, sub_action.dest]
                for name in names:
                    assert not any(b in name.lower() for b in banned), name
    assert seen > 0, "沒有掃到任何選項,測試本身壞了"


def test_cli_calls_getpass_and_never_reads_a_passphrase_from_the_environment():
    """密碼的唯一來源是 `getpass`:原始碼裡沒有 `os.environ` / `input(` / `sys.stdin`。"""
    source = (REPO_ROOT / "qvault_core" / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = {
        f"{ast.unparse(node.func)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert "getpass.getpass" in calls
    assert not any(c in calls for c in ("input", "os.environ.get", "os.getenv"))
    assert "sys.stdin" not in source


def test_passphrase_with_unencodable_characters_fails_cleanly(tmp_path, fast_kdf, ask, capsys):
    """孤兒代理對(Windows argv / 某些輸入法)→ 乾淨訊息,且**不回顯那個字元**。"""
    src = make_file(tmp_path, "payload.bin", 16)
    bad = "abc\udcff"
    ask.feed(bad, bad)
    line = clean_failure(capsys, cli.main(["encrypt", str(src)]))
    assert "UTF-8" in line
    assert "\udcff" not in line


def test_interrupt_at_the_prompt_is_not_a_traceback(tmp_path, fast_kdf, monkeypatch, capsys):
    """Ctrl-C 是最常見的「使用者按了鍵」,不該噴 traceback。"""
    def boom(label=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.getpass, "getpass", boom)
    src = make_file(tmp_path, "payload.bin", 16)
    code = cli.main(["encrypt", str(src)])
    assert code == cli.EXIT_INTERRUPT
    assert "interrupted" in clean_failure(capsys, code)


def test_no_stdin_is_a_clean_error(tmp_path, fast_kdf, monkeypatch, capsys):
    """`getpass` 在沒有 tty/stdin 時丟 `EOFError`——翻成一句話,不是 traceback。"""
    def boom(label=""):
        raise EOFError

    monkeypatch.setattr(cli.getpass, "getpass", boom)
    src = make_file(tmp_path, "payload.bin", 16)
    assert "terminal" in clean_failure(capsys, cli.main(["encrypt", str(src)]))


def test_passphrase_never_reaches_stdout_or_stderr(tmp_path, fast_kdf, ask, capsys):
    """密碼不進任何輸出——成功路徑與失敗路徑各測一次(鐵律 5)。"""
    marker = "S3cr3t-pw-marker"
    src = make_file(tmp_path, "payload.bin", 16)
    ask.feed(marker, marker)
    assert cli.main(["encrypt", str(src)]) == 0
    ask.feed("another-" + marker)
    cli.main(["decrypt", str(tmp_path / "payload.bin.qvt"), "--out-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert marker not in captured.out
    assert marker not in captured.err


# ---------------------------------------------------------------- [M7] inspect


def read_header(path: pathlib.Path):
    return deserialize(path.read_bytes()[:HEADER_SIZE_KEM1])[0]


def test_inspect_prints_exactly_the_whitelist(tmp_path, fast_kdf, ask, capsys):
    """[M7] 白名單:version、三個 id、log2n/r/p、chunk_size、磁碟位元組數——就這些。"""
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    capsys.readouterr()

    assert cli.main(["inspect", str(qvt)]) == 0
    out = capsys.readouterr().out
    labels = [line.split(":", 1)[0] for line in out.splitlines() if line.strip()]
    assert labels == [
        "version",
        "kdf_id",
        "aead_id",
        "kem_id",
        "kdf_log2n",
        "kdf_r",
        "kdf_p",
        "chunk_size",
        "file_size",
    ]

    header = read_header(qvt)
    assert f"version: {header.version}" in " ".join(out.split())
    for label, value in (
        ("kdf_log2n", header.kdf_log2n),
        ("kdf_r", header.kdf_r),
        ("kdf_p", header.kdf_p),
        ("chunk_size", header.chunk_size),
    ):
        assert f"{label}: {value}" in " ".join(out.split())
    assert f"file_size: {qvt.stat().st_size} bytes" in " ".join(out.split())
    assert "scrypt" in out and "AES-256-GCM" in out


def hex_windows(raw: bytes, width: int = 4) -> set[str]:
    """`raw` 的所有 ≥`width` 位元組連續片段的 hex(含大小寫)——「任一段」的意思。"""
    text = raw.hex()
    windows = set()
    for start in range(0, len(text) - 2 * width + 1, 2):
        for end in range(start + 2 * width, len(text) + 1, 2):
            windows.add(text[start:end])
    return windows | {w.upper() for w in windows}


@pytest.mark.parametrize("field", SECRET_FIELDS)
def test_inspect_output_contains_no_hex_of_the_secret_fields(
    tmp_path, fast_kdf, ask, capsys, field
):
    """[M7] AC 明列的那條:stdout 不含 salt/`nonce_prefix`/`wrapped_dek` **任一段**的 hex。

    「任一段」照字面測:≥4 位元組的所有連續切片,大小寫都算(hex 截斷也不行——
    wrapped DEK 進了終端截圖或工單,攻擊者不需要那個檔案就能離線爆密碼)。
    """
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    capsys.readouterr()

    assert cli.main(["inspect", str(qvt)]) == 0
    out = capsys.readouterr().out
    raw = getattr(read_header(qvt), field)
    assert len(raw) >= 4
    assert not any(window in out for window in hex_windows(raw))
    assert raw.hex() not in out


def test_inspect_output_contains_no_raw_secret_bytes(tmp_path, fast_kdf, ask, capsys):
    """連 base64/latin-1 之類的「其他表示」也順手擋掉:輸出必須是純 ASCII 欄位表。"""
    import base64

    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    capsys.readouterr()
    assert cli.main(["inspect", str(qvt)]) == 0
    out = capsys.readouterr().out
    header = read_header(qvt)
    for field in SECRET_FIELDS:
        raw = getattr(header, field)
        assert base64.b64encode(raw).decode() not in out
        assert raw.decode("latin-1") not in out
        assert str(list(raw)) not in out


def test_inspect_does_not_leak_the_protected_metadata(tmp_path, fast_kdf, ask, capsys):
    """[M7] 決策 9 保護的中繼資料(原始檔名、原始大小)不得出現在輸出裡。"""
    src = make_file(tmp_path, "payroll-2026.csv", 12345)
    assert encrypt_via_cli(ask, src) == 0
    capsys.readouterr()
    assert cli.main(["inspect", str(tmp_path / "payroll-2026.csv.qvt")]) == 0
    out = capsys.readouterr().out
    assert "payroll" not in out
    assert "12345" not in out  # 原始大小;印的是 .qvt 自己的位元組數


def test_inspect_needs_no_passphrase(tmp_path, fast_kdf, ask, capsys):
    """`inspect` 一次也不准問密碼(問了 `_Prompter` 的空佇列會炸)。"""
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    ask.prompts.clear()
    capsys.readouterr()
    assert cli.main(["inspect", str(tmp_path / "payload.bin.qvt")]) == 0
    assert ask.prompts == []


def test_inspect_reads_only_the_header(tmp_path, fast_kdf, ask, capsys):
    """`inspect` 不碰 body:把 header 之後全部砍掉,它照樣印得出來。

    這同時證明它沒有為了顯示原始大小去解 chunk 0(那要密碼)。
    """
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    header_only = tmp_path / "header-only.qvt"
    header_only.write_bytes(qvt.read_bytes()[:HEADER_SIZE_KEM1])
    capsys.readouterr()
    assert cli.main(["inspect", str(header_only)]) == 0
    out = capsys.readouterr().out
    assert f"file_size: {HEADER_SIZE_KEM1} bytes" in " ".join(out.split())


def test_cli_never_reads_the_secret_header_fields():
    """[M7] 結構性守門:`cli.py` 的**程式碼**裡沒有 `.salt` / `.nonce_prefix` /
    `.wrapped_dek` 的取值,也沒有這些名字的變數。

    白名單靠 `_INSPECT_FIELDS` 一張表維持;這條測試擋的是「臨時 debug 印一下」
    留在樹上,或有人把白名單改寫成 `vars(header)` 迴圈。
    """
    tree = ast.parse((REPO_ROOT / "qvault_core" / "cli.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in SECRET_FIELDS, ast.unparse(node)
        if isinstance(node, ast.Name):
            assert node.id not in SECRET_FIELDS, node.id
    # 反射式的全欄位傾印也一併擋掉。
    calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"vars", "asdict", "dataclasses.asdict", "repr"}


def test_inspect_whitelist_table_is_the_only_source_of_fields():
    """白名單表本身也要對得上 AC 那一行(表被改掉,這裡當場失敗)。"""
    assert [label for label, _ in cli._INSPECT_FIELDS] == [
        "version",
        "kdf_id",
        "aead_id",
        "kem_id",
        "kdf_log2n",
        "kdf_r",
        "kdf_p",
        "chunk_size",
    ]


def test_inspect_on_the_golden_vector(capsys):
    """[M2] golden 是 repo 裡唯一一個「已知位元佈局」的 `.qvt`——inspect 對它逐欄。

    這條不吃 `fast_kdf`(inspect 根本不碰 KDF),故它同時證明 inspect 不解密。
    """
    assert cli.main(["inspect", str(GOLDEN)]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "version: 1" in out
    assert "kdf_id: 1 (scrypt)" in out
    assert "aead_id: 1 (AES-256-GCM)" in out
    assert "kem_id: 1 (scrypt-KEK)" in out
    assert "kdf_log2n: 15" in out
    assert f"file_size: {GOLDEN.stat().st_size} bytes" in out
    assert "0101010101010101" not in out  # golden 的 salt
    assert "0202020202020202" not in out  # golden 的 nonce_prefix
    assert "0404040404040404" not in out  # golden 的 wrap_nonce


# ---------------------------------------------------------------- 錯誤路徑


def test_wrong_passphrase_exits_nonzero_without_a_traceback(tmp_path, fast_kdf, ask, capsys):
    """錯密碼:非零 exit、一行訊息、無 traceback、`out-dir` 零殘留。"""
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    dest = tmp_path / "out"
    dest.mkdir()
    capsys.readouterr()

    ask.feed(WRONG_PW)
    line = clean_failure(
        capsys,
        cli.main(["decrypt", str(tmp_path / "payload.bin.qvt"), "--out-dir", str(dest)]),
    )
    assert line == "qvault: AEAD authentication failed"
    assert leftovers(dest) == [], "失敗的解密不得留下任何檔案(含暫存檔)"


def test_wrong_passphrase_message_does_not_guess(tmp_path, fast_kdf, ask, capsys):
    """保證③:錯密碼與竄改**不可區分**——CLI 不得自己加「密碼可能錯誤」。"""
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    dest = tmp_path / "out"
    dest.mkdir()
    capsys.readouterr()

    ask.feed(WRONG_PW)
    wrong_pw_line = clean_failure(
        capsys, cli.main(["decrypt", str(qvt), "--out-dir", str(dest)])
    )

    raw = bytearray(qvt.read_bytes())
    raw[-1] ^= 0x01  # 改最後一個 byte(tag)
    tampered = tmp_path / "tampered.qvt"
    tampered.write_bytes(bytes(raw))
    ask.feed(PW)
    tampered_line = clean_failure(
        capsys, cli.main(["decrypt", str(tampered), "--out-dir", str(dest)])
    )

    assert wrong_pw_line == tampered_line
    for word in ("passphrase", "password", "wrong", "incorrect", "tamper"):
        assert word not in wrong_pw_line.lower()


@pytest.mark.parametrize("offset", [0, 5, 20, 41, -1])
def test_tampered_container_fails_cleanly(tmp_path, fast_kdf, ask, capsys, offset):
    """tamper:header(magic/algo-id/salt 區)與密文各改一 byte,都要乾淨失敗。"""
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    raw = bytearray((tmp_path / "payload.bin.qvt").read_bytes())
    raw[offset] ^= 0x01
    bad = tmp_path / "bad.qvt"
    bad.write_bytes(bytes(raw))
    dest = tmp_path / "out"
    dest.mkdir()
    capsys.readouterr()

    ask.feed(PW)
    clean_failure(capsys, cli.main(["decrypt", str(bad), "--out-dir", str(dest)]))
    assert leftovers(dest) == []


def test_truncated_container_fails_cleanly(tmp_path, fast_kdf, ask, capsys):
    src = make_file(tmp_path, "payload.bin", 300)
    assert encrypt_via_cli(ask, src) == 0
    raw = (tmp_path / "payload.bin.qvt").read_bytes()
    truncated = tmp_path / "cut.qvt"
    truncated.write_bytes(raw[: len(raw) - 8])
    dest = tmp_path / "out"
    dest.mkdir()
    capsys.readouterr()
    ask.feed(PW)
    clean_failure(capsys, cli.main(["decrypt", str(truncated), "--out-dir", str(dest)]))
    assert leftovers(dest) == []


@pytest.mark.parametrize("command", ["encrypt", "decrypt", "inspect"])
def test_missing_file_is_a_clean_error(tmp_path, fast_kdf, ask, capsys, command):
    """缺檔:三個子命令都一行訊息 + 非零 exit,而且**不先問密碼**。"""
    line = clean_failure(capsys, cli.main([command, str(tmp_path / "nope.qvt")]))
    assert "does not exist" in line
    assert ask.prompts == []


@pytest.mark.parametrize("command", ["decrypt", "inspect"])
def test_garbage_input_is_a_clean_error(tmp_path, fast_kdf, ask, capsys, command):
    """壞檔(不是 `.qvt`)→ `bad magic`,不是 traceback。"""
    junk = tmp_path / "junk.qvt"
    junk.write_bytes(b"not a qvault container at all, really" * 8)
    ask.feed(PW)
    line = clean_failure(capsys, cli.main([command, str(junk)]))
    assert "magic" in line


def test_empty_input_file_is_a_clean_error(tmp_path, fast_kdf, ask, capsys):
    """0 位元組的「容器」:截斷路徑也要乾淨。"""
    empty = tmp_path / "empty.qvt"
    empty.write_bytes(b"")
    assert "truncated" in clean_failure(capsys, cli.main(["inspect", str(empty)]))


def test_unknown_version_is_a_clean_error(tmp_path, fast_kdf, ask, capsys):
    """未知 version(`QVaultVersionError`)也走同一條乾淨出口。"""
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    raw = bytearray((tmp_path / "payload.bin.qvt").read_bytes())
    raw[4] = 99
    future = tmp_path / "future.qvt"
    future.write_bytes(bytes(raw))
    capsys.readouterr()
    assert "version" in clean_failure(capsys, cli.main(["inspect", str(future)]))


@pytest.mark.parametrize("command", ["encrypt", "decrypt", "inspect"])
def test_directory_as_input_is_a_clean_error(tmp_path, fast_kdf, ask, capsys, command):
    """把目錄當輸入:訊息要說中真正的問題,而且**不先問密碼**。"""
    (tmp_path / "adir").mkdir()
    line = clean_failure(capsys, cli.main([command, str(tmp_path / "adir")]))
    assert "is a directory" in line
    assert ask.prompts == []


def test_missing_out_dir_is_a_clean_error(tmp_path, fast_kdf, ask, capsys):
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    capsys.readouterr()
    ask.feed(PW)
    line = clean_failure(
        capsys,
        cli.main([
            "decrypt",
            str(tmp_path / "payload.bin.qvt"),
            "--out-dir",
            str(tmp_path / "nowhere"),
        ]),
    )
    assert "directory does not exist" in line


def test_unexpected_exception_still_prints_no_traceback(tmp_path, fast_kdf, ask, monkeypatch, capsys):
    """我們自己的 bug 也不吐 traceback:frame 裡躺著密碼與 DEK(鐵律 5)。"""
    def boom(*a, **kw):
        raise RuntimeError("secret-looking internals " + PW)

    monkeypatch.setattr(cli, "encrypt_file", boom)
    src = make_file(tmp_path, "payload.bin", 16)
    ask.feed(PW, PW)
    line = clean_failure(capsys, cli.main(["encrypt", str(src)]))
    assert line == "qvault: internal error (RuntimeError)"
    assert PW not in line


# ---------------------------------------------------------------- 覆寫保護


def test_encrypt_refuses_to_overwrite_without_force(tmp_path, fast_kdf, ask, capsys):
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    frozen = (tmp_path / "payload.bin.qvt").read_bytes()
    capsys.readouterr()

    ask.prompts.clear()
    line = clean_failure(capsys, cli.main(["encrypt", str(src)]))
    assert "refusing to overwrite" in line
    assert (tmp_path / "payload.bin.qvt").read_bytes() == frozen
    assert ask.prompts == [], "拒絕覆寫時不該讓使用者白打兩次密碼"

    assert encrypt_via_cli(ask, src, PW, "--force") == 0
    assert (tmp_path / "payload.bin.qvt").read_bytes() != frozen  # salt/nonce 每檔重生


@pytest.mark.parametrize("flags,expected", [([], False), (["--force"], True)])
def test_force_is_forwarded_to_the_vault_layer(tmp_path, fast_kdf, ask, flags, expected):
    """`--force` 必須**傳下去**,不能只靠 CLI 自己那個「已存在」前置檢查。

    前置檢查只是為了不讓使用者白打密碼;真正的守門人是 `encrypt_file`
    (前置檢查與 `os.replace` 之間有 TOCTOU 窗口,見 `.asp/pr/4.md` 打折說明 9)。
    寫死 `force=True` 傳下去的話,那個窗口裡出現的檔案就會被默默覆寫。
    """
    seen = {}

    def spy(inp, out, passphrase, **kwargs):
        seen.update(kwargs)
        return pathlib.Path(out)

    src = make_file(tmp_path, "payload.bin", 16)
    ask.feed(PW, PW)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cli, "encrypt_file", spy)
        assert cli.main(["encrypt", str(src), *flags]) == 0
    assert seen["force"] is expected


def test_decrypt_refuses_to_overwrite_without_force(tmp_path, fast_kdf, ask, capsys):
    src = make_file(tmp_path, "payload.bin", 32)
    assert encrypt_via_cli(ask, src) == 0
    qvt = tmp_path / "payload.bin.qvt"
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "payload.bin").write_bytes(b"do not clobber me")
    capsys.readouterr()

    ask.feed(PW)
    line = clean_failure(capsys, cli.main(["decrypt", str(qvt), "--out-dir", str(dest)]))
    assert "refusing to overwrite" in line
    assert (dest / "payload.bin").read_bytes() == b"do not clobber me"

    ask.feed(PW)
    assert cli.main(["decrypt", str(qvt), "--out-dir", str(dest), "--force"]) == 0
    assert (dest / "payload.bin").read_bytes() == src.read_bytes()


# ---------------------------------------------------------------- 進入點


def test_argparse_usage_errors_exit_nonzero(capsys):
    """沒給子命令 / 給了不認得的子命令 → argparse 自己的 `SystemExit(2)`。"""
    for argv in ([], ["nosuchcommand"], ["encrypt"]):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code != 0
    assert "Traceback" not in capsys.readouterr().err


def test_pyproject_entry_point_points_here():
    """AC:`[project.scripts] qvault = "qvault_core.cli:main"` 必須指得到本檔的 `main`。"""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'qvault = "qvault_core.cli:main"' in text
    assert callable(cli.main)


def run_module(*argv: str, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    """跑真正的行程(`python -m qvault_core.cli`)——證明 exit code 真的傳得出去。"""
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "qvault_core.cli", *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


def test_entry_point_exit_code_reaches_the_shell(tmp_path):
    """`sys.exit(main())`:缺檔的那條在真行程裡也必須是非零 + 無 traceback。

    console script 的 wrapper 做的就是 `sys.exit(main())`,`python -m` 走的是本檔
    尾巴同一行——回傳值沒接上的話,shell 只會看到 0(所有 `&&` 都會誤判成功)。
    """
    done = run_module("inspect", "nope.qvt", cwd=tmp_path)
    assert done.returncode != 0
    assert "Traceback" not in done.stderr
    assert done.stderr.strip().startswith("qvault: ")
    assert done.stdout == ""


def test_entry_point_inspects_the_golden_vector_in_a_real_process(tmp_path):
    done = run_module("inspect", str(GOLDEN), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    assert "version: 1" in " ".join(done.stdout.split())
    assert done.stderr == ""
