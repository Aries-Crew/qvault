"""專案契約:相依清單、內部相依方向、禁用模組(#25)。

這一檔**不測行為**,它把專案當前的形狀**釘樁**。三件事:

1. `pyproject.toml` 的 `[project].dependencies` 與 `[dependency-groups].dev`
   **恰為**那兩份清單(AGENTS.md 鐵律 2:worker 沙箱無 pypi egress,相依漂掉
   不是「裝不起來」而是「整個迴圈派不出工」)。
2. `qvault_core` 的內部 import 圖**無環**,而且每一條邊都在一張**寫死的清單**
   裡。預設因此是「不准」:新增一條邊要有人動手改這張清單,code review 看得見。
3. `qvault_core/*.py` 一個都不 import `pickle` / `marshal` / `shelve` /
   `subprocess` / `ctypes`。

## 為什麼是寫死的清單,而不是「層數比較」

「上層不能被下層 import」這種規則要先有一份層級表才驗得起來,而那份表自己又是
一份得維護的東西。寫死邊清單少一層間接:它就是「現在長這樣」那句話的可執行版本,
而且失敗訊息直接是「多了 `vault → webui` 這條邊」,不必推理。

## 禁用 import 的掃描範圍只有 `qvault_core`

`tests/` 不在裡面,而且**不應該**在裡面:`tests/test_cli.py` 與
`tests/test_cli_ui.py` 的子程序 E2E 本來就得用 `subprocess` 起一個真的
`python -m qvault_core.cli`。這件事由
`test_the_ban_is_scoped_to_the_package_and_not_the_tests` 反向釘住——它斷言
`tests/` 裡**真的有**一個 `subprocess`,所以哪天有人把掃描範圍手滑擴到 `tests`,
那條會先紅,而不是讓子程序測試被默默刪掉。
"""

from __future__ import annotations

import ast
import pathlib
import sys
import tomllib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE_DIR = REPO_ROOT / "qvault_core"
TESTS_DIR = REPO_ROOT / "tests"

#: AGENTS.md 鐵律 2 的可驗形式:執行期相依**恰為**這一條。
EXPECTED_DEPENDENCIES = ["cryptography>=44"]
#: 開發相依**恰為**這一條(`[dependency-groups].dev`,PEP 735)。
EXPECTED_DEV_DEPENDENCIES = ["pytest>=8"]

#: 票文寫死的 15 條邊(逐字照抄 AC,一條不多一條不少)。
AC_EDGES = frozenset(
    {
        ("cli", "webui"),
        ("cli", "vault"),
        ("cli", "container"),
        ("cli", "errors"),
        ("webui", "vault"),
        ("webui", "container"),
        ("webui", "errors"),
        ("vault", "container"),
        ("vault", "aead"),
        ("vault", "kek"),
        ("vault", "errors"),
        ("kek", "aead"),
        ("kek", "errors"),
        ("container", "errors"),
        ("aead", "errors"),
    }
)

#: AC 的清單**沒有列到**套件門面(`__init__.py`)的那幾條,而 AC 同時寫著
#: 「實際以現況為準」——所以這裡把現況補齊,並且把它與 AC 那 15 條分開記帳:
#:
#: * `__init__ → {aead, container, errors, kek, vault}`:`__init__.py` 是公開
#:   API 的 re-export 面(`from .aead import …`),它 import 五個下層模組是這個
#:   套件的門面設計,不是一條新的相依方向;
#: * `cli → __init__`:`cli.py` 的 `from . import __version__`(`--version` 的
#:   來源)。方向仍是「上層 → 門面」,`__init__` 不 import `cli`,故不成環。
#:
#: 兩件事都在本票施工當時就存在(不是本票加的)。判讀寫在 `.asp/pr/25.md`。
PACKAGE_FACADE_EDGES = frozenset(
    {
        ("__init__", "aead"),
        ("__init__", "container"),
        ("__init__", "errors"),
        ("__init__", "kek"),
        ("__init__", "vault"),
        ("cli", "__init__"),
    }
)

ALLOWED_EDGES = AC_EDGES | PACKAGE_FACADE_EDGES

#: 一個都不准出現在 `qvault_core/*.py` 裡。
#:
#: `pickle` / `marshal` / `shelve`:反序列化任意位元組 = 任意程式碼執行,而這個
#: 專案讀的每一個 byte 都來自一個**可能被竄改過**的 `.qvt`。
#: `subprocess`:這是一個只碰本機檔案的庫,沒有任何理由生一個行程。
#: `ctypes`:繞過型別系統直接碰記憶體——`cryptography` 已經在做該做的那部分。
BANNED_IMPORTS = ("pickle", "marshal", "shelve", "subprocess", "ctypes")


def _module_files() -> list[pathlib.Path]:
    """`qvault_core/*.py` 全部(含 `__init__.py`),排序後回傳。"""
    files = sorted(PACKAGE_DIR.glob("*.py"))
    assert files, f"{PACKAGE_DIR} 底下一個 .py 都沒有?"
    return files


def _imports(path: pathlib.Path) -> tuple[set[str], set[str]]:
    """`(套件內部的被 import 模組名, 外部頂層模組名)`。

    內部邊只看**相對** import(`from .x import y` / `from . import y`):本專案
    一律用相對 import,而絕對 import(`import qvault_core.x`)不存在,所以兩者
    不會打架(真的冒出一個絕對 self-import,
    `test_the_only_third_party_import_in_the_package_is_cryptography` 會先紅,
    因為 `qvault_core` 不在標準庫名單裡)。

    `from . import y` 這一種的 `module` 是 `None`,此時 `y` 是**什麼**決定了邊的
    另一端:`y` 是套件裡的一個模組檔(`from . import aead`)就記 `→ aead`,否則
    (`from . import __version__` 這種從門面拿名字的)才記 `→ __init__`。這個分辨
    是必要的:一律記成 `→ __init__` 會讓 `cli.py` 的 `from . import aead` 折疊成
    已登記的 `cli → __init__`,於是一條未登記的新邊悄悄過關——而
    `test_no_internal_import_edge_outside_the_hardcoded_list` 要的正好是它會紅。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_names = {candidate.stem for candidate in PACKAGE_DIR.glob("*.py")}
    internal: set[str] = set()
    external: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            external |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.module:
                internal.add(node.module.split(".")[0])
            elif node.level:
                internal |= {
                    alias.name if alias.name in module_names else "__init__"
                    for alias in node.names
                }
            else:
                external.add((node.module or "").split(".")[0])
    return internal, external


def _graph() -> dict[str, set[str]]:
    """`qvault_core` 的內部 import 圖:`{模組名: {它 import 的模組名}}`。"""
    return {path.stem: _imports(path)[0] for path in _module_files()}


def _edges() -> set[tuple[str, str]]:
    return {(src, dst) for src, targets in _graph().items() for dst in targets}


# ---------------------------------------------------------------- 相依清單


def test_runtime_dependencies_are_exactly_the_declared_one():
    """AC:`[project].dependencies` 恰為 `["cryptography>=44"]`。

    `==` 而不是 `in`:多一條就紅。worker 沙箱裝不了新套件(AGENTS.md 鐵律 2),
    所以「多一條相依」在這個 repo 不是一個小改動,是一次派不出去的出勤。
    """
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == EXPECTED_DEPENDENCIES


def test_dev_dependencies_are_exactly_the_declared_one():
    """AC:`[dependency-groups].dev` 恰為 `["pytest>=8"]`。"""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert data["dependency-groups"]["dev"] == EXPECTED_DEV_DEPENDENCIES


def test_there_are_no_other_dependency_groups_or_optional_extras():
    """同一條的另一半:沒有第二個相依群組,也沒有 `optional-dependencies`。

    AC 只點名那兩份清單,而「把新相依藏進 `[project.optional-dependencies]` 或
    `[dependency-groups].lint`」會讓那兩條斷言照樣綠。這條把後門關上。
    """
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert sorted(data["dependency-groups"]) == ["dev"]
    assert "optional-dependencies" not in data["project"]


# ---------------------------------------------------------------- 相依方向


def test_the_internal_import_graph_is_acyclic():
    """AC:`qvault_core` 內部的 import 圖**無環**。

    三色 DFS(白 = 沒看過、灰 = 在當前這條路徑上、黑 = 走完了):碰到灰色就是
    找到一個環,而且把整條路徑印出來——「有環」這個訊息本身沒用,要看到是哪幾個
    模組圍成的。
    """
    graph = _graph()
    state: dict[str, int] = {}

    def walk(node: str, path: list[str]) -> None:
        state[node] = 1
        for nxt in sorted(graph.get(node, ())):
            if state.get(nxt, 0) == 1:
                raise AssertionError(f"import 圖有環:{' → '.join(path + [nxt])}")
            if state.get(nxt, 0) == 0:
                walk(nxt, path + [nxt])
        state[node] = 2

    for module in sorted(graph):
        if state.get(module, 0) == 0:
            walk(module, [module])


def test_no_internal_import_edge_outside_the_hardcoded_list():
    """AC:每一條內部邊都在寫死的清單裡(新邊**必須改測試**才會過)。

    這是本檔的主力:它把「相依方向」從一句口頭約定變成一個會紅的 diff。
    `ALLOWED_EDGES` 是「AC 的 15 條 + 套件門面的 6 條」,兩份分開記帳(見上面
    那兩個常數的註解)。
    """
    unexpected = sorted(_edges() - ALLOWED_EDGES)
    assert not unexpected, (
        f"出現了清單外的相依邊:{unexpected}。"
        "這不一定是錯的——但它是一個架構決定,要在 ALLOWED_EDGES 裡具名登記。"
    )


def test_the_hardcoded_edge_list_has_no_dead_entries():
    """反方向:清單裡的每一條邊**現在都真的存在**。

    只驗 `⊆` 的清單會慢慢長成一份許可證大全:某條邊被刪掉了,清單上那一行還在,
    於是它哪天又被加回來時沒有人會注意。這條讓清單維持「就是現況」。
    """
    dead = sorted(ALLOWED_EDGES - _edges())
    assert not dead, f"清單裡有已經不存在的邊,該刪了:{dead}"


def test_the_ac_edge_list_is_recorded_verbatim():
    """AC 那 15 條是**一字不動**地記在這裡,門面的 6 條是另外加的。

    把「票文寫了什麼」與「本票施工時補的現況」分成兩個常數,是為了讓下一個人
    一眼看出哪些是裁定過的、哪些是對帳出來的(#25 triage 建議 ③)。
    """
    assert len(AC_EDGES) == 15
    assert AC_EDGES <= ALLOWED_EDGES
    assert ALLOWED_EDGES - AC_EDGES == PACKAGE_FACADE_EDGES
    assert not (AC_EDGES & PACKAGE_FACADE_EDGES)
    # 門面那幾條都以 `__init__` 為一端(它們就是「門面」的定義)。
    for src, dst in PACKAGE_FACADE_EDGES:
        assert "__init__" in (src, dst), (src, dst)


def test_every_module_in_the_graph_is_a_real_file():
    """圖的兩端都是真的模組檔(拼錯的模組名不該悄悄變成一個節點)。"""
    known = {path.stem for path in _module_files()}
    for src, dst in _edges():
        assert src in known, src
        assert dst in known, dst
    assert "cli" in known and "webui" in known and "vault" in known


# ---------------------------------------------------------------- 禁用模組


@pytest.mark.parametrize("path", _module_files(), ids=lambda p: p.name)
def test_no_module_imports_a_banned_stdlib_module(path):
    """AC:`qvault_core/*.py` 不 import `pickle`/`marshal`/`shelve`/`subprocess`/`ctypes`。

    逐檔一格,所以失敗訊息直接是「哪一個檔 import 了哪一個」。掃 AST 而不是
    `grep`:註解與 docstring 裡提到 `pickle`(本檔的 `BANNED_IMPORTS` 註解就提了)
    不算 import,而 `grep` 分不出來。
    """
    _internal, external = _imports(path)
    found = sorted(external & set(BANNED_IMPORTS))
    assert not found, f"{path.name} import 了禁用模組:{found}"


def test_the_ban_is_scoped_to_the_package_and_not_the_tests():
    """禁令只對 `qvault_core`:`tests/` 的子程序 E2E 本來就得用 `subprocess`。

    這條是反向守門(#25 triage 建議 ③):它斷言 `tests/` 裡**真的有**
    `subprocess`,所以掃描範圍哪天手滑擴到 `tests`,先紅的是這條——而不是讓
    子程序測試被默默刪掉來「修綠」。
    """
    assert {p.parent.name for p in _module_files()} == {"qvault_core"}
    users = sorted(
        path.name
        for path in sorted(TESTS_DIR.glob("*.py"))
        if "subprocess" in _imports(path)[1]
    )
    assert users, "tests/ 裡沒有任何 subprocess?子程序 E2E 不見了"


def test_the_only_third_party_import_in_the_package_is_cryptography():
    """同一條的上界:套件裡的外部 import ⊆ 標準庫 + `cryptography`。

    `pyproject.toml` 說相依只有一條,這條在**程式碼**那一邊驗同一件事——
    `import requests` 不會讓上面的 pyproject 測試變紅,但會讓這條變紅。
    """
    allowed = set(sys.stdlib_module_names) | {"cryptography", "__future__"}
    for path in _module_files():
        external = _imports(path)[1]
        extra = sorted(external - allowed)
        assert not extra, f"{path.name} import 了相依清單外的東西:{extra}"


# ---------------------------------------------------------------- 文件(README)

README = REPO_ROOT / "README.md"

#: AC 指定的小節標題,逐字。
README_SECTION = "## \U0001f9ea Test the whole project"
#: AC 指定的那**一條**指令。
README_COMMAND = "python -m pytest -q"
#: AC 要求寫明的四個分層(README 裡的字樣,逐字)。
README_LAYERS = ("unit", "HTTP layer", "subprocess E2E", "fuzz")


def _readme_section() -> str:
    """README 裡「🧪 Test the whole project」那一節的本文(到下一個 `## ` 為止)。"""
    text = README.read_text(encoding="utf-8")
    assert README_SECTION in text, f"README 少了這一節:{README_SECTION}"
    body = text.split(README_SECTION, 1)[1]
    return body.split("\n## ", 1)[0]


def test_the_readme_has_a_one_command_test_section():
    """AC:README 有「🧪 Test the whole project」一節,裡面有一條 `python -m pytest -q`。"""
    section = _readme_section()
    assert README_COMMAND in section, section


def test_the_readme_names_all_four_test_layers():
    """AC:那一節寫明測試分層(單元 / HTTP 層 / 子程序 E2E / fuzz)。"""
    section = _readme_section()
    for layer in README_LAYERS:
        assert layer in section, (layer, section)


def test_the_readme_section_points_at_every_test_file():
    """AC「各在哪個檔」的可驗形式:`tests/` 的每一個測試檔都在那一節裡被點名。

    這條刻意嚴格:新增一個測試檔就必須在 README 補一行。那一節的用途是讓一個
    剛 clone 的人知道「那一條指令跑了什麼」,而一份漏了三個檔的分層表比沒有更糟。
    """
    section = _readme_section()
    missing = sorted(
        path.name
        for path in sorted(TESTS_DIR.glob("test_*.py"))
        if path.name not in section
    )
    assert not missing, f"README 的測試分層沒提到這些檔:{missing}"
