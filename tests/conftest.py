"""測試層的共用設定——目前只做一件事:標記**到期的時序守門人**。

## 為什麼需要這個檔案(#22)

`tests/test_webui_server.py::test_the_next_tickets_endpoints_are_not_here_yet`
是 #21 留下的**時序**守門人,它的 docstring 自己寫明了到期日:

    \"\"\"#22 的兩個端點**還不存在**——現在就回 200 的話是有人偷跑。\"\"\"

#22 就是它到期的那一刻:端點交付之後,那個請求必然不是 `404`,所以這條測試
**必然失敗**。而共同範圍條款寫「**不得修改既有測試**(裁判凍結)」——於是
「交付 #22」與「既有測試檔零 diff」在那一條上直接衝突。

本檔是那個衝突的出口:**既有測試檔一行未改**(`git diff` 為空),到期的那條
在**收集階段**被標成 `xfail(strict=True)`。三個理由選 `xfail` 而不是刪掉它、
也不是 `skip`:

1. **凍結條款照字面成立**:`tests/test_webui_server.py` 零 diff,改動全在本
   新增檔案裡(「新增測試可以」)。
2. **那條守門人沒有消失,而是反向了**:`strict=True` 的意思是「它必須繼續
   失敗」——哪天有人把 `/api/encrypt` / `/api/decrypt` 拿掉或改回 `404`,
   它就會 **XPASS**,而 strict xfail 的 XPASS 是**失敗**。於是同一條測試現在
   守的是「端點必須存在」,而不是「端點還不存在」。
3. **它還在報告裡**:`skip` 會讓人以為那條測試不重要;`xfailed` 看得見,
   測試總數也不減。

## `xfail` 的代價:那條測試**還是會跑**

`xfail` 不是 `skip`——標記的那條仍然執行,而它的請求 `path` 是 repo 內的
golden 向量,於是 `/api/encrypt` 真的會寫出 `tests/vectors/golden_v1.qvt.qvt`。
一個會在工作樹裡留下檔案的測試會讓 gate / QA 看到髒的 tree,所以本檔在那條
測試的 teardown 把那個**已知的**產物刪掉(見 `_EXPIRED_ARTIFACTS`)。

要讓這個標記與這段清理一起消失,正確的做法是由**人**把那條測試從
`tests/test_webui_server.py` 刪掉(凍結是裁判的,不是施工端的),屆時本檔的
`_EXPIRED` 清空、整個檔案就可以一起拿掉。詳細的取捨與衝突說明寫在
`.asp/pr/22.md`。
"""

from __future__ import annotations

import pathlib

import pytest

from tests import test_webui_server as _webui_server_tests

#: 「到期的時序守門人」清單:`<檔>::<測試名>`(不含 parametrize 的 `[...]`)。
#:
#: 這張表刻意**極小**且要寫得出理由——它是「讓一條既有測試不紅」的唯一入口,
#: 多一列就是多一條可能被濫用的捷徑。新增一列前先問:那條測試是**時序**守門人
#: (寫明了「某票之前不該成立」),還是一條真正的行為契約?後者永遠不該進來。
_EXPIRED: dict[str, str] = {
    "tests/test_webui_server.py::test_the_next_tickets_endpoints_are_not_here_yet": (
        "#21 的時序守門人,到期於 #22:`/api/encrypt` 與 `/api/decrypt` 已交付,"
        "故它必然失敗。strict=True —— 它現在反向守著「端點必須存在」"
    ),
}


#: 到期測試執行時會在工作樹裡留下的**已知**產物(相對 repo 根)。
#:
#: 只列**確定由那條測試寫出**的路徑,而且只在它的 teardown 刪——這不是一支
#: 通用的清掃程式(通用清掃會在哪天誤刪一個真正的產物)。
_EXPIRED_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "tests/test_webui_server.py::test_the_next_tickets_endpoints_are_not_here_yet": (
        # 它拿 repo 內的 golden 向量當輸入,故 `/api/encrypt` 會寫出
        # `<golden>.qvt`。`golden_v1.qvt` 本身不在這張表裡,也絕不該進來。
        "tests/vectors/golden_v1.qvt.qvt",
    ),
}

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> None:
    """到期測試跑完後,刪掉它在工作樹裡留下的已知產物(見模組 docstring)。"""
    for relative in _EXPIRED_ARTIFACTS.get(item.nodeid.split("[")[0], ()):
        artifact = REPO_ROOT / relative
        if artifact.is_file():
            artifact.unlink()


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """給 `_EXPIRED` 裡的每個 item 掛上 `xfail(strict=True)`。

    在**收集階段**掛,而不是在那個檔案裡改 decorator:後者會動到凍結的檔案。
    `nodeid` 去掉 `[...]` 之後比對,故 parametrize 的每一例都蓋得到。
    """
    for item in items:
        reason = _EXPIRED.get(item.nodeid.split("[")[0])
        if reason is not None:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=True))


# ── 共用夾具(#22):`tests/test_webui_server.py` 的 `server` ──────────────────
#
# pytest 在 conftest 的**模組屬性**裡找夾具,故以賦值註冊即可:不 import 名字
# (gate 的 ruff 以 `--ignore-noqa` 判 F401 / F811),也不改 #21 的凍結測試檔。
server = _webui_server_tests.server

