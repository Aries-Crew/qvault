"""`cli` 的信號處置**還原**不留半套(#42 L-5;注入式)。

`_signals_deferred()` 把 `SIGINT` / `SIGTERM` / `SIGHUP` 一起降級成「什麼都不做」,
離開時還原。還原不是潔癖:`cli.main` 是函式庫呼叫端也會用的進入點,把行程的信號
處置永久改掉是副作用(那段理由寫在 `_signals_as_exit` 的 docstring 裡)。

本檔守的是**安裝迴圈自己被打斷**的那一刻。裝第一個之後、裝完最後一個之前,處置是
半套的:`SIGINT` 已經是 `ignore`,`SIGTERM` 還是 `_stop_on_signal`(會拋 `_Stopped`)。
那一刻收到 `SIGTERM`,例外就從安裝迴圈裡冒出去——迴圈在 `try` 外面的話 `finally`
不在它的路徑上,`SIGINT` 的 `ignore` 於是**永久留在行程上**:之後誰按 Ctrl-C 都
沒有反應,而且看不出是誰改的。

量法是**注入**而不是真信號:真的要撞進那幾微秒只能靠運氣,所以把 `signal.signal`
換成「第二次呼叫就拋 `_Stopped`」——與「`SIGINT` 已降級、`SIGTERM` 還沒降級的那一刻
收到 `SIGTERM`」等價。`test_the_pre_fix_shape_really_leaked_the_handler` 是同一個
注入打在修正前的寫法上,證明上面那條不是一條永遠綠的斷言。

#48(W5、W6)把窗口的**另一半**也關上,本檔因此有兩組注入,差別只在拋的時機:

* **拋在 `signal.signal()` 之前**(`_interrupting_signal`,#42 L-5):處置還沒換,
  要守的是「整個安裝迴圈在 `try` 裡」。
* **拋在 `signal.signal()` 回來之後**(`_interrupting_after_install`,#48 W5/W6):
  處置**已經換了**,而舊寫法 `previous[sig] = signal.signal(sig, ignore)` 要等那個
  指派完成才記得住它——拋在中間,`finally` 就看不到這個 `sig`。修法是先
  `previous[sig] = signal.getsignal(sig)` 再 `signal.signal(sig, ...)`:記在換之前,
  於是「已換、未記」不存在。兩個同形的函式(`_signals_deferred`、`_signals_as_exit`)
  各有一條這樣的證人,而且各配一條「修正前的形狀真的會漏」的對照(W6 的那一條連
  「迴圈在 `try` 外」一起照抄,因為 `_signals_as_exit` 當時正是那個形狀)。
"""

from __future__ import annotations

import contextlib
import signal
import sys

import pytest

from qvault_core import cli

#: Windows 沒有 `SIGHUP`,`SIGINT` 的處置語意也不同;這一組只在 POSIX 上跑
#: (與 `tests/test_cli_ui.py` 的 `posix_only` 同一個理由)。
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="signal 處置的還原語意只在 POSIX 上成立"
)

#: `_signals_deferred` 會動到的那幾個信號,順序與它的安裝迴圈相同。
DEFERRED_SIGNALS = (signal.SIGINT, *cli._STOP_SIGNALS)


def _handlers() -> dict[object, object]:
    """目前行程上這幾個信號的處置快照。"""
    return {sig: signal.getsignal(sig) for sig in DEFERRED_SIGNALS}


def _interrupting_signal(monkeypatch, *, fail_on: int):
    """把 `signal.signal` 換成「第 `fail_on` 次呼叫拋 `_Stopped`」。

    回傳那個記錄用的 list(裡面是每次呼叫的信號),好讓測試斷言注入**真的**發生在
    安裝迴圈中途、而不是第一次或最後一次之後。拋 `_Stopped` 之前**不**裝那一個
    handler:等價於信號在 `signal.signal()` 回來之前就到了。
    """
    real = signal.signal
    calls: list[object] = []

    def flaky(sig, handler):
        calls.append(sig)
        if len(calls) == fail_on:
            raise cli._Stopped()
        return real(sig, handler)

    monkeypatch.setattr(signal, "signal", flaky)
    return calls


@contextlib.contextmanager
def _pre_fix_signals_deferred():
    """`_signals_deferred` 修正**前**的形狀:安裝迴圈在 `try` 外面。

    逐字照抄當時的那幾行(只省掉 docstring),用途只有一個:讓
    `test_the_pre_fix_shape_really_leaked_the_handler` 能證明本檔的斷言載重。
    """

    def ignore(signum: object, frame: object) -> None:
        """收下但不做事。"""

    previous: dict[object, object] = {}
    for sig in DEFERRED_SIGNALS:
        try:
            previous[sig] = signal.signal(sig, ignore)
        except ValueError:
            previous[sig] = cli._NOT_INSTALLED
    try:
        yield
    finally:
        for sig, handler in previous.items():
            if handler is cli._NOT_INSTALLED:
                continue
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)


@posix_only
def test_a_stop_signal_during_the_install_loop_still_restores_every_handler(monkeypatch):
    """L-5:安裝迴圈被 `_Stopped` 打斷,行程上的處置仍與進來之前**逐一相同**。

    這條紅的時候的症狀不是測試失敗長的那樣:它是「跑完這個測試之後,這個行程的
    `SIGINT` 永遠是 `ignore`」——同一個 pytest 行程裡後面每一條按 Ctrl-C 的測試
    都會跟著怪,而原因在好幾個檔以前。所以斷言的是**處置本身**,不是退出碼。
    """
    before = _handlers()
    calls = _interrupting_signal(monkeypatch, fail_on=2)
    try:
        with pytest.raises(cli._Stopped):
            with cli._signals_deferred():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")

        assert calls[0] == signal.SIGINT, calls  # 第一個裝的是 SIGINT(已經被降級)
        monkeypatch.undo()                       # 還原已經做完,解掉替身再比處置
        assert _handlers() == before, (
            f"安裝迴圈被打斷之後留下了半套處置:{_handlers()} != {before}"
        )
        assert len(calls) > len(DEFERRED_SIGNALS) - 1, (
            "`finally` 一次都沒有還原",
            calls,
        )
    finally:
        # 這條紅的時候處置可能真的漂了,而那會把同一個 pytest 行程後面的測試
        # 一起帶壞(正是這個 bug 的症狀)。收乾淨再把失敗交出去。
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)


@posix_only
def test_the_pre_fix_shape_really_leaked_the_handler(monkeypatch):
    """同一個注入打在**修正前**的寫法上:`SIGINT` 的 `ignore` 真的留下來了。

    沒有這條的話,上面那條可能只是「`signal.signal` 的替身沒讓任何東西漂掉」而
    永遠綠。這條刻意把漏掉的那個處置**在測試裡手動收乾淨**(`finally`),否則它
    會把同一個 pytest 行程後面的測試一起帶壞——這正是這個 bug 的症狀。
    """
    before = _handlers()
    _interrupting_signal(monkeypatch, fail_on=2)
    try:
        with pytest.raises(cli._Stopped):
            with _pre_fix_signals_deferred():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")
        monkeypatch.undo()
        leaked = _handlers()
        assert leaked != before, "修正前的寫法沒有漏掉處置?那上面那條就不載重了"
        assert leaked[signal.SIGINT] is not before[signal.SIGINT], leaked
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert _handlers() == before


def _interrupting_after_install(monkeypatch, *, fail_on: int):
    """把 `signal.signal` 換成「第 `fail_on` 次呼叫**裝完之後**才拋 `_Stopped`」。

    與 `_interrupting_signal` 的差別只有一行的順序,而那正是 #48 W5/W6 要守的那半格:
    這裡 `real(sig, handler)` **先跑完**(處置真的換成 `ignore` / `_stop_on_signal`
    了),例外才出去。等價於信號落在 `signal.signal()` 回來之後、`previous[sig]` 的
    指派完成之前的那幾個位元組的時間。

    回傳記錄用的 list(每次呼叫的信號),好讓測試斷言注入打在哪一格。
    """
    real = signal.signal
    calls: list[object] = []

    def flaky(sig, handler):
        calls.append(sig)
        result = real(sig, handler)
        if len(calls) == fail_on:
            raise cli._Stopped()
        return result

    monkeypatch.setattr(signal, "signal", flaky)
    return calls


@contextlib.contextmanager
def _pre_w5_signals_deferred():
    """`_signals_deferred` 在 #48 W5 **之前**的形狀:換與記綁在同一個指派上。

    迴圈已經在 `try` 裡(#42 L-5 修過),差的只有順序——`previous[sig]` 的值來自
    `signal.signal()` 的**回傳值**,所以「已換、未記」那一格是真的。用途只有一個:
    讓 `test_the_pre_w5_shape_really_leaked_the_swapped_handler` 證明本檔的
    W5 證人載重。
    """

    def ignore(signum: object, frame: object) -> None:
        """收下但不做事。"""

    previous: dict[object, object] = {}
    try:
        for sig in DEFERRED_SIGNALS:
            try:
                previous[sig] = signal.signal(sig, ignore)
            except ValueError:
                previous[sig] = cli._NOT_INSTALLED
        yield
    finally:
        for sig, handler in previous.items():
            if handler is cli._NOT_INSTALLED:
                continue
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)


@contextlib.contextmanager
def _pre_w6_signals_as_exit():
    """`_signals_as_exit` 在 #48 W6 **之前**的形狀:迴圈在 `try` 外,而且換了才記。

    逐字照抄當時的那幾行(只省掉 docstring)。兩個缺口疊在一起,所以任何從安裝迴圈
    裡冒出去的例外都會留下一個 `_stop_on_signal`——而留著它比沒裝更糟:之後行程
    收到 `SIGTERM` / `SIGHUP`,都會從一個早就結束的 `ui` 裡丟出 `_Stopped`。
    """
    previous: dict[object, object] = {}
    for sig in cli._STOP_SIGNALS:
        try:
            previous[sig] = signal.signal(sig, cli._stop_on_signal)
        except ValueError:
            previous[sig] = cli._NOT_INSTALLED
    try:
        yield
    finally:
        for sig, handler in previous.items():
            if handler is cli._NOT_INSTALLED:
                continue
            signal.signal(sig, signal.SIG_DFL if handler is None else handler)


@posix_only
def test_an_exception_after_the_swap_still_restores_every_deferred_handler(monkeypatch):
    """W5:`signal.signal()` 已經換完才被打斷,`_signals_deferred` 仍逐一還原。

    斷言**逐一**比對而不是只比整張快照:整張快照相等的失敗訊息只說「漂了」,逐一
    比對說得出漂的是哪一個信號——而這個 bug 一次只漏一個(被打斷的那一格)。
    """
    before = _handlers()
    calls = _interrupting_after_install(monkeypatch, fail_on=2)
    try:
        with pytest.raises(cli._Stopped):
            with cli._signals_deferred():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")

        assert calls[:2] == list(DEFERRED_SIGNALS[:2]), calls  # 打在第二格:裝完才拋
        monkeypatch.undo()  # 解掉替身再比處置
        after = _handlers()
        for sig in DEFERRED_SIGNALS:
            assert after[sig] == before[sig], (
                f"{signal.Signals(sig).name} 的處置沒還原:{after[sig]} != {before[sig]}"
            )
        # 安裝只跑了兩格(第二格裝完就拋),所以多出來的呼叫都是 `finally` 裝回去的。
        assert len(calls) > 2, ("`finally` 一次都沒有還原", calls)
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)


@posix_only
def test_the_pre_w5_shape_really_leaked_the_swapped_handler(monkeypatch):
    """同一個注入打在 W5 **之前**的寫法上:換完沒記下的那一個處置真的留下來了。

    沒有這條的話,上面那條可能只是「替身沒讓任何東西漂掉」而永遠綠。漏掉的那個處置
    在這裡手動收乾淨(`finally`),否則它會把同一個 pytest 行程後面的測試一起帶壞。
    """
    before = _handlers()
    calls = _interrupting_after_install(monkeypatch, fail_on=2)
    try:
        with pytest.raises(cli._Stopped):
            with _pre_w5_signals_deferred():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")
        monkeypatch.undo()
        leaked = _handlers()
        interrupted = calls[1]
        assert leaked[interrupted] is not before[interrupted], (
            "換了才記的寫法沒有漏掉處置?那上面那條就不載重了",
            leaked,
        )
        assert leaked[DEFERRED_SIGNALS[0]] == before[DEFERRED_SIGNALS[0]], (
            "已記下的那一格應該照樣被還原(漏的只有被打斷的那一個)",
            leaked,
        )
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert _handlers() == before


@posix_only
def test_an_exception_after_the_swap_still_restores_every_stop_handler(monkeypatch):
    """W6:`_signals_as_exit` 同形的證人——裝完才被打斷,`_STOP_SIGNALS` 逐一還原。

    這個函式動到的是 `SIGTERM` / `SIGHUP`(`SIGINT` 由標準庫管),漏掉一個的症狀是
    行程之後收到那個信號就從一個早就結束的 `ui` 裡丟出 `_Stopped`。
    """
    before = _handlers()
    calls = _interrupting_after_install(monkeypatch, fail_on=1)
    try:
        with pytest.raises(cli._Stopped):
            with cli._signals_as_exit():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")

        assert calls[0] == cli._STOP_SIGNALS[0], calls  # 打在第一格,而它已經裝上了
        monkeypatch.undo()
        after = _handlers()
        for sig in cli._STOP_SIGNALS:
            assert after[sig] == before[sig], (
                f"{signal.Signals(sig).name} 的處置沒還原:{after[sig]} != {before[sig]}"
            )
        assert len(calls) > 1, ("`finally` 一次都沒有還原", calls)
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)


@posix_only
def test_the_pre_w6_shape_really_leaked_the_stop_handler(monkeypatch):
    """同一個注入打在 W6 **之前**的 `_signals_as_exit` 上:`_stop_on_signal` 留下來了。

    修正前那個形狀有兩個缺口(迴圈在 `try` 外、換了才記),這條只需要證明「會漏」,
    所以不去分辨是哪一個缺口漏的——分辨的工作由上面那條(修正後必綠)承擔。
    """
    before = _handlers()
    _interrupting_after_install(monkeypatch, fail_on=1)
    try:
        with pytest.raises(cli._Stopped):
            with _pre_w6_signals_as_exit():
                pytest.fail("安裝迴圈應該在進到區塊之前就被打斷")
        monkeypatch.undo()
        leaked = _handlers()
        first = cli._STOP_SIGNALS[0]
        assert leaked[first] is cli._stop_on_signal, (
            "修正前的寫法沒有漏掉處置?那上面那條就不載重了",
            leaked,
        )
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert _handlers() == before


@posix_only
def test_restoring_tolerates_a_handler_that_python_did_not_install(monkeypatch):
    """`getsignal` 回 `None` 時還原**不拋**,而且退回 `SIG_DFL`(可觀察)。

    `signal.getsignal()` 回 `None` 的意思是「現在的處置不是從 Python 裝的」,而
    `signal.signal(sig, None)` 會丟 `TypeError`。這一格**不是 W5 引入的**(舊寫法
    `previous[sig] = signal.signal(sig, ignore)` 的回傳值同樣會是 `None`),但 W5/W6
    把還原保證改寫了一遍,所以順手把它釘住:還原走的是
    `signal.SIG_DFL if handler is None else handler` 那一條。

    量法:monkeypatch `getsignal` 回 `None`,正常進出一次,然後**解掉替身**去讀真的
    處置——每一個都該是 `SIG_DFL`,而不是區塊裡那個 `ignore`。
    """
    before = _handlers()
    monkeypatch.setattr(signal, "getsignal", lambda sig: None)
    try:
        with cli._signals_deferred():
            pass  # 沒有例外:還原路徑踩到 None 也不該拋
        monkeypatch.undo()
        after = _handlers()
        for sig in DEFERRED_SIGNALS:
            assert after[sig] is signal.SIG_DFL, (
                f"{signal.Signals(sig).name} 沒退回 SIG_DFL:{after[sig]}"
            )
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert _handlers() == before


@posix_only
def test_restoring_as_exit_tolerates_a_handler_that_python_did_not_install(monkeypatch):
    """`_signals_as_exit` 版的同一格:`getsignal` 回 `None` → 每個停止信號退回 `SIG_DFL`。

    上面那條打的是 `_signals_deferred`,這條打 `_signals_as_exit`,而它**不是**同一條
    的抄寫:#48 W6 把 `previous[sig]` 的來源從 `signal.signal` 的回傳值改成
    `signal.getsignal`,於是 `tests/test_cli_ui.py::test_a_handler_we_cannot_restore_becomes_sig_dfl`
    這條既有的證人就不再量到那道防護了——它是以替身讓 `signal.signal` **回** `None`
    來觸發這一格的,而 `getsignal` 沒被攔,在 pytest 行程裡拿到的是真的 `SIG_DFL`:
    斷言於是因**環境**成立。把 `cli.py` 還原迴圈的
    `signal.SIG_DFL if handler is None else handler` 改成 `handler`,那條照樣綠
    (合併前複審 F-1 的主管層實跑:本 PR 144 passed、develop 1 failed)。

    所以這條把裁判換成 `getsignal`:它一回 `None`,`previous` 裡每一格就都是 `None`,
    還原**必須**走 `SIG_DFL` 那一側——`signal.signal(sig, None)` 會丟 `TypeError`,
    而把 `_stop_on_signal` 留在行程上更糟(之後收到 `SIGTERM` / `SIGHUP`,都會從一個
    早就結束的 `ui` 裡丟出 `_Stopped`)。兩種壞法都看得見:前者是這條紅在例外上,
    後者是紅在「處置不是 `SIG_DFL`」。

    `tests/test_cli_ui.py` 一行未動(複審 F-1 的要求),本條是純新增。
    """
    before = _handlers()
    monkeypatch.setattr(signal, "getsignal", lambda sig: None)
    try:
        with cli._signals_as_exit():
            pass  # 正常進出:還原路徑踩到 None 也不該拋
        monkeypatch.undo()
        after = _handlers()
        for sig in cli._STOP_SIGNALS:
            assert after[sig] is signal.SIG_DFL, (
                f"{signal.Signals(sig).name} 沒退回 SIG_DFL:{after[sig]}"
            )
        # `SIGINT` 不在 `_signals_as_exit` 的表裡,所以它**不該**被動到——這一句
        # 守的是「這個函式只碰 `_STOP_SIGNALS`」,否則上面那個迴圈綠了也不算。
        assert after[signal.SIGINT] == before[signal.SIGINT], after
    finally:
        monkeypatch.undo()
        for sig, handler in before.items():
            signal.signal(sig, handler)
    assert _handlers() == before
