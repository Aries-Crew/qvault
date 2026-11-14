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
