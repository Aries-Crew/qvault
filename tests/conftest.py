"""測試層共用夾具:Web UI 的 `server`(#21 起用,#22 起兩個測試檔共用)。

從 `tests/test_webui_server.py` **原樣**搬來(#30 複審 M1、#22 主管層裁定 2):
pytest 自動發現 conftest 的夾具,測試檔不必、也不該 import 它(gate 的 ruff 以
`--ignore-noqa` 判 F401 / F811)。HTTP 工具 `send` / `Response` 在 `tests/webui_client.py`。
"""

from __future__ import annotations

import threading

import pytest

from qvault_core import webui


@pytest.fixture
def server():
    """`port=0` 的伺服器,起在 daemon thread,`yield` 後 `shutdown()`。"""
    srv = webui.make_server()
    # `poll_interval` 調小只是為了測試跑得快:預設 0.5 秒會讓**每個**測試的
    # teardown 都等半秒(121 個測試 = 一分鐘的純等待)。
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "serve_forever 沒有收乾淨"
