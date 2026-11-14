"""V2:HTTP 層 10,000 筆 fuzz(#25,ADR-002 決策 14 / ROADMAP P3 判準)。

守的是**一條不變式**,不是覆蓋率:

> 任何亂序輸入打進 HTTP 層,回應的狀態碼都落在一個**封閉集合**內、非 2xx 的
> body 都是 `{"error": …}` 這一種形式、stdout/stderr 沒有 traceback、伺服器
> 執行緒不倒,而且**一個檔都沒被寫出來**。

`tests/test_webui_server.py::test_fuzzed_requests_never_5xx_and_never_traceback`
是同一條的 2,000 筆縮小版(#21 留下的回歸守門)。本檔是決策 14 字面上那 10,000
筆:語料更寬(六個方法 × 七類路徑 × token/Host/Origin/Content-Type 各自對錯 ×
十類 body),而且額外斷言「零落檔」與「狀態碼集合的下界」。

## 語料停在 gate 層(本票主管層裁定 ①)

票文的 AC 自己寫著前提「fuzz 不帶正確密碼與可寫路徑的組合,故不應寫出東西」,
而那個前提對 `/api/encrypt` **不成立**:encrypt 不需要「正確」密碼,任何字串都
會真的派生 KEK 並寫出 `<path>.qvt`。所以裁定把語料的邊界定在:

1. 所有 JSON 的 `path` 一律在 `tmp_path` 內(**不是** `tests/vectors/` 的真
   golden——命中就會在 repo 工作樹裡長出一個 `golden_v1.qvt.qvt`,而
   `.gitignore` 對 `tests/vectors/*.qvt` 有例外,那個檔不會被忽略);
2. **永不**給 `/api/encrypt` 一個存在的 path(`_input_file` 因此一定在
   `_passphrase` 之前就拒掉 → 一次 scrypt 都不跑);
3. `/api/decrypt` 的 `out_dir` **永不**是一個真目錄(`_api_decrypt` 的順序是
   輸入檔 → `out_dir` → 密碼,所以同樣在 KDF 之前就拒掉)。

兩者合起來讓「整輪 < 180 秒」與「零落檔」同時成立:正規 scrypt 15/8/1 一次約
80ms,命中一百次就吃掉 8 秒,而那一百次每次都在磁碟上留一個檔。handler 層的
正確性由 `tests/test_webui_crypto.py` 的端點測試負責,不靠 fuzz——ROADMAP P3
的判準字面也是「HTTP 層 10,000 筆亂序輸入只回乾淨 4xx 且伺服器不倒」。

## 沒有 `@pytest.mark.slow`

票文明寫不要:CI 一律跑。實測整輪約數秒(見 `test_ten_thousand_fuzzed_requests`
最後印出的耗時斷言),離 180 秒的上限很遠,不需要縮 body 上限。
"""

from __future__ import annotations

import http.client
import json
import pathlib
import random
import re
import socket
import threading
import time

import pytest

from qvault_core import webui
from tests.webui_client import send

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "vectors" / "golden_v1.qvt"
VECTORS_DIR = GOLDEN.parent

#: AC 寫死的三個數。
SEED = 20261108
REQUESTS = 10_000
TIME_BUDGET_SECONDS = 180.0

#: AC 的封閉集合,逐字。**不含 500**(我們的 bug)、**不含 501**(標準庫對未知
#: 方法的預設回應,由 `_Handler.__getattr__` 的 catch-all 收成 405;見
#: `test_an_unknown_method_is_405_json_not_501_html`)、也不含 503(那是
#: `qvault ui` 退出中才有的狀態,本檔的伺服器沒有在退出)。
ALLOWED_STATUS = frozenset({200, 400, 401, 403, 404, 405, 409, 413, 415, 422})

#: 語料**至少**要打出這些碼。少了任何一個,表示某一道門根本沒被走到(例如
#: Host 全錯 → 一萬筆都是 403),而那種 fuzz 看起來綠但什麼都沒驗。
#: `409`(目標已存在)不在裡面:它只在 encrypt 真的寫得下去時才出現,而裁定 ①
#: 正是把那條路堵掉的。
EXPECTED_AT_LEAST = frozenset({200, 400, 401, 403, 404, 405, 413, 415, 422})

METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")

FIXED_PATHS = (
    "/",
    "/app.js",
    webui.API_INSPECT_PATH,
    webui.API_ENCRYPT_PATH,
    webui.API_DECRYPT_PATH,
    "/api/nope",
)

#: 語料的**權重**(不是集合——集合就是 AC 寫的那些)。一個「每一樣都等機率」的
#: fuzz 會把一萬筆裡的九成九卡在第一道門上:`Host` 錯就 `403`,後面五道門與三個
#: 端點一個都沒走到,綠得很好看但什麼都沒驗。所以「對的那一個值」一律給高權重,
#: 讓請求有機會走到深處,錯的值則平均散在各道門上。`EXPECTED_AT_LEAST` 是這件事
#: 的量尺:它要求每一道門都真的回過一次它自己的碼。
#:
#: 權重只影響**分佈**,不影響不變式——任何分佈下 AC 的斷言都該成立。
METHOD_WEIGHTS = (10, 50, 10, 10, 10, 10)  # 對齊 `METHODS`,POST 佔一半
FIXED_PATH_WEIGHTS = (1, 1, 3, 2, 2, 1)  # 對齊 `FIXED_PATHS`
P_FIXED_PATH = 0.85
P_HOST_CORRECT = 0.85
P_HOST_MISSING = 0.90  # 累積:0.85–0.90 這一段是「整個標頭不送」
P_TOKEN_CORRECT = 0.70
P_TOKEN_MISSING = 0.78
P_ORIGIN_MISSING = 0.45
P_ORIGIN_CORRECT = 0.80  # 累積
P_JSON_BODY = 0.65
#: `_json_body` 的十類 body 的權重:前三類是「形式正確、內容隨機」(那是唯一
#: 走得到端點本體的一類),所以佔四成。
JSON_KIND_WEIGHTS = (14, 14, 14, 10, 8, 8, 8, 8, 8, 8)
#: `paths` 池子的權重:存在的真檔佔三成五(`inspect` 的 `200` / `422` 只能從
#: 那裡來),其餘散在不存在 / 目錄 / 不可用三類上。
PATH_POOL_WEIGHTS = {
    "missing": 10,
    "directories": 10,
    "unusable": 5,
    "existing": 17,
}

#: 亂數路徑用的字元集:RFC 3986 的 pchar + 幾個會打到解析邏輯的符號。
#: **刻意不含**空白、控制字元與非 ASCII——`http.client.putrequest` 對那些會
#: 自己拋 `InvalidURL` / `UnicodeEncodeError`,那是**用戶端**的錯,不是伺服器
#: 的回應,放進語料只會把測試自己炸掉而不是在測伺服器。
PATH_CHARS = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "-._~:/?#[]@!$&'()*+,;=%"
)

#: 前四個過得了門 4(`split(";")[0].strip().lower()` 恰為 `application/json`),
#: 後六個過不了。權重讓「過得了」佔 55%。
CONTENT_TYPES = (
    webui.JSON_MEDIA_TYPE,
    "application/json; charset=utf-8",
    "APPLICATION/JSON",
    "  application/json  ",
    "application/jsonx",
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data; boundary=zz",
    "",
    None,
)
CONTENT_TYPE_WEIGHTS = (25, 15, 8, 7, 9, 9, 9, 9, 5, 4)

NON_STRINGS = (None, True, False, 0, -1, 2**70, 1.5, [], {}, [1, 2], {"a": 1})


def _unusable_paths(tmp_path: pathlib.Path) -> tuple[str, ...]:
    """路徑字串本身不可用(都在 `tmp_path` 底下,一個都解析不到真實檔案)。"""
    base = str(tmp_path)
    return (
        base + "/\x00nul.bin",  # NUL → `Path.exists()` 拋 ValueError
        base + "/\udc80orphan.bin",  # 孤兒代理對 → UnicodeEncodeError
        base + "/" + "a" * 5000,  # ENAMETOOLONG → OSError
    )


@pytest.fixture
def corpus(tmp_path):
    """fuzz 的輸入語料 + 一份「開跑前 `tmp_path` 長什麼樣」的快照。

    `tmp_path` 下先放三樣**既有**的東西:一個目錄、一個真容器(golden 的
    **複本**,不是 `tests/vectors/` 裡那一份)、一個不是容器的普通檔。
    """
    a_dir = tmp_path / "a_dir"
    a_dir.mkdir()
    golden_copy = tmp_path / "golden_copy.qvt"
    golden_copy.write_bytes(GOLDEN.read_bytes())
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not a container at all" * 8)

    missing = (
        str(tmp_path / "nope.bin"),
        str(tmp_path / "missing" / "deep.bin"),
        str(tmp_path / ("long-" + "b" * 300)),
    )
    directories = (str(tmp_path), str(a_dir))
    existing_files = (str(golden_copy), str(plain))
    unusable = _unusable_paths(tmp_path)

    pools = {
        "missing": missing,
        "directories": directories,
        "unusable": unusable,
        "existing": existing_files,
    }

    def weighted(*groups: str) -> tuple[tuple[str, ...], tuple[float, ...]]:
        """把幾個池子攤平成「值, 權重」兩條平行的 tuple(組內均分組權重)。"""
        values: list[str] = []
        weights: list[float] = []
        for name in groups:
            group = pools[name]
            share = PATH_POOL_WEIGHTS[name] / len(group)
            values.extend(group)
            weights.extend([share] * len(group))
        return tuple(values), tuple(weights)

    # 其餘端點:含兩個真的存在的檔(`inspect` 的 `200` / `422` 只能從那裡來)。
    paths, path_weights = weighted("missing", "directories", "unusable", "existing")
    # `/api/encrypt` 專用:**沒有一個是存在的普通檔**(裁定 ①-2)。
    enc_paths, enc_weights = weighted("missing", "directories", "unusable")

    return {
        "encrypt_paths": enc_paths,
        "encrypt_path_weights": enc_weights,
        "paths": paths,
        "path_weights": path_weights,
        # `out_dir`:**沒有一個是真目錄**(裁定 ①-3)。
        "out_dirs": (
            str(tmp_path / "no_such_dir"),
            str(golden_copy),
            "",
            "   ",
        ),
        "tmp_path": tmp_path,
    }


@pytest.fixture
def fuzz_target():
    """`port=0` 的伺服器 + 它的執行緒(本檔要斷言「thread 存活」,故要拿得到它)。

    與 `tests/conftest.py` 的 `server` 同一個形狀(共同範圍條款:`port=0`、
    在 thread 內啟動、測試結束前 `shutdown()`);差別只是順便 `yield` 執行緒。
    """
    srv = webui.make_server()
    thread = threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield srv, thread
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "serve_forever 沒有收乾淨"


def _tree(root: pathlib.Path) -> dict[str, int | None]:
    """`root` 底下每一個項目的相對路徑 → 大小(目錄是 `None`)。"""
    snapshot: dict[str, int | None] = {}
    for item in sorted(root.rglob("*")):
        key = str(item.relative_to(root))
        snapshot[key] = None if item.is_dir() else item.stat().st_size
    return snapshot


def _nested(depth: int) -> dict:
    """`{"path": {"path": {… 50 層 …}}}`——`_text_field` 看到 dict 就 `400`。"""
    node: dict | str = "bottom"
    for _ in range(depth):
        node = {"path": node}
    return {"path": node}


def _json_body(rng: random.Random, route: str, corpus: dict) -> bytes:
    """隨機 JSON(或假裝是 JSON 的東西)。`route` 決定 `path` 從哪個池子抽。"""
    if route == webui.API_ENCRYPT_PATH:
        pool, weights = corpus["encrypt_paths"], corpus["encrypt_path_weights"]
    else:
        pool, weights = corpus["paths"], corpus["path_weights"]

    def a_path() -> str:
        return rng.choices(pool, weights=weights, k=1)[0]

    kind = rng.choices(range(10), weights=JSON_KIND_WEIGHTS, k=1)[0]
    if kind == 0:
        payload = {"path": a_path()}
    elif kind == 1:
        payload = {
            "path": a_path(),
            "passphrase": "".join(rng.choices(PATH_CHARS, k=rng.randint(0, 40))),
        }
    elif kind == 2:
        payload = {
            "path": a_path(),
            "out_dir": rng.choice(corpus["out_dirs"]),
            "passphrase": "".join(rng.choices(PATH_CHARS, k=rng.randint(0, 40))),
            "force": rng.choice([True, False, "yes", 1, None]),
        }
    elif kind == 3:  # 型別錯
        payload = rng.choice(
            [
                {"path": rng.choice(NON_STRINGS)},
                {"path": a_path(), "passphrase": rng.choice(NON_STRINGS)},
                {"path": a_path(), "out_dir": rng.choice(NON_STRINGS)},
                {"path": a_path(), "force": rng.choice(NON_STRINGS)},
                {rng.choice(PATH_CHARS): rng.choice(NON_STRINGS)},
            ]
        )
    elif kind == 4:  # 巢狀 50 層
        payload = _nested(50)
    elif kind == 5:  # 含 NUL
        payload = {
            "path": str(corpus["tmp_path"]) + "/\x00" + "x" * rng.randint(0, 20),
            "passphrase": "pw\x00pw",
            "out_dir": "\x00",
        }
    elif kind == 6:  # 超長字串(順便打到門 5 的 64 KiB 上限)
        # 前綴照樣掛在 `tmp_path` 下:不是因為這個名字解析得到什麼(它必定
        # `ENAMETOOLONG`,70,000 那一檔連門 5 都過不了),而是「語料的每一個
        # `path` 都在 `tmp_path` 內」要**字面**成立——相對路徑會讓那句宣稱
        # 比實際寬一點,而那種「幾乎對」的宣稱最難查(#25 複審彙整項)。
        # `::test_every_generated_path_stays_under_tmp_path` 直接掃產出的 body。
        payload = {
            "path": str(corpus["tmp_path"]) + "/" + "a" * rng.choice([5_000, 70_000])
        }
    elif kind == 7:  # 不是 JSON 物件
        return rng.choice([b"[]", b"null", b'"x"', b"123", b"true", b""])
    elif kind == 8:  # 壞 JSON
        return rng.choice(
            [b'{"path":', b"{", b"}", b'{"path" "x"}', b'{,}', b'{"a":1,}']
        )
    else:  # 不是 UTF-8
        return rng.randbytes(rng.randint(1, 64)) + b"\xff\xfe"
    return json.dumps(payload).encode("utf-8")


def _request_plan(rng: random.Random, srv, corpus: dict) -> dict:
    """抽一筆請求的所有參數(抽完才發,方便失敗時把整筆印出來)。"""
    if rng.random() < P_FIXED_PATH:
        path = rng.choices(FIXED_PATHS, weights=FIXED_PATH_WEIGHTS, k=1)[0]
    else:
        path = "".join(rng.choices(PATH_CHARS, k=rng.randint(1, 64)))
    route = path.split("?", 1)[0].split("#", 1)[0]

    if rng.random() < P_JSON_BODY:
        raw_body = _json_body(rng, route, corpus)
    else:
        raw_body = rng.randbytes(rng.randint(0, 70_000))

    host_roll = rng.random()
    if host_roll < P_HOST_CORRECT:
        host = srv.expected_host
    elif host_roll < P_HOST_MISSING:
        host = None
    else:
        host = rng.choice(
            [
                "evil.example",
                f"localhost:{srv.port}",
                "127.0.0.1:1",
                webui.LOOPBACK,
                f"127.0.0.1:{srv.port} ",
            ]
        )

    token_roll = rng.random()
    if token_roll < P_TOKEN_CORRECT:
        token = f"Bearer {srv.token}"
    elif token_roll < P_TOKEN_MISSING:
        token = None
    else:
        token = rng.choice(
            [
                "Bearer nope",
                "Bearer " + "A" * len(srv.token),
                f"bearer {srv.token}",
                f"Bearer  {srv.token}",
                "Basic " + srv.token,
                srv.token,
                "",
            ]
        )

    origin_roll = rng.random()
    if origin_roll < P_ORIGIN_MISSING:
        origin = None
    elif origin_roll < P_ORIGIN_CORRECT:
        origin = srv.expected_origin
    else:
        origin = rng.choice(
            ["http://evil.example", "null", f"https://127.0.0.1:{srv.port}", ""]
        )

    return {
        "method": rng.choices(METHODS, weights=METHOD_WEIGHTS, k=1)[0],
        "path": path,
        "raw_body": raw_body,
        "token": token,
        "host": host,
        "origin": origin,
        "content_type": rng.choices(
            CONTENT_TYPES, weights=CONTENT_TYPE_WEIGHTS, k=1
        )[0],
    }


def _describe(plan: dict) -> dict:
    """失敗訊息用的摘要:body 只留長度與開頭,不把 70,000 bytes 印進報告。"""
    return {
        **{k: v for k, v in plan.items() if k != "raw_body"},
        "body_len": len(plan["raw_body"]),
        "body_head": plan["raw_body"][:60],
    }


def _send_plan(srv, plan: dict, index: int):
    """發一筆,**連線層的例外也當成失敗**(#25 複審授權項 (c))。

    `send` 底下是 `http.client`,而連線被對方 RST / 半途關掉時它拋的是
    `ConnectionResetError` / `BrokenPipeError`(`OSError`)或
    `RemoteDisconnected` / `BadStatusLine`(`HTTPException`,串流錯位的另一種
    徵狀)。原本這些會以一個**裸例外**結束測試:沒有 `index`、沒有那一筆的
    組合,於是「偶發紅」查不下去——而它真正的根因是產品缺陷(`_respond` 的
    殘留 body 收尾,見 `qvault_core/webui.py`)。

    轉成 `AssertionError` 並帶上 `index` + `_describe(plan)`:seed 固定,所以
    有 index 就重現得出來(重跑到第 `index` 筆即可)。
    """
    try:
        return send(
            srv,
            plan["method"],
            plan["path"],
            raw_body=plan["raw_body"],
            token=plan["token"],
            host=plan["host"],
            origin=plan["origin"],
            content_type=plan["content_type"],
        )
    except (OSError, http.client.HTTPException) as exc:
        raise AssertionError(
            f"第 {index} 筆在連線層就炸了({type(exc).__name__}: {exc}):"
            f"{_describe(plan)}"
        ) from None


# ================================================================ 本體


def test_ten_thousand_fuzzed_requests(fuzz_target, corpus, capfd):
    """AC:10,000 筆亂序請求 → 封閉狀態碼集合、乾淨 JSON 錯誤、伺服器不倒。

    一筆一條 TCP 連線(決策 14 的字面規模)。每一筆都斷言:

    * 狀態碼 ∈ `ALLOWED_STATUS`(所以沒有 `500`、沒有 `501`);
    * 非 2xx 的 body `json.loads` 得開且含 `error`——**HEAD 除外**:依
      RFC 9110 §9.3.2,HEAD 的回應不帶 body(`_respond` 也照辦),所以那裡
      要驗的是狀態碼與 `Content-Length` 標頭,不是 body 的內容。

    打完再驗:伺服器執行緒還活著、最後一筆正常的 `POST /api/inspect` golden 仍
    `200`、整輪耗時 < 180 秒、狀態碼的分佈真的打到了每一道門。
    """
    srv, thread = fuzz_target
    rng = random.Random(SEED)
    capfd.readouterr()
    seen: dict[int, int] = {}

    started = time.monotonic()
    for index in range(REQUESTS):
        plan = _request_plan(rng, srv, corpus)
        res = _send_plan(srv, plan, index)
        seen[res.status] = seen.get(res.status, 0) + 1
        assert res.status in ALLOWED_STATUS, (index, res.status, _describe(plan))
        if plan["method"] == "HEAD":
            # HEAD 不帶 body(RFC 9110);`Content-Length` 仍要宣告出來。
            assert res.body == b"", (index, _describe(plan))
            assert res.header("Content-Length") is not None, (index, _describe(plan))
            continue
        if res.status // 100 != 2:
            try:
                error = json.loads(res.body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:  # pragma: no cover
                raise AssertionError(
                    f"非 2xx 的 body 不是 JSON:{exc}:{index}:{_describe(plan)}:"
                    f"{res.body[:200]!r}"
                ) from None
            assert isinstance(error, dict), (index, _describe(plan), error)
            assert "error" in error, (index, _describe(plan), error)
            assert isinstance(error["error"], str), (index, _describe(plan), error)
            assert res.header("Content-Type") == webui.JSON_CONTENT_TYPE
    elapsed = time.monotonic() - started

    # 伺服器 thread 存活。
    assert thread.is_alive(), "fuzz 把 serve_forever 打死了"

    # 最後一筆正常的 `POST /api/inspect` golden 仍 200。
    final = send(
        srv,
        path=webui.API_INSPECT_PATH,
        payload={"path": str(GOLDEN)},
        token=f"Bearer {srv.token}",
        host=srv.expected_host,
    )
    assert final.status == 200, (final.status, final.text)
    assert final.json()["chunk_size"] == 65536

    # 零 traceback(stdout 與 stderr 都掃;access log 本來就會在 stderr 上)。
    output = capfd.readouterr()
    assert "Traceback" not in output.out, output.out[-2000:]
    assert "Traceback" not in output.err, output.err[-2000:]

    # 每一道門都被走到了(否則這一萬筆驗的東西比看起來少)。
    assert set(seen) <= ALLOWED_STATUS, seen
    assert EXPECTED_AT_LEAST <= set(seen), (EXPECTED_AT_LEAST - set(seen), seen)
    assert sum(seen.values()) == REQUESTS, seen

    # 整輪 < 180 秒。
    assert elapsed < TIME_BUDGET_SECONDS, f"整輪 {elapsed:.1f}s,超過 180s"


def test_the_fuzz_corpus_writes_nothing_to_disk(fuzz_target, corpus, capfd):
    """AC:fuzz 期間 `tmp_path` 內沒有任何新檔。

    與上面那條分開跑,因為它們問的是兩件不同的事(回應的形狀 vs 副作用),而
    分開的失敗訊息直接指出是哪一件壞了。筆數照樣 10,000——「少寫幾筆就不會
    落檔」不是這條要證的東西。

    順帶守住裁定 ①-1:`tests/vectors/` 的清單也要一個 byte 不變(語料若不小心
    把真 golden 餵給 `/api/encrypt`,那裡會長出一個 `golden_v1.qvt.qvt`,而
    `.gitignore` 對 `tests/vectors/*.qvt` 有例外 → 它會跟著 `git status` 跑)。
    """
    srv, _thread = fuzz_target
    rng = random.Random(SEED)
    capfd.readouterr()

    before = _tree(corpus["tmp_path"])
    vectors_before = _tree(VECTORS_DIR)

    for index in range(REQUESTS):
        plan = _request_plan(rng, srv, corpus)
        _send_plan(srv, plan, index)

    capfd.readouterr()
    after = _tree(corpus["tmp_path"])
    assert after == before, {
        "新增": sorted(set(after) - set(before)),
        "消失": sorted(set(before) - set(after)),
        "改大小": sorted(k for k in set(after) & set(before) if after[k] != before[k]),
    }
    assert _tree(VECTORS_DIR) == vectors_before, "fuzz 動到了 tests/vectors/"


def test_the_corpus_never_offers_encrypt_an_existing_path(corpus):
    """裁定 ①-2 的結構性守門:`encrypt_paths` 裡一個存在的普通檔都沒有。

    這條不打伺服器。它守的是**語料自己**——上面兩條的「零落檔」與「< 180 秒」
    都建立在這個前提上,而前提破掉時的徵狀(偶發的多出一個 `.qvt`、偶發的慢)
    是最難追的那一種。`out_dirs` 同理:一個真目錄都沒有。
    """
    for raw in corpus["encrypt_paths"]:
        try:
            assert not pathlib.Path(raw).is_file(), raw
        except (OSError, ValueError):
            pass  # 路徑字串本身就不可用 → 當然不是一個存在的檔
    for raw in corpus["out_dirs"]:
        try:
            assert not pathlib.Path(raw).is_dir() or not raw.strip(), raw
        except (OSError, ValueError):
            pass
    # 池子裡的每一個 path 都在 `tmp_path` 底下(裁定 ①-1)。
    base = str(corpus["tmp_path"])
    for raw in corpus["paths"] + corpus["encrypt_paths"]:
        assert raw.startswith(base), raw


def test_every_generated_path_stays_under_tmp_path(corpus):
    """同一條,但掃的是**產出的 body**,不只是池子(#25 複審彙整項)。

    上面那條只看 `corpus` 的兩個池子,而 `_json_body` 有幾類 body 是**就地**組
    路徑的(kind 5 的 NUL、kind 6 的超長字串)——它們繞過池子,所以「語料的每一個
    `path` 都在 `tmp_path` 內」那句話對它們不成立也不會被發現。複審點出 kind 6
    原本是個**相對**路徑(雖然必定 `ENAMETOOLONG`,所以實際上碰不到任何東西),
    宣稱比實際寬了一點。

    這條把宣稱改成可驗的:真的生出來的 JSON body,凡 `path` 是字串的,一律要在
    `tmp_path` 底下;而且**打到 `/api/encrypt` 的那些**一個存在的普通檔都不是
    (裁定 ①-2,同樣是在產出上驗,不是在池子上)。
    """
    rng = random.Random(SEED)
    base = str(corpus["tmp_path"])
    routes = (
        webui.API_ENCRYPT_PATH,
        webui.API_DECRYPT_PATH,
        webui.API_INSPECT_PATH,
        webui.PAGE_PATH,
    )
    checked = 0
    for route in routes:
        for _ in range(500):
            raw = _json_body(rng, route, corpus)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue  # kind 7–9 刻意不是合法 JSON 物件
            if not isinstance(payload, dict):
                continue
            value = payload.get("path")
            if not isinstance(value, str):
                continue  # kind 3 的型別錯、kind 4 的巢狀
            assert value.startswith(base), (route, value[:80])
            checked += 1
            if route == webui.API_ENCRYPT_PATH:
                try:
                    assert not pathlib.Path(value).is_file(), (route, value[:80])
                except (OSError, ValueError):
                    pass  # 路徑字串本身不可用 → 當然不是一個存在的檔
    # 樣本數的下界:斷言真的跑過,而不是被 `continue` 全部跳掉。
    assert checked > 500, checked


# ================================================================ 複審擋合併項:成功路徑的殘留 body

#: 複審確定性重現的那一筆,逐字:`GET /` + 正確 Host + 宣告 70,700 bytes 的
#: body,而 body 裡**含 `\r\n`**——殘留的位元組被當成請求行解析時,`\r\n` 就是
#: 它找到的那個「行尾」。
WITNESS_BODY_BYTES = 70_700

#: `GET /` 的 body,逐 byte(證人把收到的 body 跟它對完,多一個 byte 就紅)。
PAGE_HTML_BYTES = webui.PAGE_HTML.encode("utf-8")


def _witness_body() -> bytes:
    """70,700 bytes、每 101 bytes 一個 `\\r\\n` 的 body。"""
    line = b"x" * 99 + b"\r\n"
    body = (line * (WITNESS_BODY_BYTES // len(line) + 1))[:WITNESS_BODY_BYTES]
    assert len(body) == WITNESS_BODY_BYTES
    assert b"\r\n" in body
    return body


def test_a_static_200_leaves_no_second_response_on_the_wire(server, capfd):
    """#25 複審擋合併項 (b):**不靠負載**的確定性證人。

    `GET /` 帶一個宣告了 `Content-Length` 的 body 是合法的 HTTP(GET 的 body
    沒有語意,但送得出來)。修正前:`_static` 回 `200` + keep-alive 而**一個
    byte 的 body 都沒讀掉**,`handle_one_request` 接著把殘留的位元組當成下一個
    請求的請求行,於是同一條連線上多出一份基底類別的 **HTML `400`**(違反決策 8
    「錯誤只有 JSON 一種形式」),而 `send_error` 之後在仍有未讀資料時關 socket
    → RST → 用戶端在負載下看到 `ConnectionResetError`。

    這條用 raw socket 送那一筆、讀到 EOF,斷言整條流上**只有一個狀態行而且是
    `200`**、沒有 HTML 錯誤頁、access log 只有一行。沒有負載、沒有時序假設——
    修正前紅、修正後綠,每一次都一樣。
    """
    body = _witness_body()
    request = (
        f"GET {webui.PAGE_PATH} HTTP/1.1\r\n"
        f"Host: {server.expected_host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("latin-1") + body

    capfd.readouterr()
    raw = socket.create_connection((webui.LOOPBACK, server.port), timeout=10)
    broke = None
    chunks: list[bytes] = []
    try:
        raw.sendall(request)
        while True:
            part = raw.recv(65536)
            if not part:
                break
            chunks.append(part)
    except OSError as exc:
        # 連線層的例外**本身**就是症狀之一,但它不是這條的主斷言:記下來,讓
        # 失敗訊息說得出是哪一種,然後照樣驗已經收到的那段流。
        broke = f"{type(exc).__name__}: {exc}"
    finally:
        raw.close()

    stream = b"".join(chunks)
    log = capfd.readouterr().err

    # ① access log 只有這一行。這是最**確定性**的那個斷言:伺服器有沒有把殘留的
    #    body 當成第二個請求,它自己的 log 說得出來——修正前必定多一行
    #    `- / 400`(method 解析不出來所以是 `-`)。線上的位元組則取決於 RST 搶在
    #    哪一刻,有時是多一份 HTML 錯誤頁、有時是 `200` 被截斷,故放在後面。
    log_lines = [line for line in log.splitlines() if line]
    assert log_lines == ["GET / 200"], (
        f"access log 不只一行——殘留的 body 被當成下一個請求了:{log_lines}"
    )

    # ② 線上的位元組:一個狀態行、就是那份頁面、沒有基底類別的 HTML 錯誤頁。
    assert broke is None, f"連線被對方中斷:{broke};已收到 {len(stream)} bytes"
    assert stream.startswith(b"HTTP/1.1 200 OK"), stream[:200]
    status_lines = re.findall(rb"HTTP/1\.[01] \d{3}", stream)
    assert len(status_lines) == 1, (
        f"同一條連線上出現了 {len(status_lines)} 個狀態行 {status_lines}:"
        f"{stream[:400]!r}"
    )
    # 決策 8:這個伺服器說出口的錯誤只有 JSON 一種形式,沒有 HTML 錯誤頁。
    # (不能掃 `<html`:`GET /` 回的**正是**一份 HTML 頁面。掃的是基底類別
    # `DEFAULT_ERROR_MESSAGE` 的字樣,並把 body 與那份頁面逐 byte 對完——
    # 逐 byte 這一條同時抓到另一個徵狀:`200` 的尾巴被 RST 吃掉。)
    assert b"Error response" not in stream, stream[-400:]
    assert b"Error code" not in stream, stream[-400:]
    _head, separator, payload = stream.partition(b"\r\n\r\n")
    assert separator, stream[:200]
    assert payload == PAGE_HTML_BYTES, (
        f"body 不是那一份頁面而已(差 {len(payload) - len(PAGE_HTML_BYTES)} "
        f"bytes):{payload[-400:]!r}"
    )
    # ③ 收尾的機制(複審授權項 (a)):宣告了而沒讀過的 body → 關連線 + 讀乾淨。
    assert b"Connection: close" in stream, stream[:400]


def test_a_static_request_without_a_body_still_reuses_the_connection(server):
    """另一半:**沒有**殘留 body 的靜態回應不補 `Connection: close`,keep-alive 照舊。

    (a) 的收尾是有條件的,條件就是「對方宣告了 body 而我們沒讀」。沒有這一條,
    修正就會變成「每個靜態回應都關連線」——頁面載入要 `/`、`/app.css`、
    `/app.js` 三個請求,每個都重開一條 TCP 連線。這條守住那個沒有發生。
    """
    conn = http.client.HTTPConnection(webui.LOOPBACK, server.port, timeout=10)
    try:
        for index, route in enumerate((webui.PAGE_PATH, webui.APP_JS_PATH)):
            conn.putrequest("GET", route, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", server.expected_host)
            conn.endheaders()
            res = conn.getresponse()
            payload = res.read()
            assert res.status == 200, (index, route, res.status)
            assert payload, (index, route)
            assert res.getheader("Connection") is None, (index, route)
            assert res.will_close is False, (index, route)
    finally:
        conn.close()


# ================================================================ 未知方法(裁定 ②)


@pytest.mark.parametrize("method", ["TRACE", "PROPFIND", "FOO", "BREW", "PATCH"])
@pytest.mark.parametrize("path", ["/", "/app.js", webui.API_INSPECT_PATH])
def test_an_unknown_method_is_405_json_not_501_html(server, method, path):
    """本票主管層裁定 ②:沒有具名 `do_<METHOD>` 的方法回 **405 + JSON**。

    標準庫的預設是 `501 Not Implemented` + 一份 **HTML** 錯誤頁(
    `BaseHTTPRequestHandler.handle_one_request` 查不到 `do_<METHOD>` 就
    `send_error`)。兩件事都不對:`501` 不在決策 14 的封閉集合裡,而 HTML body
    不是本層唯一的錯誤形式,還順手把「這是個 `BaseHTTPRequestHandler`」告訴了
    打進來的人。`_Handler.__getattr__` 把它收成跟 `PUT /` 一樣的那一句。
    """
    res = send(server, method, path, token=f"Bearer {server.token}",
               host=server.expected_host)
    assert res.status == 405, (res.status, res.text)
    assert res.json() == {"error": "method not allowed"}
    assert res.header("Content-Type") == webui.JSON_CONTENT_TYPE
    for name, value in webui.SECURITY_HEADERS:
        assert res.header(name) == value


def test_the_catch_all_only_answers_do_names(server):
    """catch-all **只**接 `do_` 開頭的名字,其餘照常 `AttributeError`。

    `_drain_request_body` 的 `getattr(self, "headers", None)` 與 `_route` 的
    `getattr(self, "path", "")` 要維持「真的沒有就是沒有」的語意——一個吃掉所有
    名字的 `__getattr__` 會把那兩個 `None` 預設值變成「永遠拿得到東西」,而那
    正是它們在請求行還沒解析成功時要處理的情況。
    """
    handler = webui._Handler.__new__(webui._Handler)
    assert handler.do_TRACE.__func__ is webui._Handler._dispatch
    assert handler.do_X.__func__ is webui._Handler._dispatch
    for name in ("do_", "headers", "path", "_body_consumed", "nope"):
        with pytest.raises(AttributeError):
            getattr(handler, name)


def test_an_unknown_method_does_not_print_a_traceback(server, capfd):
    """未知方法也不吐 traceback,access log 仍是 `<method> <path> <status>` 一行。"""
    capfd.readouterr()
    assert send(server, "BREW", "/", host=server.expected_host).status == 405
    output = capfd.readouterr()
    assert "Traceback" not in output.out + output.err
    assert "BREW / 405" in output.err, output.err
