r"""本機 Web UI 的 HTTP 伺服器骨架(ADR-002,決策 4–10、13)。

設計的唯一事實源 = `docs/adr/ADR-002-local-web-ui.md`(Accepted)。本檔是那份
決策的可執行轉錄:只綁 IPv4 loopback、一次性 bearer token、`Host` / `Origin` /
方法 / 型別 / 大小 / JSON 形式六道入口防線、三個 `/api/*` 端點、三份靜態內容與
安全標頭。

#21 交了伺服器骨架與 `/api/inspect`;#22 加上 `/api/encrypt` 與 `/api/decrypt`;
#23 把佔位頁換成真頁面(`/`、`/app.js`、`/app.css`)。`qvault ui` 子命令在 #24。

## 前端是三個模組常數,不是三個檔案(決策 1、10;#23 主管層裁定 ②)

`PAGE_HTML` / `APP_JS` / `APP_CSS` 住在這個模組裡,`_STATIC_RESPONSES` 在 import
時就把它們編成 bytes。沒有 `importlib` 的資源查詢、沒有相對於 `__file__` 的
路徑、更沒有讀 cwd——「wheel 裝起來之後 `/app.js` 還供不供得出來」因此不是一個
問題:供得出來的條件就只有「這個模組 import 成功」。

CSP(決策 10)是 `default-src 'none'` 起手,故這三份內容彼此之間是唯一的引用
關係:HTML 只引 `/app.css` 與 `/app.js` 這兩個同源絕對路徑,沒有 inline
script / inline style / `on*` 屬性 / 任何外部資源。token 只活在 `app.js` 的一個
變數裡(決策 5):從 fragment 讀進來、立刻 `history.replaceState` 抹掉網址列,
不進 `localStorage` / `sessionStorage` / cookie。

## 密碼只在 body,而且只往下傳(決策 2、5、9)

`passphrase` 這個欄位**只有一個讀取點**(`_passphrase`),而且它的回傳值只有
一個去處:`vault.encrypt_file` / `vault.decrypt_file` 的參數。密碼不進網址
(query 會進 access log)、不進標頭、不進任何 `_Reject` 的訊息、不進 log、
不進成功回應——`_log_line` 只記 method / path / 狀態碼,而成功回應的鍵恰為
`RESULT_KEYS`(只有寫出的路徑)。`tests/test_webui_crypto.py` 用一把一次性的
sentinel 密碼走完四條路徑,斷言它不在 stdout / stderr / 任何回應 body /
`tmp_path` 樹下任何非 `.qvt` 檔案 / `.qvt` 的 bytes 裡。

## 錯誤分類的單一事實源(決策 8;#22 主管層裁定)

例外 → `(kind, message)` 由 `errors.classify` 決定,`cli` 與本檔**共用同一個
函式**,故「UI 與 CLI 對同一狀況逐字同訊息」不靠人去對帳。本檔只多一張
`kind → HTTP 狀態碼` 的表(`_STATUS_BY_KIND`)——狀態碼是**本層的表達**,
不是錯誤體系的一部分,所以它住這裡而不是 `errors.py`。使用錯誤的訊息
(缺檔、拒絕覆寫、out_dir 不存在……)一律取 `errors` 的 `MSG_*` 常數:
本檔**不自己編**任何一句與 CLI 重疊的訊息(`tests/test_webui_crypto.py` 掃
AST 守著)。

## 新增的攻擊面與六道門(決策 5、6)

本模組讓本機多了一個會接受 HTTP 請求的程序,要防的是「使用者瀏覽器裡的其他
網頁」把它當跳板。每個請求依序過:

    1. Host     必須恰等於 `127.0.0.1:<port>`      違者 403  ← 擋 DNS rebinding
    2. method   `/api/*` 只收 POST                 違者 405
    3. Origin   若存在必須恰等於 `http://127.0.0.1:<port>`  違者 403
    4. 型別     `Content-Type: application/json`   違者 415
    5. 大小     `Content-Length` ≤ 64 KiB          違者 413
    6. token    `Authorization: Bearer <token>`    缺或錯 401

`/api/*` 在門 1 與門 2 之間另有一道**不是防跨站**的門:`qvault ui` 宣布停止
受理之後(`stop_accepting_work`,#24 複審 M1),新的 `/api/*` 一律 `503`——理由
在退出路徑那一側(別讓一份寫檔工作在沒有人等它的時候才開始),不在威脅模型裡,
故不編進上面那張表。

**前五道在讀 body 之前就判完**(決策 6),第六道也在 `rfile.read()` 之前——
一個 65,537 byte 的請求不會先被收進記憶體才被拒絕。順序照決策 6 的行文
(「一個不知道 token 的網頁**即使過得了這些**也打不進來」):形式防線是外門、
token 是內門,**兩道各自獨立**,任一道單獨成立就足以擋住跨來源的網頁。

`localhost` 刻意**不收**:它解析成什麼由 OS 的 hosts 檔決定,而那不是我們能
保證的東西(決策 6)。token 走網址的 **fragment**(`/#<token>`),瀏覽器不會把
fragment 送到伺服器,故它不進 access log、不進 `Referer`(決策 5)。

## 兩條在本層才成立的規矩

1. **不能改綁定位址,要在型別層面成立**(決策 4):`make_server` 的簽章只有
   `port`,沒有 `host` / `bind` / `address`。位址是模組常數 `LOOPBACK`,不是
   參數——「不能改」靠的不是文件,是**沒有那個參數可以傳**。
2. **什麼都不記、什麼都不吐**(決策 8、9):`log_message` 的每一行只有 method、
   path(不含 query)、狀態碼;`log_error` 整個收掉(它的訊息會轉述請求行);
   未預期例外只回**型別名**,永不 traceback——frame 裡躺著密碼與 DEK(鐵律 5)。
   而真的要記的那三樣**先過控制字元跳脫**(`_escaped`,#39):path 是攻擊者寫的,
   而 stderr 自 #24 起接到使用者的互動終端,原始 ESC 在那裡是可執行的控制序列。
3. **檔名與路徑的規則一律交給 `vault`**(決策 2):`.qvt` 的輸出路徑照 CLI 的
   規則組(同目錄、加 `QVT_SUFFIX`),但還原端的檔名**不由本層決定**——
   `decrypt_file` 解 chunk 0、淨化檔名(ADR-001 決策 17/21)、回傳它實際寫出的
   路徑,本層照抄進 `{"out": ...}`。在這裡再做一份淨化 = 兩份會漂,而漂掉的
   那一份是安全檢查。

## 一條連線只有一個關閉者(#47)

`WebUIServer.process_request` 把連線**交給**工作執行緒之後,主執行緒就關不動
它了:標準庫 `_handle_request_noblock` 的裸 `except:` 會對在途連線
`shutdown_request`(停止信號落在 `t.start()` 那一刻就會走到那裡),而工作執行緒
的 `finally` 本來就會關同一條連線——兩個關閉者裡,先到的那個會讓一個**已經
在組的回應**變成客戶端眼中的 `RemoteDisconnected`。修法見
`WebUIServer.process_request` 的 docstring:所有權歸工作執行緒,不靠逾時、
不覆寫私有方法。

## `inspect` 走白名單,而且是具名白名單([M7])

`_INSPECT_FIELDS` 與 `cli._INSPECT_FIELDS` 是**兩張表**,因為決策 13 不准 `webui`
import `cli`(相依方向是 `cli → webui`)。兩張表逐項相等由
`tests/test_webui_server.py::test_inspect_fields_match_the_cli_whitelist` 釘住:
它拿 `cli._INSPECT_FIELDS` 與本檔的表對照,任一邊漂掉就當場失敗。

表是「(鍵, 取值函式)」而不是 `dataclasses.asdict` / `vars()` / `FIELD_LAYOUT`
迴圈:差別在**新增欄位時的預設行為**。迴圈式的寫法會讓 header 未來多出來的欄位
(P1 的 ML-KEM 會加 `kem_pub` 之類的東西)**自動**被 JSON 吐出去;具名白名單的
預設是「不吐」,要多一欄得有人動手改表,程式碼審查看得見。`salt` /
`nonce_prefix` / `wrapped_dek` 因此在本檔的**程式碼裡一次都沒有被取值**
(只有這段說明文字提到它們,`tests/test_webui_server.py` 掃 AST 守著)。
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .container import (
    AEAD_ID_AES256GCM,
    HEADER_SIZE_KEM1,
    KDF_ID_SCRYPT,
    KEM_ID_SCRYPT,
    deserialize,
)
from .errors import (
    MSG_INPUT_IS_DIR,
    MSG_INPUT_MISSING,
    MSG_INPUT_NOT_REGULAR,
    MSG_OUT_DIR_MISSING,
    MSG_PASSPHRASE_EMPTY,
    MSG_PASSPHRASE_UNENCODABLE,
    MSG_REFUSE_OVERWRITE,
    QVaultError,
    classify,
)
from .vault import decrypt_file, encrypt_file

__all__ = [
    "LOOPBACK",
    "MAX_BODY_BYTES",
    "JSON_MEDIA_TYPE",
    "HTML_CONTENT_TYPE",
    "JS_CONTENT_TYPE",
    "CSS_CONTENT_TYPE",
    "PAGE_PATH",
    "APP_JS_PATH",
    "APP_CSS_PATH",
    "PAGE_HTML",
    "APP_JS",
    "APP_CSS",
    "CONTENT_SECURITY_POLICY",
    "SECURITY_HEADERS",
    "INSPECT_KEYS",
    "RESULT_KEYS",
    "API_INSPECT_PATH",
    "API_ENCRYPT_PATH",
    "API_DECRYPT_PATH",
    "QVT_SUFFIX",
    "WebUIServer",
    "make_server",
]

#: 唯一的綁定位址(決策 4)。**不是**參數、不從環境讀、沒有任何覆寫路徑:
#: IPv4 loopback 寫死在這裡,`::1` 也不綁(多一個位址就是多一個面)。
LOOPBACK = "127.0.0.1"

#: body 上限 64 KiB(決策 6)。路徑模式(決策 2)下 body 只有路徑與密碼,
#: 連這個都用不到十分之一;上限的用途是讓一個大 POST 在**讀進記憶體之前**被拒。
MAX_BODY_BYTES = 64 * 1024

JSON_MEDIA_TYPE = "application/json"
JSON_CONTENT_TYPE = "application/json; charset=utf-8"
HTML_CONTENT_TYPE = "text/html; charset=utf-8"
JS_CONTENT_TYPE = "text/javascript; charset=utf-8"
CSS_CONTENT_TYPE = "text/css; charset=utf-8"

#: 錯誤回應後的 lingering close 上限(見 `_Handler._drain_request_body`)。
DRAIN_LIMIT_BYTES = 1 << 20
DRAIN_TIMEOUT_SECONDS = 1.0

BEARER_SCHEME = "Bearer"
API_PREFIX = "/api/"
API_INSPECT_PATH = "/api/inspect"
API_ENCRYPT_PATH = "/api/encrypt"
API_DECRYPT_PATH = "/api/decrypt"
PAGE_PATH = "/"
APP_JS_PATH = "/app.js"
APP_CSS_PATH = "/app.css"

#: `encrypt` 的輸出檔名 = 輸入**加上**這個後綴(不是取代副檔名),與 CLI 同
#: (ADR-002 決策 7:「輸出與 CLI 同為同目錄 `<name>.qvt`」)。兩邊逐字相等由
#: `tests/test_webui_crypto.py::test_the_suffix_is_the_same_one_the_cli_uses` 釘住。
QVT_SUFFIX = ".qvt"

#: `encrypt` / `decrypt` 成功回應的鍵,恰為這些(決策 2:「回應只回寫出的路徑」)。
#: 不回原始大小、不回檔名以外的任何中繼資料——那些正是決策 9 要保護的東西。
RESULT_KEYS: tuple[str, ...] = ("out",)

#: 決策 10 的 CSP,逐字。`default-src 'none'` 起手,故前端**沒有** inline
#: script / inline style / `on*` 屬性 / 外部資源,一個都不能有。
#: `tests/test_webui_server.py::test_csp_constant_matches_adr_002` 拿 ADR 原文對,
#: ADR 改字而這裡沒跟上就當場失敗(反之亦然)。
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)

#: 決策 10:**所有**回應都帶這三個。由 `_Handler.end_headers` 統一注入,
#: 故連基底類別自己發的錯誤回應(畸形請求行之類)也帶得上——漏一條路徑的
#: 可能性因此是零。
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)

#: 演算法 id → 人看得懂的名字(與 `cli._KDF_NAMES` 等三張表同內容,見模組
#: docstring 為何是兩份)。純顯示用;id 的合法性由 `container.deserialize` 把關。
KDF_NAMES = {KDF_ID_SCRYPT: "scrypt"}
AEAD_NAMES = {AEAD_ID_AES256GCM: "AES-256-GCM"}
KEM_NAMES = {KEM_ID_SCRYPT: "scrypt-KEK"}
UNKNOWN_NAME = "unknown"

#: [M7] `/api/inspect` 的白名單:(JSON 鍵, 取值函式)。見模組 docstring。
#: `file_size` 不在這張表裡——它來自 `fstat`,不是 header 欄位。
_INSPECT_FIELDS: tuple[tuple[str, object], ...] = (
    ("version", lambda h: h.version),
    ("kdf_id", lambda h: h.kdf_id),
    ("kdf_name", lambda h: KDF_NAMES.get(h.kdf_id, UNKNOWN_NAME)),
    ("aead_id", lambda h: h.aead_id),
    ("aead_name", lambda h: AEAD_NAMES.get(h.aead_id, UNKNOWN_NAME)),
    ("kem_id", lambda h: h.kem_id),
    ("kem_name", lambda h: KEM_NAMES.get(h.kem_id, UNKNOWN_NAME)),
    ("kdf_log2n", lambda h: h.kdf_log2n),
    ("kdf_r", lambda h: h.kdf_r),
    ("kdf_p", lambda h: h.kdf_p),
    ("chunk_size", lambda h: h.chunk_size),
)

#: `/api/inspect` 回應的鍵,恰為這些(決策 7)。
INSPECT_KEYS: tuple[str, ...] = tuple(key for key, _ in _INSPECT_FIELDS) + (
    "file_size",
)

#: 真頁面(決策 11)。三個表單 = 三個操作;每個 `<input>` 配一個 `<label for>`;
#: 結果進 `aria-live="polite"` 區、錯誤進 `role="alert"` 區。
#:
#: CSP 是 `default-src 'none'; script-src 'self'; style-src 'self'`,故這裡
#: **一個** inline script / inline style / `on*` 屬性 / 外部資源都沒有:樣式全在
#: `/app.css`、行為全在 `/app.js`,兩者都是同源的絕對路徑。表單不給 `action`
#: 也不給 `method`——`form-action 'none'` 會擋掉真的表單送出,送出一律由
#: `app.js` 攔 `submit` 事件接手(決策 10)。
#:
#: 欄位的 `id` 是「`<表單>_<欄位名>`」而 `name` 是裸的欄位名:`name` 要跟
#: API 的 JSON 鍵一對一(決策 7),而 `id` 必須全頁唯一(三個表單都有 `path`)。
PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QVault</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header>
<h1>QVault</h1>
<p>本機保險庫。檔案由這台機器上的 QVault 自己讀寫,內容不經網路;密碼只在送出的
那一刻存在,送出後欄位立刻清空。</p>
</header>

<section id="output">
<h2>結果</h2>
<p id="error" role="alert"></p>
<div id="result" aria-live="polite"></div>
</section>

<form id="encrypt">
<h2>加密</h2>
<p class="field">
<label for="encrypt_path">要加密的檔案路徑</label>
<input id="encrypt_path" name="path" type="text" autocomplete="off" required>
</p>
<p class="field">
<label for="encrypt_passphrase">密碼</label>
<input id="encrypt_passphrase" name="passphrase" type="password" autocomplete="new-password" required>
</p>
<p class="field">
<label for="encrypt_passphrase_confirm">再輸入一次密碼</label>
<input id="encrypt_passphrase_confirm" name="passphrase_confirm" type="password" autocomplete="new-password" required>
</p>
<p class="field inline">
<input id="encrypt_force" name="force" type="checkbox">
<label for="encrypt_force">覆寫已存在的輸出檔</label>
</p>
<p class="actions"><button type="submit">加密</button></p>
</form>

<form id="decrypt">
<h2>解密</h2>
<p class="field">
<label for="decrypt_path">要解密的 .qvt 路徑</label>
<input id="decrypt_path" name="path" type="text" autocomplete="off" required>
</p>
<p class="field">
<label for="decrypt_out_dir">還原到哪個目錄</label>
<input id="decrypt_out_dir" name="out_dir" type="text" autocomplete="off" required>
</p>
<p class="field">
<label for="decrypt_passphrase">密碼</label>
<input id="decrypt_passphrase" name="passphrase" type="password" autocomplete="current-password" required>
</p>
<p class="field inline">
<input id="decrypt_force" name="force" type="checkbox">
<label for="decrypt_force">覆寫已存在的輸出檔</label>
</p>
<p class="actions"><button type="submit">解密</button></p>
</form>

<form id="inspect">
<h2>檢視</h2>
<p class="field">
<label for="inspect_path">要檢視的 .qvt 路徑</label>
<input id="inspect_path" name="path" type="text" autocomplete="off" required>
</p>
<p class="actions"><button type="submit">檢視</button></p>
</form>

<script src="/app.js"></script>
</body>
</html>
"""

#: 前端行為(決策 5、11)。只做四件事:取 token、組請求、把結果以 `textContent`
#: 寫進兩個區、送出後清掉密碼欄。業務規則全在伺服器(決策 11),唯一的前端檢查
#: 是 encrypt 的兩次密碼一致——伺服器只收一次密碼(決策 7),所以二次確認除了
#: 在這裡做沒有別的地方可做。
#:
#: 幾個形狀是 AC 直接驗原始碼的(#23 主管層裁定 ①),改動時請一起讀
#: `tests/test_webui_page.py`:
#:   * `location.hash` + `history.replaceState`:token 進記憶體、fragment 離開網址列
#:   * 不出現 `localStorage` / `sessionStorage` / `document.cookie` / `innerHTML`
#:   * 每個 `fetch(` 的第一個參數是三條 API 路徑之一的**字面值**,且呼叫點自帶
#:     `Authorization` 與 `Content-Type: application/json`(所以沒有共用的 headers
#:     輔助函式——「每個 fetch 都帶這兩個」要在原始碼上一眼看得完)
#:   * 兩次密碼不一致 → 在任何 `fetch(` 之前 `return`
#:   * 三個密碼欄各恰有一處 `.value = ""`,成功與失敗兩條路都會走到
APP_JS = """\"use strict\";

/* QVault 本機 Web UI 的前端(ADR-002 決策 5、10、11)。
 *
 * 這份檔案是頁面上唯一的腳本:CSP 的 `script-src 'self'` 讓 inline script 與
 * `on*` 屬性一律失效,所有行為都在這裡綁 `addEventListener`。
 *
 * token 只活在下面這個變數裡(決策 5):從網址 fragment 讀進來,立刻用
 * `history.replaceState` 把 fragment 從網址列抹掉。它不寫檔、不進 cookie、
 * 不進瀏覽器的任何持久化儲存、也不回寫進 DOM——頁面一關就沒了,而這一條是
 * `tests/test_webui_page.py` 用「這份原始碼裡找不到那幾個 API 的名字」驗的。
 */

let token = "";

const MSG_MISMATCH = "兩次輸入的密碼不一致;沒有送出任何請求。";
const MSG_WORKING = "處理中…";
const MSG_UNREACHABLE = "連不上本機伺服器——它可能已經結束了。";
const MSG_WRITTEN = "已寫出:";
const MSG_BAD_RESPONSE = "伺服器的回應不是預期的格式;沒有任何檔案被寫出的證據。";

const encryptForm = document.getElementById("encrypt");
const decryptForm = document.getElementById("decrypt");
const inspectForm = document.getElementById("inspect");
const errorBox = document.getElementById("error");
const resultBox = document.getElementById("result");

/* ------------------------------------------------------------------ token */

function readTokenFromFragment() {
  const fragment = location.hash;
  token = fragment.charAt(0) === "#" ? fragment.slice(1) : fragment;
  history.replaceState(null, "", location.pathname);
}

/* -------------------------------------------- 顯示:一律 textContent,不碰 HTML */

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function showError(message) {
  clearChildren(resultBox);
  errorBox.textContent = message;
}

function showLine(message) {
  errorBox.textContent = "";
  clearChildren(resultBox);
  const line = document.createElement("p");
  line.textContent = message;
  resultBox.appendChild(line);
}

function showWrittenPath(payload) {
  if (typeof payload.out !== "string") {
    showError(MSG_BAD_RESPONSE);
    return;
  }
  showLine(MSG_WRITTEN + payload.out);
}

function showFields(payload) {
  errorBox.textContent = "";
  clearChildren(resultBox);
  const list = document.createElement("dl");
  Object.keys(payload).forEach(function (key) {
    const term = document.createElement("dt");
    term.textContent = key;
    const value = document.createElement("dd");
    value.textContent = String(payload[key]);
    list.appendChild(term);
    list.appendChild(value);
  });
  resultBox.appendChild(list);
}

/* --------------------------------------------------------------- 密碼欄清空 */

function clearPassphrases() {
  encryptForm.elements.passphrase.value = "";
  encryptForm.elements.passphrase_confirm.value = "";
  decryptForm.elements.passphrase.value = "";
}

/* ------------------------------------------------------------ 三個 submit */

function onEncryptSubmit(event) {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  /* 唯一的前端規則:兩次密碼不一致就**不送請求**(決策 7)。 */
  if (fields.passphrase_confirm.value !== fields.passphrase.value) {
    clearPassphrases();
    showError(MSG_MISMATCH);
    return;
  }
  settle(sendEncrypt({
    path: fields.path.value,
    passphrase: fields.passphrase.value,
    force: fields.force.checked
  }), showWrittenPath);
}

function onDecryptSubmit(event) {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  settle(sendDecrypt({
    path: fields.path.value,
    out_dir: fields.out_dir.value,
    passphrase: fields.passphrase.value,
    force: fields.force.checked
  }), showWrittenPath);
}

function onInspectSubmit(event) {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  settle(sendInspect({ path: fields.path.value }), showFields);
}

/* 成功與失敗**兩條路**都清密碼欄,然後才顯示結果。 */
function settle(pending, onPayload) {
  showLine(MSG_WORKING);
  pending.then(function (payload) {
    clearPassphrases();
    onPayload(payload);
  }, function (failure) {
    clearPassphrases();
    showError(failure.message || MSG_UNREACHABLE);
  });
}

/* ------------------------------------------------------------ 三條 API 請求 */

function sendEncrypt(body) {
  return oneJsonResponse(fetch("/api/encrypt", {
    method: "POST",
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }));
}

function sendDecrypt(body) {
  return oneJsonResponse(fetch("/api/decrypt", {
    method: "POST",
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }));
}

function sendInspect(body) {
  return oneJsonResponse(fetch("/api/inspect", {
    method: "POST",
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }));
}

/* 伺服器的每個回應都是 JSON:成功回 payload,4xx/5xx 把 `error` 那一行抬成
 * `Error`——錯誤訊息的唯一來源是伺服器(決策 8),前端不自己編。 */
function oneJsonResponse(pending) {
  return pending.then(function (response) {
    return response.json().catch(function () {
      return null;
    }).then(function (payload) {
      if (payload === null || typeof payload !== "object") {
        throw new Error(MSG_BAD_RESPONSE + "(HTTP " + String(response.status) + ")");
      }
      if (!response.ok) {
        throw new Error(payload.error || "HTTP " + String(response.status));
      }
      return payload;
    });
  });
}

/* ------------------------------------------------------------------ 啟動 */

readTokenFromFragment();
encryptForm.addEventListener("submit", onEncryptSubmit);
decryptForm.addEventListener("submit", onDecryptSubmit);
inspectForm.addEventListener("submit", onInspectSubmit);
"""

#: 樣式(決策 10)。`style-src 'self'` 讓 `<style>` 與 `style=` 失效,故樣式只能
#: 從這裡來。這裡也刻意沒有 `@import`、沒有任何位址引用、沒有自備字型:外部資源
#: 為零是 AC 直接掃的一條,而 `color-scheme` 讓深淺兩色由瀏覽器決定,
#: 不必自己配一組顏色。
APP_CSS = """:root {
  color-scheme: light dark;
}

body {
  margin: 0 auto;
  max-width: 44rem;
  padding: 1.5rem 1rem 4rem;
  font-family: system-ui, sans-serif;
  line-height: 1.5;
}

h1 {
  margin: 0 0 0.25rem;
  font-size: 1.5rem;
}

h2 {
  margin: 0 0 0.75rem;
  font-size: 1rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  opacity: 0.7;
}

header p {
  margin: 0 0 1.5rem;
  opacity: 0.75;
}

form,
#output {
  margin: 0 0 1.25rem;
  padding: 1rem;
  border: 1px solid;
  border-radius: 0.5rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin: 0 0 0.75rem;
}

.field.inline {
  flex-direction: row;
  align-items: center;
  gap: 0.5rem;
}

label {
  font-size: 0.875rem;
}

input[type="text"],
input[type="password"] {
  font: inherit;
  padding: 0.4rem 0.5rem;
  border: 1px solid;
  border-radius: 0.25rem;
  background: transparent;
  color: inherit;
}

.actions {
  margin: 0;
}

button {
  font: inherit;
  padding: 0.4rem 1.25rem;
  border: 1px solid;
  border-radius: 0.25rem;
  background: transparent;
  color: inherit;
  cursor: pointer;
}

#error {
  margin: 0;
  font-weight: 600;
}

#error:empty {
  display: none;
}

#result p {
  margin: 0;
  overflow-wrap: anywhere;
}

#result dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.15rem 0.75rem;
  margin: 0;
  font-variant-numeric: tabular-nums;
}

#result dt {
  opacity: 0.7;
}

#result dd {
  margin: 0;
  overflow-wrap: anywhere;
}
"""

#: 路徑 → (已編碼的 bytes, Content-Type)。在 import 時就編好:每個請求重編一次
#: 同一份不會變的內容是白做的工,而「內容來自模組常數」這條 AC 也因此在型別
#: 層面看得見——這張表的值沒有任何一條路徑通往檔案系統。
_STATIC_RESPONSES: dict[str, tuple[bytes, str]] = {
    PAGE_PATH: (PAGE_HTML.encode("utf-8"), HTML_CONTENT_TYPE),
    APP_JS_PATH: (APP_JS.encode("utf-8"), JS_CONTENT_TYPE),
    APP_CSS_PATH: (APP_CSS.encode("utf-8"), CSS_CONTENT_TYPE),
}


class _Reject(Exception):
    """入口防線或使用錯誤:一個狀態碼 + 一行訊息,收斂成 JSON `{"error": ...}`。

    只裝**訊息**,不裝原例外——`__cause__` 一旦帶上,任何一個手滑的 `raise` 都
    可能把底層例外(與它 frame 裡的東西)帶進回應。同 `cli._CleanExit` 的理由。
    """

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _dumps(payload: dict) -> bytes:
    """`dict` → JSON bytes。**唯一**的回應編碼點,而且不可編碼的字元殺不掉它。

    `errors="replace"` 不是潔癖:`path` / `out_dir` 是使用者給的字串,裡面可能
    有一個**孤兒代理對**(`chr(0xDC80)`,Windows argv 與某些輸入法產生得出來,
    JSON 也送得進來)。`str.encode("utf-8")` 對它會拋 `UnicodeEncodeError`——而
    這個 encode 發生在**錯誤出口自己**裡面,拋了就沒有人能回答了:連線被丟掉,
    客戶端收到的是 `RemoteDisconnected`,連一個狀態碼都沒有,比 `5xx` 更糟
    (決策 14 的不變式「任何畸形輸入都收斂成 4xx、伺服器不倒」會當場破掉)。

    退化成 `?` 同時是對的方向:那個字元本來就不該被回顯——它可能是使用者
    密碼的一部分(鐵律 5),而 `_passphrase` 那條路徑也是這樣處理的。
    """
    return json.dumps(payload, ensure_ascii=False, sort_keys=False).encode(
        "utf-8", "replace"
    )


#: `errors.classify` 的 `kind` → HTTP 狀態碼(ADR-002 決策 8 的那張表,逐列)。
#:
#: **這張表住這裡,不住 `errors.py`**(#22 主管層裁定):狀態碼是 web 這一層的
#: 表達方式,錯誤體系不該知道 HTTP 存在。反過來說,本檔也不自己判斷「這個例外
#: 算哪一類」——那是 `classify` 的事,兩端共用。
#:
#: `unexpected → 500` 這一列的 `message` 是**型別名**(`classify` 保證),故
#: 決策 8 的「`5xx` 的 body 只給例外型別名」在這裡是結構性的,不靠呼叫端自律。
_STATUS_BY_KIND: dict[str, HTTPStatus] = {
    "format": HTTPStatus.UNPROCESSABLE_ENTITY,
    "decrypt": HTTPStatus.UNPROCESSABLE_ENTITY,
    "version": HTTPStatus.UNPROCESSABLE_ENTITY,
    "missing": HTTPStatus.NOT_FOUND,
    "exists": HTTPStatus.CONFLICT,
    "not_dir": HTTPStatus.BAD_REQUEST,
    "usage": HTTPStatus.BAD_REQUEST,
    "unexpected": HTTPStatus.INTERNAL_SERVER_ERROR,
}

#: 本層自己的使用錯誤(**沒有** CLI 對應情境,故不在 `errors` 的 `MSG_*` 裡):
#: 型別錯是 HTTP/JSON 才有的問題——CLI 那邊由 argparse 把關,根本到不了。
#: 只提欄位**名字**,絕不回顯欄位的**值**(`passphrase` 的值是密碼)。
_MSG_NOT_A_STRING = "{field} must be a string"
_MSG_NOT_A_BOOLEAN = "{field} must be a boolean"

#: `qvault ui` 已經宣布停止受理新工作(複審 M1)。退出路徑等在途工作的那幾秒裡,
#: keep-alive 的既有連線還送得進新的 `/api/*`,而受理它就是在退出之後才開始寫
#: 一個 `.qvault-*.part`——不是客戶端做錯了什麼,所以是 `503` 而不是 `4xx`。
_MSG_SHUTTING_DOWN = "server is shutting down"

#: 路徑字串本身不可用(含 NUL、長到 `ENAMETOOLONG`……):`Path.exists()` 這類
#: 查詢就會拋,連 `stat` 都走不到。是使用錯誤,不是我們的 bug。
_MSG_PATH_UNUSABLE = "path is not a usable file name"
#: `out_dir: ""` 在 `Path` 裡等於 `.`——UI 看不見伺服器的 cwd,故 API 要求明說
#: (CLI 的 `.` 是看得見的預設值,兩者不對稱是刻意的;#30 複審 L4)。
_MSG_OUT_DIR_EMPTY = "out_dir must not be empty"

#: 同一個寫入目標的請求**序列化**(#30 複審 M5)。`vault` 是「先查存在 → 整檔
#: 加解密 → `os.replace`」,而 `os.replace` 會覆寫:`ThreadingHTTPServer` 下兩個
#: 打同一個目標的請求若都在對方 replace 前查過「不存在」,就都回 `200`——encrypt
#: 的檔只解得開後寫的那一把密碼,decrypt 的明文互蓋。核心四檔凍結,故在本層
#: 以「目標一把鎖」關掉它:encrypt 的鍵是輸出檔,decrypt 的鍵是 `out_dir`(檔名
#: 要解開 chunk 0 才知道)。已知邊界:encrypt 寫 `D/x.qvt` 與 decrypt 進 `D` 而
#: 還原名恰為 `x.qvt` 兩者鍵不同,不互斥;本程序以外的寫入者本層也管不到。
#: 鎖表只增不減(一個本機工具一次執行碰到的目標數有限)。
_TARGET_LOCKS: dict[str, threading.Lock] = {}
_TARGET_LOCKS_GUARD = threading.Lock()


def _target_lock(path: Path) -> threading.Lock:
    """`path` 的那一把寫入鎖(以 `realpath` 為鍵,同一目標的不同寫法共用一把)。"""
    key = os.path.realpath(path)
    with _TARGET_LOCKS_GUARD:
        return _TARGET_LOCKS.setdefault(key, threading.Lock())


#: access log 的控制字元跳脫表(#39)。鍵涵蓋 **C0**(`0x00`–`0x1f`,含 ESC / CR /
#: LF)、**DEL**(`0x7f`)、**C1**(`0x80`–`0x9f`),外加反斜線本身——不跳脫反斜線的話,
#: path 裡寫死的五個字面字元 `\x1b` 與真 ESC 跳脫後同形,讀 log 的人分不出哪個是哪個。
#:
#: 這張表與標準庫 `BaseHTTPRequestHandler._control_char_table` 同語意,但**不引用它**:
#: 那是私有名(底線開頭),CPython 任何一個小版本都可以搬掉它。委派
#: `super().log_message()` 同樣不行——它會把 `address_string()` 與時間戳前綴進每一行,
#: 而決策 9 只准 method / path / 狀態碼三樣。
_CONTROL_CHAR_TABLE = str.maketrans(
    {code: f"\\x{code:02x}" for code in (*range(0x20), 0x5C, 0x7F, *range(0x80, 0xA0))}
)


def _escaped(text: str) -> str:
    r"""`text` 的控制字元換成 `\xNN` 字面(#39)。

    寫進 stderr 的東西有一半是攻擊者寫的(請求行裡的 path)。stderr 自 #24 起接到
    使用者的**互動終端**,所以原始的 ESC 會被終端當控制序列執行:清畫面、改游標、
    印一行假網址。跳脫之後它只是字元,而且因為 CR / LF 一起跳脫,一筆 log 保證一行
    ——log 不會被塞進第二筆假的 access log 行。

    **表到 U+009F 封頂就夠用,但那是一個有前提的「夠用」**(#42 F6)。到得了這裡
    的 path 只有 `_route()` 從 `self.path` 切出來的那一段,而 `self.path` 來自
    `BaseHTTPRequestHandler.parse_request` 的
    `requestline = str(self.raw_requestline, "iso-8859-1")`(CPython 3.12)——
    iso-8859-1 解得出來的字元恰好是 U+0000–U+00FF,所以這張表蓋得住**所有到得了
    這一層的**控制字元。U+0085(`Cc`)、U+2028(`Zl`)、U+202E(`Cf`)這類更高碼位
    的控制 / 格式字元**今天打不進來**,因此不在表上。

    前提只有一個,而且它不在本函式裡:請求行處理路徑(`_route` 與它的上游)
    **不得做百分號解碼**。`urllib.parse.unquote` 會把 `%E2%80%AE` 變成真的
    U+202E,表的上緣當場就成了缺口——雙向控制字元於是原封不動落到終端上,
    把 access log 那一行的 path 視覺上反轉。承重的那一半是測試而不是這段話:
    `tests/test_webui_log_premise.py::test_the_request_line_path_never_percent_decodes`
    以 `ast` 掃本檔,在這條路上注入一次 `unquote` 就紅。真的哪天需要解碼,
    改表(改成依 `unicodedata.category in {Cc, Cf, Zl, Zp}` 一律跳脫)要與那次
    改動同一個 commit。
    """
    return text.translate(_CONTROL_CHAR_TABLE)


def _status(kind: str) -> HTTPStatus:
    """`kind` → 狀態碼。查不到就是我們漏了一列,`KeyError` 會變成 `500`。"""
    return _STATUS_BY_KIND[kind]


def _classified(exc: BaseException) -> _Reject:
    """例外 → `_Reject`:分類與訊息來自 `errors.classify`,狀態碼來自本層的表。

    這是本檔**唯一**把例外翻成回應的地方(連 `_dispatch` 的未預期例外也走它),
    故「同一個例外在 UI 與 CLI 說同一句話」不可能漏掉某一條路徑。
    """
    kind, message = classify(exc)
    return _Reject(_status(kind), message)


def _text_field(payload: dict, field: str) -> str:
    """取一個**必填的字串**欄位;型別不符 → `400`,訊息只提欄位名。"""
    value = payload.get(field)
    if not isinstance(value, str):
        raise _Reject(_status("usage"), _MSG_NOT_A_STRING.format(field=field))
    return value


def _flag(payload: dict, field: str) -> bool:
    """取一個**選填的 bool** 欄位(缺席 = `False`);`1` / `"true"` 都不算。

    寬鬆解讀(「非空就是真」)在這裡的代價是**覆寫別人的檔案**:`force` 是
    decrypt 唯一會讓明文蓋過既有檔的開關,寧可回 `400` 要前端說清楚。
    """
    value = payload.get(field, False)
    if not isinstance(value, bool):
        raise _Reject(_status("usage"), _MSG_NOT_A_BOOLEAN.format(field=field))
    return value


def _passphrase(payload: dict) -> str:
    """密碼的**唯一**讀取點(決策 7)。回傳值只往 `vault` 的參數去,別無去處。

    三道檢查與 CLI 逐字同訊息(`errors` 的 `MSG_*`):非字串、空字串、無法
    UTF-8 編碼。最後那條**絕不**轉述 `UnicodeEncodeError`——它的訊息會把出錯的
    那個字元印出來,而那是密碼的一部分(鐵律 5);`MSG_PASSPHRASE_UNENCODABLE`
    是定值,不帶輸入。

    空字串在這裡就拒絕,不進 KDF:`encrypt` 從不接受空密碼,故不存在任何一個
    `.qvt` 是空密碼加密的(同 `cli._ask_passphrase` 的理由)。
    """
    value = payload.get("passphrase")
    if not isinstance(value, str):
        raise _Reject(_status("usage"), _MSG_NOT_A_STRING.format(field="passphrase"))
    if not value:
        raise _Reject(_status("usage"), MSG_PASSPHRASE_EMPTY)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _Reject(_status("usage"), MSG_PASSPHRASE_UNENCODABLE) from None
    return value


class _Handler(BaseHTTPRequestHandler):
    """一個請求一次六道門(見模組 docstring 的表)。

    所有方法都走同一個 `_dispatch`:`Host` 的檢查因此對**任何**方法都成立,
    不只 GET / POST——「任何請求」照字面做,免得哪天多一個 `do_*` 就漏一道門。
    """

    #: 不吐 Python 版本(預設的 `sys_version` 會把它寫進 `Server` 標頭:
    #: 那是免費送給攻擊者的版本指紋,而本機 UI 沒有任何理由需要它)。
    server_version = "qvault-webui"
    sys_version = ""

    #: HTTP/1.1 + 每個回應都帶 `Content-Length`(見 `_respond`)。錯誤回應一律
    #: 附 `Connection: close`:被擋下的請求我們**沒有讀它的 body**,那些位元組
    #: 還在 socket 裡,連線不關就會被下一個請求當成請求行(request smuggling)。
    protocol_version = "HTTP/1.1"

    #: keep-alive 的閒置連線不會永遠佔著一條執行緒(測試的 `shutdown()` 也因此
    #: 不必等任何人)。
    timeout = 10

    # ------------------------------------------------------------ 路由

    def _dispatch(self) -> None:
        """唯一的入口。三類出口:正常、`_Reject`、以及我們自己的 bug。"""
        self._body_consumed = False
        try:
            self._handle()
        except _Reject as rejected:
            self._error(rejected.status, rejected.message)
        except Exception as exc:  # noqa: BLE001 —— 見下
            # 決策 8:`5xx` 的 body **只有例外型別名**,永不訊息、永不 traceback。
            # 例外訊息會轉述輸入(路徑、甚至密碼),traceback 的 frame 裡躺著
            # 密碼與 DEK(鐵律 5)。型別名足夠讓人開票,而且不含任何輸入。
            #
            # 走 `_classified` 而不是自己寫 `500 + type(exc).__name__`:
            # `classify` 對未預期例外回的就是型別名,而「只有型別名」這件事
            # 因此只有**一個**實作點(端點與這裡共用),漏不掉也漂不掉。
            rejected = _classified(exc)
            self._error(rejected.status, rejected.message)

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch

    def __getattr__(self, name: str) -> object:
        """具名清單**之外**的方法也走 `_dispatch`(#25 主管層裁定 ②)。

        `handle_one_request` 的分派是 `hasattr(self, "do_" + self.command)`:查不到
        就由基底類別回 **`501 Not Implemented`**,而那個回應有兩個問題——body 是
        **HTML**(不是本層唯一的錯誤形式 `{"error": …}`),狀態碼也不在決策 14 的
        封閉集合裡。`do_TRACE` / `do_PROPFIND` / `do_BREW` 這種動詞打進來時,使用者
        看到的應該跟 `PUT /` 一樣是一句 `405`,而不是「這個伺服器用的是
        `BaseHTTPRequestHandler`」這條實作細節。

        上面那串 `do_* = _dispatch` 因此**不是**白名單,只是具名的常見動詞;
        「任何方法都過同一條路」由這裡在型別層面成立,不靠有人記得補一行。
        方法是否受理仍由 `_handle` 判(靜態路由只收 GET / HEAD,`/api/*` 只收
        POST),故這個 catch-all 一個方法都沒有**放行**,只是把拒絕的話換成
        本層自己的那一句。

        只接 `do_` 開頭的名字,其餘照常 `AttributeError`:`getattr(self, …, None)`
        式的探測(`_drain_request_body` 的 `headers`、`_route` 的 `path`)必須維持
        原本「真的沒有就是沒有」的語意。
        """
        if name.startswith("do_") and len(name) > 3:
            return self._dispatch
        raise AttributeError(name)

    def _handle(self) -> None:
        # 門 1:Host(決策 6)。在路由之前,故 `GET /` 也過這道門。
        if self.headers.get("Host", "") != self.server.expected_host:
            raise _Reject(HTTPStatus.FORBIDDEN, "unexpected Host header")

        route = self._route()
        if route.startswith(API_PREFIX):
            # 在途計數(#24 F1):`/api/*` 是**唯一**會寫檔的路徑,而
            # `vault` 的寫法是「寫 `.qvault-*.part` → `os.replace`」。連線執行緒
            # 是 daemon,直譯器一結束就被砍掉、`finally` 不跑——於是中途被打斷
            # 的解密會把一個**明文片段**留在 out_dir 裡。`qvault ui` 因此要在
            # 退出前等這段做完(`wait_until_idle`),而「這段」只有這裡數得出來:
            # keep-alive 的連線執行緒在兩個請求之間是活著但閒著的,從外面看
            # 分不出「正在解密」與「在等下一個請求」。
            #
            # 門 1.5:**退出中**(複審 M1)。`serve_forever` 回來之後不再有新
            # 連線,但 HTTP/1.1 keep-alive 的既有連線仍送得進一個新的
            # `/api/*`——`server_close()` 關的是 listen socket,不是已經建立的
            # 連線。在退出路徑等在途工作的那幾秒裡受理它,等於在等待結束
            # **之後**才開始寫一份 `.qvault-*.part`,然後被直譯器結束時砍掉的
            # daemon 執行緒留在半路。「不再受理」與「把自己數進去」在
            # `work_started` 的**同一把鎖**裡發生,故兩者之間沒有縫:它回
            # `False` 就是沒被數進去,這個請求拿 `503`。
            if not self.server.work_started():
                raise _Reject(HTTPStatus.SERVICE_UNAVAILABLE, _MSG_SHUTTING_DOWN)
            try:
                self._handle_api(route)
            finally:
                self.server.work_finished()
            return

        # 頁面與兩份靜態內容只收 GET / HEAD。
        if self.command not in ("GET", "HEAD"):
            raise _Reject(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
        static = _STATIC_RESPONSES.get(route)
        if static is not None:
            self._static(static)
            return
        raise _Reject(HTTPStatus.NOT_FOUND, "not found")

    def _route(self) -> str:
        """請求路徑,**去掉 query 與 fragment**。

        去 query 不只是為了路由:`_log_line` 記的是同一個值,而 token 若被某個
        客戶端塞進 `?token=`(Jupyter 式,決策的否決清單裡那條),去掉 query 就是
        它不會進 access log 的理由。
        """
        path = getattr(self, "path", "") or ""
        return path.split("?", 1)[0].split("#", 1)[0]

    def _handle_api(self, route: str) -> None:
        """`/api/*`:門 2–6 跑完才碰 body。"""
        # 門 2:方法。
        if self.command != "POST":
            raise _Reject(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

        # 門 3:Origin。缺席代表非瀏覽器客戶端(瀏覽器對跨來源 POST 一定送
        # Origin),放行;`null` 是個**字串**,不等於缺席,故照樣擋(決策 6)。
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.expected_origin:
            raise _Reject(HTTPStatus.FORBIDDEN, "unexpected Origin header")

        # 門 4:型別。`application/json; charset=utf-8` 算合格,`text/plain` 與
        # 缺席不算——表單的 `text/plain` / `multipart` 正是跨來源 POST 打得出來的
        # 三種型別,擋掉它們等於擋掉無 JS 的 CSRF 表單。
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if media_type.strip().lower() != JSON_MEDIA_TYPE:
            raise _Reject(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                f"Content-Type must be {JSON_MEDIA_TYPE}",
            )

        # 門 5:大小。在 `read()` 之前,故超標的 body 一個 byte 都不進記憶體。
        length = self._content_length()

        # 門 6:token(決策 5)。仍在 `read()` 之前。
        if not self._authorized():
            raise _Reject(HTTPStatus.UNAUTHORIZED, "missing or invalid bearer token")

        endpoint = self._ENDPOINTS.get(route)
        if endpoint is None:
            raise _Reject(HTTPStatus.NOT_FOUND, "not found")

        endpoint(self, self._read_json(length))

    # ------------------------------------------------------------ 門的實作

    def _content_length(self) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            length = int(raw)
        except ValueError:
            raise _Reject(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from None
        if length < 0:
            raise _Reject(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise _Reject(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"request body must be at most {MAX_BODY_BYTES} bytes",
            )
        return length

    def _authorized(self) -> bool:
        """`Authorization: Bearer <token>`,比對走 `hmac.compare_digest`(決策 5)。

        **不是** `==`:字串的 `==` 一比到不同的 byte 就回來,而這個伺服器就在
        攻擊者的瀏覽器打得到的地方——可量測的時間差會把 token 一個 byte 一個
        byte 地交出去。長度不同時 `compare_digest` 也不洩內容。

        標頭值由 `http.client` / 瀏覽器以 iso-8859-1 解碼,`latin-1` 編回去就是
        線上的原始 bytes;token 自己是 urlsafe base64(純 ASCII),兩邊同碼。
        """
        scheme, _, presented = self.headers.get("Authorization", "").partition(" ")
        if scheme != BEARER_SCHEME:
            return False
        return hmac.compare_digest(
            presented.encode("latin-1"), self.server.token.encode("latin-1")
        )

    def _read_json(self, length: int) -> dict:
        """讀 body 並解成 **JSON 物件**;其餘一律 `400`(決策 8)。

        `[]` / `"x"` / 壞 JSON / 空 body 都不是物件,四種同一個碼:回應不區分
        「你送了陣列」與「你送了半個 JSON」——錯誤訊息的顆粒度就是攻擊者的
        探測工具,而這裡沒有任何需要被區分的使用情境。
        """
        raw = bytearray()
        self._body_consumed = True
        while len(raw) < length:
            chunk = self.rfile.read(length - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        try:
            payload = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _Reject(
                HTTPStatus.BAD_REQUEST, "request body must be a JSON object"
            ) from None
        if not isinstance(payload, dict):
            raise _Reject(HTTPStatus.BAD_REQUEST, "request body must be a JSON object")
        return payload

    # ------------------------------------------------------------ 端點

    def _input_file(self, payload: dict) -> Path:
        """三個端點共用的輸入檔檢查:回一個**存在的普通檔案**的 `Path`。

        不是普通檔案的三種情況分開講,因為使用者的下一步不一樣(同
        `cli._require_file`);訊息取 `errors` 的 `MSG_*`,故 UI 與 CLI 不會各說
        一套。檢查在**問密碼之前**(同 CLI):打錯一個路徑不該讓使用者白打密碼。
        """
        target = Path(_text_field(payload, "path"))
        try:
            exists, is_dir, is_file = (
                target.exists(),
                target.is_dir(),
                target.is_file(),
            )
        except (OSError, ValueError):
            # 名字長到 `ENAMETOOLONG`、含 NUL…… 是使用錯誤,不是我們的 bug。
            raise _Reject(_status("usage"), _MSG_PATH_UNUSABLE) from None
        if not exists:
            raise _Reject(_status("missing"), MSG_INPUT_MISSING.format(path=target))
        if is_dir:
            # 目錄固定 `400`(#21 的 AC「擇一並固定」):它**存在**,`404` 會把
            # 「打錯路徑」和「選到資料夾」混成同一句話,而這兩種情況使用者的
            # 下一步完全不同。
            raise _Reject(_status("usage"), MSG_INPUT_IS_DIR.format(path=target))
        if not is_file:
            raise _Reject(_status("usage"), MSG_INPUT_NOT_REGULAR.format(path=target))
        return target

    def _api_inspect(self, payload: dict) -> None:
        """`POST /api/inspect {"path"}` → 白名單欄位(決策 7 / [M7])。

        **不問密碼、也不讀密碼**:白名單的每一項都在明文 header 裡,而需要密碼
        才拿得到的兩樣東西(原始檔名、`orig_size`)正是決策 9 要保護的中繼資料。
        body 多給一個 `passphrase` 欄不會改變任何行為——本函式連看它一眼的
        程式碼都沒有(未知的鍵一律忽略)。
        """
        target = self._input_file(payload)

        try:
            with open(target, "rb") as fh:
                size = os.fstat(fh.fileno()).st_size
                header, _ = deserialize(fh.read(HEADER_SIZE_KEM1))
        except (QVaultError, OSError) as exc:
            # 決策 8:分類與訊息都走 `errors.classify`——`QVaultError` → `422` 且
            # 訊息**逐字轉述**(一個字都不加,保證④)、`FileNotFoundError` →
            # `404`、其餘 `OSError` → `400`。
            raise _classified(exc) from None
        except ValueError:
            raise _Reject(_status("usage"), _MSG_PATH_UNUSABLE) from None

        result = {key: get(header) for key, get in _INSPECT_FIELDS}
        result["file_size"] = size
        self._json(HTTPStatus.OK, result)

    def _api_encrypt(self, payload: dict) -> None:
        """`POST /api/encrypt {"path", "passphrase", "force"=false}` → `200 {"out"}`。

        輸出路徑的規則與 CLI 逐字相同:**同目錄、同名加 `QVT_SUFFIX`**(決策 2)。
        二次確認在前端做(決策 7),伺服器只收一次——它無從判斷「打錯字」,而
        重複的密碼欄只會讓密碼在 body 裡多躺一份。

        檢查順序照 CLI(`cli._cmd_encrypt`):輸入檔 → 目標已存在(看 `force`)→
        密碼——兩種錯誤同時出現時,兩端說同一句話(#30 複審第 2 輪 N2)。`force` 一路傳到
        `encrypt_file`,故**不能**寫死 `force=True` 傳下去。「已存在」的檢查與寫入
        包在同一把**目標鎖**裡(`_target_lock`):`encrypt_file` 自己也是先查再
        `os.replace`,兩者之間沒有鎖的話,同一目標的並行請求會都回 `200`(#30 複審
        M5)。鎖只擋本程序內的並行;本程序以外的寫入者仍是 vault 層的 TOCTOU。
        """
        target = self._input_file(payload)
        force = _flag(payload, "force")
        out = target.with_name(target.name + QVT_SUFFIX)
        with _target_lock(out):
            if out.exists() and not force:
                raise _Reject(_status("exists"), MSG_REFUSE_OVERWRITE.format(path=out))
            passphrase = _passphrase(payload)
            try:
                written = encrypt_file(target, out, passphrase, force=force)
            except (QVaultError, OSError) as exc:
                # 來源**檔名**過不了 ADR-001 決策 21 的淨化(`con.txt`、`a:b.txt`……)
                # 也走這裡:`encrypt_file` 拋 `QVaultFormatError` → `422`,訊息逐字
                # 等於 CLI 對同一個檔說的那一句。
                raise _classified(exc) from None
        self._json(HTTPStatus.OK, {"out": str(written)})

    def _api_decrypt(self, payload: dict) -> None:
        """`POST /api/decrypt {"path", "out_dir", "passphrase", "force"=false}`。

        回的 `out` 是 `decrypt_file` **實際寫出**的路徑:檔名從 chunk 0 解出來、
        經 ADR-001 決策 17/21 淨化,由 `vault` 做,本層不重做也不自己從
        `<name>.qvt` 去掉後綴猜(決策 2)。

        錯密碼與竄改在這裡**完全不可區分**(ADR-001 保證③):兩者都是
        `QVaultDecryptError`、同一個 `kind`、同一句訊息、同一個 `422`。本層
        一個字都不加——「密碼可能錯誤」之類的猜測就是把 ADR 花力氣消掉的
        oracle 在最外層又裝回去。失敗時 `out_dir` 裡不會留下任何半成品
        (`decrypt_file` 的原子性,決策 16)。

        檢查順序照 CLI(`cli._cmd_decrypt`):輸入檔 → `out_dir` → 密碼 →
        `force`——兩種錯誤同時出現時,兩端說同一句話(#30 複審 L8)。寫入包在
        `out_dir` 的目標鎖裡(見 `_target_lock`)。
        """
        target = self._input_file(payload)
        raw_out_dir = _text_field(payload, "out_dir")
        if not raw_out_dir.strip():
            raise _Reject(_status("usage"), _MSG_OUT_DIR_EMPTY)
        out_dir = Path(raw_out_dir)
        try:
            is_dir = out_dir.is_dir()
        except (OSError, ValueError):
            raise _Reject(_status("usage"), _MSG_PATH_UNUSABLE) from None
        if not is_dir:
            # 決策 8 明列:`out_dir` 不存在是 `400`(使用錯誤),不是 `404`——
            # `404` 在本 API 專指**輸入檔**不存在。
            raise _Reject(_status("not_dir"), MSG_OUT_DIR_MISSING.format(path=out_dir))
        passphrase = _passphrase(payload)
        force = _flag(payload, "force")

        with _target_lock(out_dir):
            try:
                written = decrypt_file(target, out_dir, passphrase, force=force)
            except (QVaultError, OSError) as exc:
                raise _classified(exc) from None
        self._json(HTTPStatus.OK, {"out": str(written)})

    #: 路由表:`/api/*` 的**全部**端點,恰為這三條(決策 7)。
    #:
    #: 一張表而不是一串 `if route == ...`:新增端點要在這裡具名登記,而
    #: `_handle_api` 查不到就是 `404`——預設是「不存在」,不是「忘記擋」。
    #: 六道門在 `_handle_api` 裡**早於**這張表跑完,故端點函式一律可以假設
    #: 「Host / 方法 / Origin / 型別 / 大小 / token 都過了」。
    _ENDPOINTS = {
        API_INSPECT_PATH: _api_inspect,
        API_ENCRYPT_PATH: _api_encrypt,
        API_DECRYPT_PATH: _api_decrypt,
    }

    def _static(self, static: tuple[bytes, str]) -> None:
        """`/`、`/app.js`、`/app.css` + 決策 10 的五個標頭。

        CSP 在這裡逐條發給**三者**(另三個由 `end_headers` 注入):`/app.js` 自己
        也帶 CSP,是因為瀏覽器會對它套上**它自己**的那一份——直接開
        `http://127.0.0.1:<port>/app.js` 這條路徑也就一樣受管。
        """
        body, content_type = static
        self._respond(
            HTTPStatus.OK,
            body,
            content_type,
            (("Content-Security-Policy", CONTENT_SECURITY_POLICY),),
        )

    # ------------------------------------------------------------ 回應

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        self._respond(status, _dumps(payload), JSON_CONTENT_TYPE)

    def _error(self, status: HTTPStatus, message: str) -> None:
        """錯誤的唯一出口:JSON `{"error": "<一行>"}` + 關連線(決策 8)。

        `Connection: close` 這裡是**無條件**的,不等 `_respond` 去判有沒有殘留
        body:被擋下的請求我們連 `Content-Length` 都可能沒看懂(`invalid
        Content-Length` 那條),而「看不懂宣告了多少」正是最不該繼續用這條連線的
        情況。收尾(lingering close)由 `_respond` 統一做。
        """
        self._respond(
            status,
            _dumps({"error": message}),
            JSON_CONTENT_TYPE,
            (("Connection", "close"),),
        )

    def _undrained_body_bytes(self) -> int:
        """對方**宣告了**而我們還沒讀的 body 有幾個 byte(讀過或沒宣告 → `0`)。

        `_body_consumed` 為真表示 body 已經在正常流程裡讀乾淨(`_read_json`),
        那條路徑不必收尾。缺席的 / 看不懂的 `Content-Length` 回 `0`:這個函式
        只回答「要不要做 lingering close」,而那件事只有在知道確切長度時做得準;
        看不懂長度的請求一律由 `_error` 的無條件 `Connection: close` 收場。
        """
        if getattr(self, "_body_consumed", True):
            return 0
        headers = getattr(self, "headers", None)
        declared = headers.get("Content-Length") if headers else None
        try:
            return max(0, int(declared))
        except (TypeError, ValueError):
            return 0

    def _drain_request_body(self) -> None:
        """lingering close:錯誤回應**寫完之後**,把對方宣告的 body 讀掉再關。

        這不是「讀 body 來做判斷」——六道門全部在 `_respond` 之前就判完了
        (`_body_consumed` 為真表示 body 是正常流程讀的,這裡不碰)。這是 TCP
        層的收尾:socket 裡還有沒讀完的位元組時關連線,核心發的是 **RST** 而不是
        FIN,而對方收到 RST 會把**連我們剛寫好的那個回應一起丟掉**——「413 偶發
        ConnectionReset」就是這麼來的。

        上限 1 MiB / 1 秒:只陪對方送到這裡,絕不無限奉陪。超過就直接關,寧可讓
        對方吃 RST——一個宣告 1 GB body 的客戶端不值得我們讀 1 GB。
        """
        if self._body_consumed:
            return
        headers = getattr(self, "headers", None)
        declared = headers.get("Content-Length") if headers else None
        try:
            remaining = min(int(declared), DRAIN_LIMIT_BYTES)
        except (TypeError, ValueError):
            return
        try:
            self.connection.settimeout(DRAIN_TIMEOUT_SECONDS)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _respond(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """本層**唯一**的回應出口:狀態行 + 標頭 + body,然後收尾。

        ## 殘留 body 的收尾在這裡,不在呼叫端(#25 複審的擋合併項)

        原本只有 `_error` 做 lingering close,於是**成功**路徑漏了一個洞:
        `GET /` 帶一個宣告了 `Content-Length` 的 body(合法的 HTTP——GET 的 body
        沒有語意,但送得出來)會拿到 `200` + keep-alive,而那個 body **一個 byte
        都沒被讀掉**。`handle_one_request` 接著把殘留的位元組當成**下一個請求的
        請求行**來解析,於是:

        1. 同一條連線上多出一份基底類別 `send_error` 的 **HTML** `400`——而決策 8
           說這個伺服器的錯誤**只有** `{"error": …}` 一種形式,那份 HTML 也是我們
           說出口的話;
        2. `send_error` 之後在**仍有未讀資料**時關 socket,核心發的是 **RST**,
           對方連我們寫好的那個 `200` 一起丟掉 → 用戶端看到的是
           `ConnectionResetError` / `BrokenPipeError`,在負載下偶發。

        所以判斷與收尾都搬到這個唯一的出口:**宣告了而沒被讀過**的 body(見
        `_undrained_body_bytes`)→ 補 `Connection: close`、回應寫完之後
        `_drain_request_body()`。沒有殘留 body 的回應一個 byte 都不變,
        keep-alive 照舊(`tests/test_webui_crypto.py::
        test_several_requests_on_one_keep_alive_connection` 守著這一半)。

        `Connection` 由呼叫端給了就不重複加(`_error` 是無條件給的那個)。

        **已知殘留**:`Transfer-Encoding: chunked` 的請求沒有 `Content-Length`,
        所以這裡判不出長度、也框不出 chunk 邊界。標準庫的
        `BaseHTTPRequestHandler` 從頭到尾不支援 chunked 請求(`_content_length`
        看不到標頭就回 `0`),故那種請求打到 `/api/*` 會被當成空 body → `400` →
        `_error` 的無條件 close 收場;打到靜態路由則仍可能殘留。那條在本票的
        授權半徑之外(複審授權的是「宣告了非零 `Content-Length`」這一種),記在
        `.asp/pr/25.md` 的「已知殘留」。
        """
        undrained = self._undrained_body_bytes()
        if undrained and not any(
            name.lower() == "connection" for name, _ in extra_headers
        ):
            extra_headers = extra_headers + (("Connection", "close"),)

        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

        if undrained:
            self._drain_request_body()

    def end_headers(self) -> None:
        """決策 10 的三個標頭在**這裡**注入——每個回應一條不漏。

        放在 `_respond` 裡就只覆蓋我們自己發的回應;基底類別的 `send_error`
        (畸形請求行、請求行過長之類)會繞過它,而那些回應一樣是這個伺服器
        說出口的話。
        """
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    # ------------------------------------------------------------ log(決策 9)

    def log_request(self, code: object = "-", size: object = "-") -> None:
        """access log 的唯一格式:`<method> <path> <status>`。

        基底類別記的是 `self.requestline`——那是**原始請求行**,含 query 與 HTTP
        版本。query 可能帶 token,故這裡自己組:method、去掉 query 的 path、
        狀態碼,就這三樣。不記 headers、不記 body、不記 `size`。

        `code` 在 `send_error` 路徑上可能是 `HTTPStatus`;`path` 在請求行還沒
        解析成功時根本不存在(`_route` 的 `getattr` 顧到了)。
        """
        status = int(code) if isinstance(code, (int, HTTPStatus)) else code
        self.log_message("%s %s %s", self.command or "-", self._route() or "-", status)

    def log_message(self, fmt: str, *args: object) -> None:
        r"""寫一行到 stderr,**控制字元先跳脫成 `\xNN`**(#39)。

        `flush` 不能省:伺服器跑在別的執行緒,而測試要讀得到。

        跳脫是標準庫 `log_message` 本來就做的事(`message.translate(
        self._control_char_table)`),而覆寫它等於把那層拿掉:path 裡的 ESC 於是
        原封不動落到使用者的終端上。`_escaped` 把它補回來——細節與「為什麼不委派
        `super()`」見該函式。整行(格式化之後)一起過表,所以未來多一個欄位也不會
        漏掉。
        """
        sys.stderr.write(_escaped(fmt % args) + "\n")
        sys.stderr.flush()

    def log_error(self, fmt: str, *args: object) -> None:
        """整個收掉(決策 9)——一個 byte 都不寫,**故也沒有跳脫的問題**(#39)。

        基底類別用它記 `send_error` 的訊息,而那些訊息會轉述請求行
        (`Bad request version ('…')`)——請求行是攻擊者寫的,不該被我們代為
        印到使用者的終端上。狀態碼本身已經由 `log_request` 記過一次。

        這是本層對控制字元注入的**第一道**(不寫就不會被注入);第二道是
        `log_message` 的跳脫,管的是真的要記的那三個欄位。哪天有人讓這個方法開口
        說話,請讓它走 `log_message`,不要自己 `sys.stderr.write`
        (`tests/test_webui_server.py` 有一條掃描式斷言守著這件事)。
        """


class WebUIServer(ThreadingHTTPServer):
    """只綁 loopback 的 `ThreadingHTTPServer` + 一把一次性 token(決策 4、5)。

    `__init__` 的參數只有 `port`,**而且不可以有別的**:位址是模組常數
    `LOOPBACK`。決策 4 要的「不能改綁定位址」因此在型別層面成立——不是文件說
    不要改,是沒有那個參數可以傳。
    """

    #: 連線執行緒是 daemon:`shutdown()` 不會被一條 keep-alive 連線卡住。
    daemon_threads = True

    def __init__(self, port: int = 0) -> None:
        super().__init__((LOOPBACK, port), _Handler)
        #: 每次啟動一把,32 bytes 的熵(決策 5)。不寫檔、不進 cookie /
        #: `localStorage` / `sessionStorage`、不進網址的 query——只經
        #: `self.url` 的 fragment 到瀏覽器。
        self.token = secrets.token_urlsafe(32)
        #: 正在跑的 `/api/*` 請求數(#24 F1)。`_idle` 是「現在沒有在途工作」,
        #: 起始就是 set:還沒有人打進來。
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        self._idle = threading.Event()
        self._idle.set()
        #: 「不再受理新的 `/api/*` 工作」(複審 M1)。與計數共用
        #: `_inflight_lock`,故「宣布停止」與「把自己數進去」不會交錯。
        self._stopping = False
        #: 已經交給工作執行緒的連線(#47)。在這個集合裡的連線,**只有**那條
        #: 工作執行緒可以關;主執行緒(標準庫的錯誤路徑)對它的 `shutdown_request`
        #: / `close_request` 一律無作用。見 `process_request` 的 docstring。
        #: 存**物件本身**而不是 `id(request)`:存著物件就一併擋住「socket 被 GC
        #: 之後 id 被重用、無辜的新連線被判成在途」這條路。
        self._handed_off: set[object] = set()
        self._handoff_lock = threading.Lock()

    def work_started(self) -> bool:
        """一個 `/api/*` 請求開始處理(由 `_Handler` 呼叫)。

        回 `False` = **沒有**被數進去,因為已經宣布停止受理(`stop_accepting_work`);
        呼叫端此時要回 `503`,而且**不可以**呼叫 `work_finished`(沒加就不能減,
        否則計數變負、`_idle` 永遠不 set)。
        """
        with self._inflight_lock:
            if self._stopping:
                return False
            self._inflight += 1
            self._idle.clear()
            return True

    def work_finished(self) -> None:
        """那個請求處理完了(含被擋下 / 丟例外的那些:呼叫端放在 `finally`)。"""
        with self._inflight_lock:
            self._inflight -= 1
            if self._inflight == 0:
                self._idle.set()

    def stop_accepting_work(self) -> None:
        """宣布不再受理新的 `/api/*` 工作:之後進來的都拿 `503`(複審 M1)。

        `qvault ui` 的退出序列第一步。沒有這一步,`wait_until_idle` 等的那個
        集合在它等待的期間還會長大(keep-alive 的連線送進新請求),而等待
        結束**之後**才開始的那一份寫檔工作沒有任何人在等它——它會被直譯器
        結束時砍掉的 daemon 執行緒留在半路,`.qvault-*.part` 明文片段留在
        out_dir,正是 `wait_until_idle` 要防的那件事。

        **單向、不可逆**:沒有 `resume`。叫它的時候行程正在退出;提供一條
        回頭路只會多一個「退出中又活回來」的狀態要推理。

        不碰 `_idle`:已經在途的工作照常跑完、照常把它 set。
        """
        with self._inflight_lock:
            self._stopping = True

    @property
    def is_stopping(self) -> bool:
        """已經宣布停止受理新的 `/api/*` 工作了嗎(給測試與呼叫端看的事實)。"""
        with self._inflight_lock:
            return self._stopping

    def wait_until_idle(self, timeout: float) -> bool:
        """等到沒有在途的 `/api/*` 工作為止;回 `True` = 真的都做完了。

        給 `qvault ui` 的退出路徑用(#24 F1):連線執行緒是 daemon,行程結束時
        不會跑它們的 `finally`,中途被殺的解密會在 out_dir 留下 `.qvault-*.part`
        這個**明文片段**。等待是**有界**的——決策 12 要 5 秒內結束,所以超時
        就放棄(呼叫端負責說一句話),這是緩解不是保證。
        """
        return self._idle.wait(timeout)

    # ------------------------------------------------ 連線的所有權(#47)

    def process_request(self, request: object, client_address: object) -> None:
        """起工作執行緒接手這條連線——**交出去之後,關它的只有那條執行緒**。

        這個覆寫是 #47 的修正,根因在標準庫的**三處**:

        1. `socketserver.ThreadingMixIn.process_request` 以 `t.start()` 作結尾,
           而 `threading.Thread.start` 的最後一行是 `self._started.wait()`
           ——主執行緒在那裡**等**,信號正是在這種等待裡被遞送。
        2. `socketserver.BaseServer._handle_request_noblock` 把這個呼叫包在

               except Exception:  self.handle_error(...); self.shutdown_request(request)
               except:            self.shutdown_request(request); raise

           而 `cli._Stopped` 與 `KeyboardInterrupt` 都是 `BaseException`(前者
           刻意如此,見 `cli._Stopped`),走的是第二支:**主執行緒**關掉一條
           工作執行緒已經拿到手的連線。
        3. 而 `ThreadingMixIn.process_request_thread` 的
           `finally: self.shutdown_request(request)` 本來就會關它。

        也就是說同一條連線有兩個關閉者,而其中一個(主執行緒)可能在工作執行緒
        還沒寫出一個 byte 的時候就關。客戶端於是拿到 `RemoteDisconnected`:
        **連狀態碼都沒有**,而 access log 可能已經記下一個 `200`——這違反
        複審 M1 的承諾「已接收的請求要完整回應後才停」。

        修法是把關閉的**所有權**交給工作執行緒,而不是去覆寫標準庫的私有方法、
        也不是等一個逾時:進了 `_handed_off` 的連線,主執行緒關不動它(見
        `shutdown_request`),唯一的關閉者是 `process_request_thread` 的
        `finally`。所以這條保證不是「窗口變窄了」,是那個窗口裡**沒有人**有權
        關它。

        `Exception` 另計:`t.start()` 自己丟 `RuntimeError`(起不了執行緒)時
        工作執行緒**根本沒起來**,沒有人會跑那個 `finally`。這時要把延後撤掉,
        讓標準庫的 `except Exception` 路徑照原本的規矩關掉連線——否則那條
        連線的 fd 會留到行程結束(`ui` 是個跑很久的行程)。`BaseException`
        則不撤:走到那裡時 `_start_new_thread` 已經回來、執行緒已經在跑,
        那正是本修正要保護的那一刻。
        """
        with self._handoff_lock:
            self._handed_off.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            # 執行緒沒起來 → 沒有工作執行緒會關它 → 交回標準庫的錯誤路徑。
            self._reclaim(request)
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        """工作執行緒的本體;**它**才是這條連線的關閉者(#47)。

        標準庫的版本以 `finally: self.shutdown_request(request)` 作結,而那一句
        此刻還在 `_handed_off` 的保護下(無作用),所以真正的關閉由這裡的
        `finally` 做:先把連線從 `_handed_off` 拿掉(所有權交回),再走
        `TCPServer.shutdown_request` 原本那條路(`SHUT_WR` + `close`)。

        順序不能反:先關再拿掉的話,中間那一瞬間別的執行緒會以為它還不准關。
        """
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._reclaim(request)
            super().shutdown_request(request)

    def shutdown_request(self, request: object) -> None:
        """關一條連線——除非它已經交給工作執行緒了(#47)。

        無作用的那一支**不是**漏關:關它的人是
        `process_request_thread` 的 `finally`(見上)。
        """
        if self._is_handed_off(request):
            return
        super().shutdown_request(request)

    def close_request(self, request: object) -> None:
        """同 `shutdown_request`:交出去的連線不由別人關(#47)。

        今天可達的只有 `shutdown_request`(`_handle_request_noblock` 叫的是
        它);這一層是**地板**,免得標準庫未來多一條直接 `close_request` 的
        路徑又把在途連線關掉。`TCPServer.shutdown_request` 自己呼叫的
        `self.close_request` 會進到這裡,但那時連線已經不在 `_handed_off`
        裡(`_reclaim` 先跑),所以真的會關。
        """
        if self._is_handed_off(request):
            return
        super().close_request(request)

    def _is_handed_off(self, request: object) -> bool:
        with self._handoff_lock:
            return request in self._handed_off

    def _reclaim(self, request: object) -> None:
        """把連線從「已交出去」拿回來(冪等:兩條路徑都可能叫它)。"""
        with self._handoff_lock:
            self._handed_off.discard(request)

    @property
    def port(self) -> int:
        """**實際**綁到的埠。`port=0` 時由 OS 配,故不能回傳建構子收到的那個值。"""
        return self.server_address[1]

    @property
    def url(self) -> str:
        """啟動時要印出來的那一行:token 在 **fragment**(決策 5)。

        fragment 不會被瀏覽器送到伺服器,故 token 不進 access log、不進
        `Referer`;頁面載入後由 JS 讀 `location.hash` 進記憶體並
        `history.replaceState` 清掉網址列(那段在 #23)。
        """
        return f"http://{LOOPBACK}:{self.port}/#{self.token}"

    @property
    def expected_host(self) -> str:
        """`Host` 必須恰等於這個(決策 6)。`localhost:<port>` 不算。"""
        return f"{LOOPBACK}:{self.port}"

    @property
    def expected_origin(self) -> str:
        """`Origin` 若存在必須恰等於這個(決策 6)。"""
        return f"http://{LOOPBACK}:{self.port}"

    def handle_error(self, request: object, client_address: object) -> None:
        """不印 traceback(決策 9 / 鐵律 5:frame 裡有密碼與 DEK)。

        `_Handler._dispatch` 已經把每個請求包起來了,所以這裡理論上到不了;
        留著是因為「理論上到不了」在 socket 層面從來不是保證,而預設行為是
        把整個 traceback 印到 stderr。
        """


def make_server(port: int = 0) -> WebUIServer:
    """建一個已綁好 `127.0.0.1:<port>` 的伺服器(還沒開始服務)。

    `port=0` → 由 OS 配一個空埠(測試一律用這個,免得撞)。回傳值的
    `serve_forever()` / `shutdown()` 是 `socketserver` 的原物。

    **簽章只有 `port`**:沒有 `host`、`bind`、`address`(決策 4)。要改這一點
    得改 `LOOPBACK` 這個模組常數,而那是一個 code review 看得見的 diff,不是
    一個使用者打得出來的命令列參數。

    埠被占 → `OSError` 原樣往上拋;翻成一行乾淨錯誤是 `qvault ui` 的事(#24)。
    """
    return WebUIServer(port)
