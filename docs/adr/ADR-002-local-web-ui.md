# ADR-002:本機 Web UI(Python 標準庫)與其信任邊界

> 狀態:Accepted|日期:2026-11-08|範圍:qvault 的本機瀏覽器介面——HTTP 伺服器、JSON API、單頁前端、`qvault ui` 子命令、信任邊界與測試層級;加密核心(ADR-001)一字不動|住所:qvault
> roadmap-ref: now/P3

> **Accepted(2026-11-08)**:本 ADR 屬 asp-ng 鐵則的種子四類(安全)——**由人合併本 PR 即為核准**。四項設計決定(UI 形式、檔案模型、人審方式、本輪範圍)由使用者於 2026-11-08 主管層 session 中逐項裁定,記於決策 1–4。

## 背景

P0 交付了 Python 參考核心與 CLI(ADR-001),但使用者要用它得開終端機、記指令、在 `getpass` 提示下打密碼。ROADMAP P2 的 Rust/Tauri 桌面版明寫在自動迴圈外(worker 無 Rust toolchain、GUI 無法 headless 測)。本 ADR 補一條**迴圈做得到**的路:一個只在本機跑、純 Python 標準庫的瀏覽器介面,把 CLI 的三個操作搬到網頁表單上,**不碰加密核心、不加任何相依**。

## 威脅模型(在 ADR-001 之上追加的面)

新增的攻擊面只有一個:**本機上多了一個會接受 HTTP 請求的程序**。要防的是「使用者瀏覽器裡的其他網頁」把這個程序當成跳板:

| | |
|---|---|
| **防** | ① 其他網站用 CSRF 打 loopback(假造表單、`fetch` 到 `127.0.0.1:port`);② DNS rebinding(攻擊者網域解析到 127.0.0.1 後以該 Host 打進來);③ token、密碼、明文經 URL、log、暫存檔外洩;④ 伺服器被餵壞輸入後倒掉或吐 traceback(frame 裡有密碼與 DEK) |
| **不防(明列)** | 端點失陷(malware 可直接讀檔,不需經本 UI);同一台機器上**同一使用者**的其他程序(它們本來就讀得到檔案);同機其他使用者看得到啟動終端的情況(token 只印在啟動它的終端,假設終端私有);瀏覽器擴充功能讀頁面記憶體;ADR-001 已明列的各項 |
| **保證** | ① 只綁 `127.0.0.1`,沒有任何選項能改綁;② 沒有 token 的請求一律 401;③ 密碼只存在於請求 body 與處理它的 Python frame,不進 log、不進回應、不落地;④ 錯誤回應沿用 ADR-001 保證③:密碼錯與竄改**不區分** |

## 決策

1. **形式:純標準庫本機 Web UI**(使用者 2026-11-08 裁定;替代方案 Flask/FastAPI 要擴 worker 映像且是相依單向門、TUI 不是瀏覽器介面、Tauri 維持在 P2)。新模組 `qvault_core/webui.py`:`http.server.ThreadingHTTPServer` 子類 + `BaseHTTPRequestHandler`;前端為伺服器自己提供的一個 HTML、一個 JS、一個 CSS。
2. **檔案模型:路徑模式**(使用者裁定;替代方案「瀏覽器上傳內容」會讓明文經 HTTP 與瀏覽器記憶體、且大檔失去 streaming)。API 收**本機路徑**,伺服器呼叫 `vault.encrypt_file` / `vault.decrypt_file` 讀寫磁碟;回應只回寫出的路徑。路徑不限制在某個根目錄之下——本工具以啟動它的使用者權限跑在使用者自己的機器上,限制根目錄擋不住任何本模型內的攻擊者,反而讓 UI 比 CLI 弱;真正的門是第 4 條。
3. **人審:核心四檔零改動即由主管層合併**(使用者裁定)。每張票的 AC 釘 `aead.py` / `kek.py` / `container.py` / `vault.py` 對 develop 零 diff;UI 層 PR 經 reality-checker 獨立複審、CI 綠、主管層本機瀏覽器互動驗收後合併;P1(ML-KEM)**不在本輪**(使用者裁定,另立成果卡)。
4. **綁定與埠**:只綁 IPv4 loopback `127.0.0.1`;埠預設 `0`(由 OS 配)可 `--port N` 指定;**沒有** `--host` / `--bind` 之類的選項,`make_server` 的簽章也沒有這種參數——「不能改」要在型別層面成立,不是靠文件。
5. **鑑權:每次啟動一次性 token**。`secrets.token_urlsafe(32)` 於啟動時產生;瀏覽器經啟動時印出的網址 `http://127.0.0.1:<port>/#<token>` 取得——放在 **fragment**,瀏覽器不會把 fragment 送到伺服器,故它不進 access log、不進 Referer;頁面載入後立刻讀 `location.hash` 進記憶體並以 `history.replaceState` 清掉網址列的 fragment。之後每個 `/api/*` 請求帶 `Authorization: Bearer <token>`;伺服器以 `hmac.compare_digest` 比對;缺或錯 → `401`。token 不寫檔、不進 cookie / `localStorage` / `sessionStorage`。
6. **跨來源與 rebinding 防線**(逐請求、在讀 body 之前):`Host` 必須恰等於 `127.0.0.1:<port>`(擋 DNS rebinding;`localhost` 也不收,因為那會解析成誰由 OS 決定);`Origin` 若存在必須恰等於 `http://127.0.0.1:<port>`(瀏覽器對跨來源 POST 一定送 Origin;缺席代表非瀏覽器客戶端,放行);`/api/*` 只收 `POST`、`Content-Type: application/json`、body ≤ 64 KiB;違者分別 `403` / `405` / `415` / `413`。配合第 5 條,一個不知道 token 的網頁即使過得了這些也打不進來——兩道門各自獨立。
7. **API 面**(JSON in / JSON out;欄位名與 CLI 概念一對一):
   - `POST /api/inspect {"path"}` → `200 {version, kdf_id, kdf_name, aead_id, aead_name, kem_id, kem_name, kdf_log2n, kdf_r, kdf_p, chunk_size, file_size}`——白名單**逐項等於** `cli._INSPECT_FIELDS` + `file_size`,[M7] 的禁令(salt / `nonce_prefix` / `wrapped_dek` 任何形式)原樣適用;**不問密碼**。
   - `POST /api/encrypt {"path", "passphrase", "force"=false}` → `200 {"out"}`;輸出與 CLI 同為同目錄 `<name>.qvt`。
   - `POST /api/decrypt {"path", "out_dir", "passphrase", "force"=false}` → `200 {"out"}`(實際寫出路徑,檔名經 ADR-001 決策 17/21 淨化——由 `vault` 做,UI 層不重做)。
   - 密碼**只**在 JSON body 的 `passphrase` 欄;空字串 → `400`;無法 UTF-8 編碼 → `400` 且訊息不含該字元(同 CLI `_check_encodable`);encrypt 的二次確認在前端做,伺服器只收一次。
8. **錯誤回應**:一律 JSON `{"error": "<一行訊息>"}`,狀態碼 `400` 使用錯誤(壞 JSON、缺欄位、型別錯、空密碼、out_dir 不存在)、`401` token、`403` Host/Origin、`404` 輸入檔不存在、`405`、`409` 目標已存在且未 `force`、`413`、`415`、`422` `QVaultError`(密碼錯 / 竄改 / 不是 `.qvt`——訊息**逐字等於** CLI 對同一狀況的訊息,不區分)。`5xx` 只在未預期例外時出現,body 只給例外型別名,永不含 traceback。分類沿用 `cli.main` 的四類收斂,不另長一套。
9. **伺服器不記 body**:覆寫 `log_message`,access log 只記 method、path(不含 query)、狀態碼;不記 headers、不記 body;任何例外路徑不印 traceback 到 stderr。
10. **回應標頭**:所有回應帶 `Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`;頁面另帶 `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`——故前端**沒有** inline script / inline style / `on*` 屬性 / 外部資源,一個都不能有(CSP 會讓它們失效,測試也掃)。
11. **前端**:三個表單(encrypt:path、passphrase ×2、force;decrypt:path、out_dir、passphrase、force;inspect:path);密碼欄 `type="password"`、送出後清空;結果與錯誤顯示在 `aria-live` 區;所有輸入有 `<label for>`。前端沒有邏輯可測的「業務規則」——規則全在伺服器;JS 只做取 token、組請求、顯示結果。
12. **`qvault ui [--port N] [--no-browser]`**:啟動伺服器、stdout 印一行網址(含 fragment token)、預設 `webbrowser.open` 該網址、Ctrl-C / SIGTERM 乾淨退出(exit 0,不吐 traceback);埠被占 → 一行乾淨錯誤、非零 exit。**不新增任何收密碼的選項**(`tests/test_cli.py::test_no_option_anywhere_takes_a_passphrase` 繼續把關)。
13. **相依方向**:`cli → webui → {vault, container(只 `deserialize` 與常數), errors}`;`webui` 不得 import `aead` / `kek`;核心四檔不得 import `webui` / `cli`。以 `ast` 測試釘住。
14. **測試層級**(方法論 V0–V8 對應):V0/V1 CI 的 pytest;V2 fuzz 以 stdlib `random`(固定 seed)對 HTTP 層打 10,000 筆;V3 變異由主管層於本機跑並記在 PR;V5 差異測試:UI 路徑與 CLI 路徑互解、golden 向量經 API 解回;V6 gitleaks 在 gate;V8 reality-checker + 主管層本機瀏覽器驗收。**worker 不跑瀏覽器**:前端的互動正確性不是 worker 的 Done When,而是合併前的人側驗收項。
15. **不做 HTTPS**:loopback 內沒有網路路徑可竊聽;加自簽憑證只會讓瀏覽器警告與憑證管理成為新的攻擊面與支援負擔。

## 被否決的替代方案

| 方案 | 否決理由 |
|---|---|
| Flask / FastAPI + 前端框架 | 新相依是單向門,且要先擴 asp-ng worker 映像並發版;介面豐富度不是本輪目標 |
| 瀏覽器上傳 / 下載內容 | 明文經 HTTP 與瀏覽器記憶體、大檔失去 streaming、要另寫一套串流上傳 |
| token 放 query string(`?token=`,Jupyter 式) | 進 access log、進瀏覽器歷史、可能進 Referer |
| cookie session | 多了 CSRF 面與 SameSite 細節;一次性 bearer token 更小 |
| 限制路徑根目錄 | 模型內的攻擊者(其他網頁)被第 5、6 條擋在外面;根目錄限制擋不住任何新的人,只讓 UI 比 CLI 弱 |
| curses TUI | 純標準庫但互動測試困難,且不是使用者要的瀏覽器介面 |

## 後果

- 使用者多一條 `qvault ui` 路徑;CLI 與函式庫介面不變。
- 多一個模組與一批 HTTP 層測試;pyproject 相依**不變**。
- 前端互動正確性有一段是人側驗收——這是 worker 能力上限,記在 ROADMAP P3 的能力上限列。
