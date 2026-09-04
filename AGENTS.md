# AGENTS.md — QVault 開發規約(asp-ng 消費端)

本 repo 由 **asp-ng** 自主開發迴圈施工(ROADMAP `- [ ]` → issue → dev worker → QA → merge)。
本檔是 worker 的憲法;違反下列鐵律的 PR 應被 QA 擋下。

## 專案定位

QVault = 後量子就緒的本地檔案保險庫。**本 repo 只做 Python 參考核心**:`.qvt` 格式 +
AES-256-GCM 信封 + 可插拔 KEK 層。Rust/Tauri GUI 與打包**不在**自動迴圈範圍(見 ROADMAP P2)。

## 🔴 鐵律(不可違反)

1. **只用受審密碼庫,永不手刻密碼原語。** AES-256-GCM / scrypt / HKDF 一律走 `cryptography`
   套件;ML-KEM 走真正的 PQC 庫(P1 屆時指定)。**禁止**自行實作 Kyber、AES、GCM、任何
   有限體/格運算。手刻密碼是危險的,QA 對任何自刻原語一律 reject。
2. **相依 ⊆ asp-ng worker 映像已烘進者。** 目前可用:`cryptography`、`pyyaml`、Python 3.12
   stdlib、`pytest`。**worker 沙箱無 pypi/crates egress,執行期裝不了新套件。** 需要新相依
   (例:P1 的 PQC 庫)必須**先擴 asp-ng 的 `docker/worker.Dockerfile` + pyproject**,再在此
   新增——否則 worker 建置即失敗。新增相依的 PR 要在 body 註明「已確認在 worker 映像內」。
3. **KEK 層是可插拔介面。** DEK(資料金鑰)由一個 KEK 抽象包裝;P0 用 scrypt-KEK,P1 換
   ML-KEM-KEK **信封層一行不動**。任何把 KEK 邏輯寫死進信封層的 PR 應被擋。
4. **每張交付含三類測試**:round-trip(加密→解密還原)、**tamper**(改一 byte 密文/tag/header
   → 解密必 raise,不得靜默回錯資料)、邊界(空檔、大檔、格式壞、錯密碼)。無 tamper 測試
   的密碼碼視同未完成。
5. **不落地明文金鑰**:DEK/KEK 不寫檔、不進 log、不入例外訊息。`inspect` 只印 header/演算法,
   永不印任何金鑰或明文。

## 測試與 CI

- `python3 -m pytest -q` 必須全綠(CI 的 `tests` job)。
- 密碼碼優先寫**已知答案測試向量**(KAT):同一輸入+金鑰+nonce → 固定輸出,跨實作可對。
- 覆蓋 tamper 的每一個欄位(magic/version/algo-id/salt/nonce/ct/tag 各改一 byte)。

## `.qvt` 容器格式

**格式的唯一事實源 = `docs/adr/ADR-001`**(v1:STREAM 式分塊 AEAD;header 作 AAD;nonce 前綴+計數器永不重用;檔名加密進 chunk 0)。**勿在他處另複製格式**(消滅第二份帳);格式變更 = 改 ADR-001 且 version +1、保留舊版讀取。
## 迴圈慣例(asp-ng 消費端)

- 方向走 `docs/ROADMAP.md`(now 帶 `- [ ]` 自動轉 issue);工作走 issue。
- issue 的驗收準則(AC)由人補進 body 後才動工(§525);worker 依 AC 施工,不自行擴張範圍。
- 嚴格有序的交付以 `depends-on: #N`(行首)宣告,前置票**未關閉**即 `blocked` 不派工。
- **PR 描述必須含行首 `Closes #<票號>`**,以及 AC 逐條對照(做不到的逐條說明)。
  這不是格式潔癖:runtime 的關票動作取的是 PR body 的 `Closes` 行,漏寫則該票
  **永不關閉**,於是所有 `depends-on` 它的票永遠停在 `blocked`——一張漏寫就鎖死
  整條 P0 鏈(#1→#2→#3→#4→#5),而且沒有任何錯誤訊息。
  GitHub 原生的 `Closes` 只在併入預設分支(`main`)時生效,而 worker PR 併的是
  `develop`——實際關票由 runtime 在**促升至 main** 時執行,故這行是寫給 runtime 讀的。
- 破壞性動作、憑證輸出一律禁止(繼承 asp-ng 四鐵則)。
