# QVault ROADMAP(文件鏈鏈頭)

> 本檔是階段的唯一事實源。`now` 帶的 `- [ ]` 交付項由 asp-ng 自動轉成 issue
> (Path 2,ADR-000:480):寫一行 → 開一張 issue → 人補 AC 進 body → dev → QA → merge。
> `- [x]` / HTML 註解掉的不轉。變更 = 對本檔的 PR。

## now — P0 核心信封(Python 參考實作)
P0:.qvt 容器格式、AES-256-GCM 信封、scrypt KEK、檔案層、CLI。**設計見 `docs/adr/ADR-001`(Draft;定案前不實作)**。
判準:round-trip / tamper / 邊界 KAT 全綠;只用 cryptography(不手刻);KEK 抽象(KeyEncapsulation ABC)留 PQC 插槽;錯誤體系(QVaultError 家族);inspect 不洩金鑰;威脅模型與 `.qvt` 格式依 ADR-001。
非目標:後量子(P1)、GUI(P2)、金鑰管理/KMS、多人共享、雲端同步、金鑰輪換;永不自刻密碼原語。
支援平台:純 Python 3.12+,OS 無關(Linux/macOS/Windows;無平台專屬碼)。
能力上限:全在 worker 映像的 cryptography(AES-256-GCM/scrypt)能力內;後量子需先擴 asp-ng 映像(見 P1)。

- [x] `.qvt` 容器格式:AGENTS.md 定義的欄位序列化與反序列化,格式壞即 raise QVaultFormatError(純 struct,含各欄位邊界測試)
- [x] AES-256-GCM 信封核心:DEK 以 secrets.token_bytes(32) 生成,encrypt(plaintext, aad) 回 (nonce, ct, tag)、decrypt 竄改即 raise(含已知答案測試向量 KAT)
- [x] scrypt KEK:passphrase 經 scrypt(n=2**15,r=8,p=1) 派生 KEK,以 AES-GCM 包/解 DEK;定義 KeyEncapsulation 抽象介面供 P1 換 ML-KEM
- [x] 檔案層:encrypt file→file.qvt、decrypt 還原原檔;大檔以固定塊 streaming,不整檔載入記憶體
- [x] CLI:qvault encrypt/decrypt/inspect(argparse);inspect 只印 header 與演算法,錯密碼給乾淨錯誤不吐 traceback

## next — P1 後量子層(ML-KEM-1024)
P1:烘受審 PQC 庫進 asp-ng worker 映像後,新增 ML-KEM-1024 的 KeyEncapsulation 實作;混合模式(scrypt-KEK 與 ML-KEM-KEK 雙重封裝 DEK)。
判準:NIST FIPS 203 KAT 對得上;混合模式任一層被破 DEK 仍安全;信封層零改動(KEK 介面就位之證)。
能力上限:需先擴 asp-ng 沙箱(worker 映像烘 PQC 庫並 pin)——在此之前 loop 建不了,故為觸發式。

## later — P2 產品化(loop 外)
P2:Rust/Tauri 桌面 GUI、拖放批次、跨平台打包(AppImage/dmg/msi)、AES-NI 硬體加速。
判準:GUI 呼叫 qvault-core 的穩定 API;.qvt 跨 Python/Rust 實作相容(共用 KAT)。
能力上限:worker 無 Rust toolchain、GUI 無法 headless 測試——迴圈外,由人施工或另立 repo。
