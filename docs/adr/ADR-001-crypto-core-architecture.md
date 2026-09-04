# ADR-001:QVault 加密核心架構(Python 參考實作)

> 狀態:Draft|日期:2026-09-04|範圍:QVault Python 加密核心——`.qvt` 格式、AES-256-GCM 信封、KEK 抽象、錯誤體系、威脅模型;Rust/Tauri 產品(P2)另議|住所:qvault
> roadmap-ref: now/P0

> **Draft**:本 ADR 定案(升 Accepted)前,dev worker 不得寫 production code。待人審補齊「未決/待審」節後定案。

## 背景

QVault 保護檔案抵抗 **Harvest-Now-Decrypt-Later**(HNDL)與靜態竊取。本 repo 由 asp-ng 自主開發迴圈施工,先做 **Python 參考核心**(沙箱只跑得動 Python;Rust/Tauri/後量子見 ROADMAP P1/P2)。密碼工具的架構必須**先定案再實作**——本 ADR 補上 ROADMAP 只列交付、未定設計的缺口。

## 範圍與非目標

- **P0 範圍**:`.qvt` 容器格式、AES-256-GCM 信封、scrypt-KEK、檔案加解密、CLI(`encrypt`/`decrypt`/`inspect`)。
- **P0 非目標**:後量子(P1)、GUI(P2)、金鑰管理/KMS、多人共享、雲端同步、金鑰輪換、密碼記憶/keyring。
- **永不做**:自刻密碼原語(AES/GCM/Kyber/scrypt 一律走受審庫)。

## 支援平台

- **P0 核心**:純 Python 3.12+,**OS 無關**——凡跑得動 Python 皆可(Linux/macOS/Windows),無任何平台專屬碼、無編譯步驟。
- **桌面(P2,迴圈外)**:Tauri → Windows/macOS/Linux;由人在核心上蓋,不在本 ADR。

## 威脅模型

| | |
|---|---|
| **防** | 靜態竊取(`.qvt` 被整檔拷走)、竄改(AEAD tag 偵測)、HNDL(P1 後量子層後) |
| **不防(明列)** | 端點失陷(malware 讀明文 / keylogger)、記憶體取證(DEK/KEK 在 RAM)、側通道(用受審庫緩解,**不宣稱**抗)、rubber-hose、使用者選弱密碼(給 KDF 但不強制強度) |
| **保證** | ①竄改/錯金鑰 → 一律 raise,**絕不回錯資料** ②金鑰不落地、不進 log、不進例外訊息 ③decrypt 對「竄改」與「錯密碼」不於訊息區分(避免 oracle) |

## 密碼架構

**信封加密**(envelope):
1. 隨機 256-bit **DEK**(`secrets.token_bytes(32)`)以 **AES-256-GCM** 加密檔案資料。
2. DEK 由 **KEK** 包裝(wrap),wrapped DEK 存進 `.qvt`。
3. 換 KEK / 加後量子時**不必重加密整檔**——只換 DEK 的包裝。

**KEK 可插拔**——`KeyEncapsulation` ABC 是 PQC 的插槽:
```python
class KeyEncapsulation(ABC):
    kem_id: int                              # 記進 header,向前相容
    def wrap(self, dek: bytes) -> bytes: ...   # → wrapped_dek
    def unwrap(self, wrapped: bytes) -> bytes: ...  # → dek;失敗 raise QVaultDecryptError
```
- **P0**:`ScryptKEK`——passphrase 經 `scrypt` 派生 KEK,以 AES-256-GCM 包/解 DEK。
- **P1**:`MLKEMKek`(ML-KEM-1024)、`HybridKEK`(scrypt ⊕ ML-KEM 雙封裝,任一層被破 DEK 仍安全)——**信封層零改動**即證 KEK 抽象成立。

## 模組切法(相依方向:cli → vault → {container, aead, kek};無環)

| 模組 | 職責 |
|---|---|
| `qvault_core/container.py` | `.qvt` 格式 serialize/deserialize(純 `struct`,不碰加密) |
| `qvault_core/aead.py` | AES-256-GCM 包裝(`cryptography`) |
| `qvault_core/kek.py` | `KeyEncapsulation` ABC + `ScryptKEK` |
| `qvault_core/vault.py` | 檔案加解密編排(讀檔→DEK→aead→wrap→container→寫 `.qvt`;反向) |
| `qvault_core/cli.py` | `encrypt`/`decrypt`/`inspect`(argparse) |

## 錯誤體系

- `QVaultError`(基)
  - `QVaultFormatError`:magic 錯、version 未知、欄位長度不符、截斷。
  - `QVaultDecryptError`:AEAD tag 驗證失敗(**竄改或錯金鑰,不於訊息區分**)。
  - `QVaultVersionError`:未知 `.qvt` version。
- **鐵律**:例外訊息**永不**含金鑰/密碼/明文。

## `.qvt` 格式

```
magic(4B "QVLT") | version(1B) | kdf_id(1B) | aead_id(1B) | kem_id(1B)
| salt(16B) | nonce(12B) | wrapped_dek_len(2B, big-endian) | wrapped_dek(變長)
| ciphertext(變長) | tag(16B)
```
- version 變更 +1 且**保留舊版讀取**(向後相容)。
- 演算法以 id 記(kdf_id/aead_id/kem_id),不寫死。

## 決策

1. **信封(DEK+KEK)而非 passphrase 直接加密檔案**——換 KEK/加 PQC 不必重加密整檔。
2. **KEK 抽象 ABC = PQC 插槽**——P1 零改信封層。
3. **只用 `cryptography`**(已在 asp-ng worker 映像);P1 的 PQC 庫需先烘映像(ROADMAP P1 能力上限)。
4. **tamper/錯金鑰一律 raise**,不回部分資料;不做 padding oracle。

## 未決/待審(請你補齊,定案前不實作)

1. **大檔分塊 + nonce**:AES-GCM nonce 12B、單金鑰有 ~64GB 上限,分塊時**每塊 nonce 不可重用**(重用=災難性)。我傾向 **STREAM 式構造**(base_nonce ‖ 32-bit chunk counter ‖ last-chunk flag)。**這條最危險,務必定案再寫。**
2. **header 綁進 AEAD 的 AAD**:把 header 當 AES-GCM 的 AAD,防有人重組/竄改 header 欄位。我傾向**要**。
3. **scrypt 參數**:n/r/p 具體值(我傾向 n=2¹⁵,r=8,p=1)與未來可調(參數記進 header?)。
4. **密碼強度政策**:要不要最低要求 / zxcvbn 類提示(P0 是否納入)。
5. **檔名/中繼資料**:原檔名是否加密進 `.qvt`(洩不洩檔名)。
