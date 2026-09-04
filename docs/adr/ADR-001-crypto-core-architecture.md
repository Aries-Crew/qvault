# ADR-001:QVault 加密核心架構(Python 參考實作)

> 狀態:Accepted|日期:2026-09-04|範圍:QVault Python 加密核心——`.qvt` 格式、AES-256-GCM 信封、KEK 抽象、錯誤體系、威脅模型;Rust/Tauri 產品(P2)另議|住所:qvault
> roadmap-ref: now/P0

> **Accepted**(2026-09-04,人審採納全部傾向):五項原未決已定案,見「決策」節。dev worker 依本 ADR 施工。

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

## `.qvt` 格式(v1,STREAM 式分塊 AEAD)

**Header(明文;整段作為每個 chunk 的 AES-GCM AAD)**
```
magic          4B   b"QVLT"
version        1B   = 1
kdf_id         1B   1 = scrypt
aead_id        1B   1 = AES-256-GCM
kem_id         1B   1 = scrypt-KEK(P0);2 = ML-KEM(P1);3 = hybrid(P1)
kdf_log2n      1B   scrypt N = 2^此值(P0 = 15)
kdf_r          1B   scrypt r(P0 = 8)
kdf_p          1B   scrypt p(P0 = 1)
salt           16B  KDF salt
nonce_prefix   7B   STREAM nonce 前綴(每檔隨機)
chunk_size     4B   BE;明文分塊大小(P0 = 65536)
wrapped_dek_len 2B  BE
wrapped_dek    var
```

**加密體(STREAM;chunk i 的 12B nonce = `nonce_prefix(7B) ‖ uint32_BE(i) ‖ flag(1B)`)**
- `flag`:最後一個 chunk = `0x01`,其餘 = `0x00`(防截斷——少了尾 chunk,flag 不符即解密失敗)。
- 每個 chunk 的 **AAD = 上面整段 header**(綁死 header,任一欄位被改則解密失敗)。
- **chunk 0 = 加密的中繼資料**(原檔名 + 原大小,length-prefixed)——檔名不洩。
- chunk 1..n = 檔案資料,每塊 `chunk_size` 明文(末塊可短)。
- 每個 chunk 落盤 = `ciphertext ‖ tag(16B)`。

**不變式**:①`nonce_prefix` 每檔隨機 → `(prefix ‖ counter)` 全域唯一,**永不重用 nonce** ②末塊 flag=1 → 防截斷 ③header 作 AAD → 防欄位重組 ④version +1 且保留舊版讀取(向後相容)。

## 決策

1. **信封(DEK+KEK)而非 passphrase 直接加密檔案**——換 KEK/加 PQC 不必重加密整檔。
2. **KEK 抽象 ABC = PQC 插槽**——P1 零改信封層。
3. **只用 `cryptography`**(已在 asp-ng worker 映像);P1 的 PQC 庫需先烘映像(ROADMAP P1 能力上限)。
4. **tamper/錯金鑰一律 raise**,不回部分資料;不做 padding oracle。

## 決策(續)——原五項未決,人審 2026-09-04 採納全部傾向

5. **大檔分塊 nonce = STREAM 構造**(`nonce_prefix ‖ uint32_BE counter ‖ last-flag`,見 `.qvt` 格式)——nonce **永不重用**、末塊 flag 防截斷。**最關鍵的一條**;實作務必以 KAT + 跨塊竄改/截斷測試釘死。
6. **header 綁進每個 chunk 的 AEAD AAD**——防 header 欄位重組/竄改。
7. **scrypt n=2¹⁵, r=8, p=1**,且**記進 header**(kdf_log2n/kdf_r/kdf_p)供未來可調,不必換 kdf_id。
8. **P0 不強制密碼強度**——只提供 KDF,強度政策為非目標(後續議)。
9. **原檔名加密進 `.qvt`**(chunk 0 的加密中繼資料)——不洩檔名。
