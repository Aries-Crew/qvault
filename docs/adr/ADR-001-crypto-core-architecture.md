# ADR-001:QVault 加密核心架構(Python 參考實作)

> 狀態:Accepted|日期:2026-09-04|範圍:QVault Python 加密核心——`.qvt` 格式、AES-256-GCM 信封、KEK 抽象、錯誤體系、威脅模型;Rust/Tauri 產品(P2)另議|住所:qvault
> roadmap-ref: now/P0

> **Accepted**(2026-09-04):五項原未決經人審定案(決策 5–9);其後一輪**獨立密碼安全複審**判定當時的 ADR+AC 為 `not-ready`,補上決策 10–20 與 `.qvt` 格式的五處空白(salt 來源、`wrapped_dek` 佈局、chunk 0 佈局、空檔佈局、AAD 位元組界)。**決策 10–20 是 ADR 自己的洞,不是 AC 轉錄失誤**——只補 AC 會讓兩份文件再度漂移,故回寫於此。dev worker 依本 ADR 施工。

## 背景

QVault 保護檔案抵抗 **Harvest-Now-Decrypt-Later**(HNDL)與靜態竊取。本 repo 由 asp-ng 自主開發迴圈施工,先做 **Python 參考核心**(沙箱只跑得動 Python;Rust/Tauri/後量子見 ROADMAP P1/P2)。密碼工具的架構必須**先定案再實作**——本 ADR 補上 ROADMAP 只列交付、未定設計的缺口。

## 範圍與非目標

- **P0 範圍**:`.qvt` 容器格式、AES-256-GCM 信封、scrypt-KEK、檔案加解密、CLI(`encrypt`/`decrypt`/`inspect`)。
- **P0 非目標**:後量子(P1)、GUI(P2)、金鑰管理/KMS、多人共享、雲端同步、金鑰輪換、密碼記憶/keyring。
- **永不做**:自刻密碼原語(AES/GCM/Kyber/scrypt 一律走受審庫)。

## 支援平台

- **P0 核心**:純 Python 3.12+,凡跑得動 Python 皆可(**Linux / macOS / Windows**),無平台專屬碼、無編譯步驟。
- **Windows 的兩處實際差異(誠實記,勿讓宣稱大於實作)**:
  ①**檔案權限**:`0o600` 是 POSIX 語意,Windows 上 `os.chmod` 近乎 no-op——`.qvt`、
  還原明文、暫存檔在 Windows 會拿到預設 ACL。「保護還原後的明文」這條在 Windows
  **明顯較弱**,列為已知上限(stdlib 無可攜的 ACL 收窄手段;要補需 pywin32 之類的
  平台相依,牴觸「無平台專屬碼」)。
  ②**檔名危險面不同**:Windows 另有保留裝置名、磁碟機相對路徑、交替資料流、尾部
  點/空白四類 POSIX 沒有的招——見決策 21。
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

**Header(明文;`serialize()` 的完整輸出即 AAD)**
```
magic           4B   b"QVLT"
version         1B   = 1
kdf_id          1B   1 = scrypt
aead_id         1B   1 = AES-256-GCM
kem_id          1B   1 = scrypt-KEK(P0);2 = ML-KEM(P1);3 = hybrid(P1)
kdf_log2n       1B   scrypt N = 2^此值(P0 = 15)
kdf_r           1B   scrypt r(P0 = 8)
kdf_p           1B   scrypt p(P0 = 1)
salt            16B  KDF salt——**每檔重新隨機**(決策 10)
nonce_prefix    7B   STREAM nonce 前綴(每檔隨機)
chunk_size      4B   BE;明文分塊大小(P0 = 65536)
wrapped_dek_len 2B   BE(kem_id=1 時恆為 60)
wrapped_dek     var  **60B 定長**:wrap_nonce(12B) ‖ ct(32B) ‖ tag(16B)(決策 11)
```
kem_id=1 時 header 長度恆為 100B(定長 40B + wrapped_dek 60B)。

**AAD 的位元組界(決策 12)**:AAD == `serialize()` 的**完整輸出**,即 `.qvt` 的
`offset 0 .. body_offset`(**含 `wrapped_dek`**);`deserialize` 回傳的 `body_offset`
即 AAD 長度。此處歧義會讓兩個實作互不相容,而各自的 round-trip 與竄改測試都會通過。

**加密體(STREAM;chunk i 的 12B nonce = `nonce_prefix(7B) ‖ uint32_BE(i) ‖ flag(1B)`)**
- `flag`:最後一個 chunk = `0x01`,其餘 = `0x00`。
- 每個 chunk 的 AAD = 上述 header 全段。
- **chunk 0 = 加密的中繼資料**,明文佈局(決策 13):
  `name_len(2B BE) ‖ name_utf8(name_len B) ‖ orig_size(8B BE)`,總長 ≤ 4096B。
- chunk 1..n = 檔案資料,每塊 `chunk_size` 明文(末塊可短)。
- 每塊落盤 = `ciphertext ‖ tag(16B)`。
- **空檔(orig_size = 0)正規佈局(決策 14)**:body **只有 chunk 0**,且其 flag =
  `0x01`(chunk 0 可同時是末塊);**禁止**補一個零長度資料塊。

**不變式**:①`nonce_prefix` 每檔隨機 → `(prefix ‖ counter)` 全域唯一,**永不重用**
②末塊 flag=1 → 防截斷 ③header 作 AAD → 防欄位重組 ④version +1 且保留舊版讀取。

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

## 決策(續二)——獨立安全複審補洞(2026-09-04)

把 AC 交給自主實作者之前做了一輪**獨立密碼安全複審**,判定 **not-ready**。判定理由值得逐字記下:

> 這份 AC 有**兩條完全合理的實作路徑會產生 AES-GCM nonce 重用 / 全域固定 KEK,而五張 issue 的每一條驗收都會通過**。

也就是說,實作者**不必犯錯、只要做出合理選擇**就會蓋出被完全攻破的東西。以下把當時的空白補成決策——複審明確指出這幾項**是 ADR 自己的洞,不是 AC 的轉錄失誤**,故回寫於此;只補 AC 會讓兩份文件再度漂移。

10. **salt 每檔重新隨機**:`salt = secrets.token_bytes(16)`。**禁止**常數、禁止由密碼/檔名/路徑/時間/任何雜湊派生。常數 salt = 全世界所有檔案共用同一把 KEK,一張 scrypt 彩虹表通吃,離線爆破成本由 O(檔案數) 降為 **O(1)**——而當時 AC 沒有任何一條會因此失敗。
11. **`wrapped_dek` = `wrap_nonce(12B) ‖ ct(32B) ‖ tag(16B)`(60B 定長)**,`wrap_nonce` **每次 wrap 重新隨機**;wrap 的 **AAD = 常數 `b"QVLT-dek-v1"`**(domain separation;**不可**用 header——header 本身含 `wrapped_dek`,循環)。固定/零 wrap_nonce 一旦配上決策 10 未落實,即 GCM nonce 重用 → 洩 DEK 差值、可解出 GHASH 子鑰 H → **偽造任意 wrapped DEK**。
12. **AAD 位元組界** = `serialize()` 全段(含 `wrapped_dek`),即 `raw[:body_offset]`。
13. **chunk 0 明文佈局** = `name_len(2B BE) ‖ name_utf8 ‖ orig_size(8B BE)`,≤ 4096B。
14. **空檔正規佈局**:body 僅 chunk 0 且其 flag = `0x01`;禁止補零長度資料塊。
15. **header 界限檢查先於任何緩衝區配置與 KDF 呼叫**:`kdf_log2n ∈ [14,22]`、`kdf_r ∈ [1,32]`、`kdf_p ∈ [1,16]`、`chunk_size ∈ [4096, 1048576]` 且為 2 的冪、三個 id 皆 == 1、`wrapped_dek_len == 60`;任一不符 → `QVaultFormatError`。**header 全部欄位都是攻擊者可控,而它們在 tag 被驗證之前就要被使用**(KDF 參數、緩衝區大小):一個 60 byte 的畸形檔設 `kdf_log2n=63` 就是 `Scrypt(n=2**63)` → OOM,且丟出的不是三種 QVaultError。
16. **解密具原子性**:寫入同目錄暫存檔(0600),**全部** chunk 驗證通過且末塊 flag==`0x01` 之後才 `os.replace()`;任一步失敗即 unlink 暫存檔再 raise。否則串流解密會在 raise 之前把前 k 塊明文留在磁碟上——違反保證①,並成為**可控的部分解密原語**(截斷到任意 chunk 邊界,受害者拿到前綴明文且毫無提示)。
17. **chunk 0 的檔名是不可信輸入**:經 `os.path.basename()` 後檢查非空、非 `.`/`..`、不含 `/`、`\`、NUL、UTF-8 strict 可解、≤255B;寫出路徑須 realpath 後仍在 `realpath(out_dir)` 之下;目標已存在預設拒絕(`--force` 才覆寫)。**「經過認證」不等於「可信」——簽發者就是攻擊者**(Zip Slip:別人寄來的 `.qvt` 內嵌 `../../../.ssh/authorized_keys`)。
18. **密碼正規化**:passphrase 一律 `unicodedata.normalize("NFC", pw)` 再 UTF-8 編碼。否則 macOS 的 NFD 輸入與 Windows/Linux 的 NFC 派生出不同 KEK,同一個密碼跨平台打不開檔案——直接牴觸「OS 無關」。
19. **金鑰不得可印**:`ScryptKEK.__repr__` 固定為 `<ScryptKEK kem_id=1>`(預設 dataclass repr 會把 passphrase 印出來,而 `logging.exception`、pytest locals 展開都會吐);包裝 `InvalidTag` 一律 `raise ... from None`。保證②在此之前**不可證偽**。
20. **隨機來源限 `secrets`**(`qvault_core/` 內禁止 `import random`);`.qvt`、還原明文、暫存檔建立時皆 `0o600`;`inspect` 輸出走**白名單**(僅 version/三個 id/kdf 參數/chunk_size/檔案位元組數),**不得**輸出 salt、nonce_prefix、wrapped_dek——把 wrapped DEK 印進終端或工單,等於讓攻擊者不需檔案就能離線爆密碼。

## 決策(續三)——Windows 硬化(2026-09-04 人審提問查出)

人審問「支援哪些 OS」時查出:ADR 宣稱含 Windows,但決策 17 的檔名淨化**只擋得住
POSIX 的招**。以下四類在原檢查(排除空字串、`.`/`..`、`/`、`\`、NUL)下**全部會通過**,
而它們在 Windows 上都能逃出 `out_dir`——**宣稱支援卻沒守住,對加密工具是最糟的組合**。

21. **檔名淨化須含 Windows 專屬四類**(在決策 17 之上追加,三平台一律套用——
    淨化規則不因執行平台而異,否則在 Linux 產生的惡意檔拿到 Windows 才發作):
    - **不得含 `:`**——一條規則同時擋掉磁碟機相對路徑(`C:evil.txt`,在 Windows 會
      寫到 C: 的目前目錄而非 `out_dir`)與交替資料流(`x.txt:hidden`,內容藏進別的流)。
    - **去副檔名後的主檔名(大小寫不分)不得為保留裝置名**:`CON`、`PRN`、`AUX`、
      `NUL`、`COM1`–`COM9`、`LPT1`–`LPT9`(寫入這些名字在 Windows 行為詭異、可能掛住)。
    - **不得以 `.` 或空白結尾**(Windows 會靜默去尾 → 可造成撞名覆寫)。
    - **不得含控制字元**(`\x00`–`\x1f`)。
    違反任一 → `QVaultFormatError`,**不得**嘗試「修正」成合法名(修正等於替攻擊者
    挑一個能寫的位置)。
