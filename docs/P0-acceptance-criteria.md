# QVault P0 issue 驗收準則(依 ADR-001;經獨立密碼安全複審補強)

> 第一版經**獨立密碼安全複審**判定 `not-ready`——當時「有兩條完全合理的實作路徑會產生
> AES-GCM nonce 重用 / 全域固定 KEK,而每一條驗收都會通過」。本版補入 C1–C4、H1–H5 與
> M/L 各項;對應的設計空白已回寫 ADR-001 決策 10–20。
>
> 全部繼承 AGENTS.md 鐵則:**只用受審庫、永不手刻密碼原語、相依 ⊆ worker 映像、金鑰不落地**。

---

## #1 `.qvt` 容器格式

- [ ] `qvault_core/container.py`:`QVaultHeader`(magic/version/kdf_id/aead_id/kem_id/kdf_log2n/kdf_r/kdf_p/salt/nonce_prefix/chunk_size/wrapped_dek)+ `serialize()->bytes`、`deserialize(bytes)->(QVaultHeader, body_offset)`,位元佈局**逐欄依 ADR-001**,多位元組整數一律 big-endian。
- [ ] `qvault_core/errors.py`:`QVaultError` → `QVaultFormatError` / `QVaultVersionError` / `QVaultDecryptError`。
- [ ] magic≠`b"QVLT"`→`QVaultFormatError`;version 未知→`QVaultVersionError`;定長欄位長度不符 / 輸入截斷 → `QVaultFormatError`(**不得外洩** `struct.error`/`IndexError`)。
- **[H1] 界限檢查必須先於任何緩衝區配置與 KDF 呼叫**:
  - [ ] `deserialize` 在配置任何以 header 值決定大小的緩衝區、且在呼叫 `Scrypt` **之前**完成:`kdf_log2n ∈ [14,22]`、`kdf_r ∈ [1,32]`、`kdf_p ∈ [1,16]`、`chunk_size ∈ [4096,1048576]` 且為 2 的冪、`kdf_id/aead_id/kem_id` 皆 == 1、`wrapped_dek_len == 60`;任一不符 → `QVaultFormatError`(**不得靜默忽略未知 id**)。
  - [ ] 測試:`kdf_log2n=63` 的 header → 立刻 `QVaultFormatError`,並以 monkeypatch 斷言 **`Scrypt` 從未被呼叫**;`chunk_size=0xFFFFFFFF` → `QVaultFormatError`。
  - [ ] **fuzz**:random 產生 10,000 筆長度 0–512 的隨機/半合法位元組餵 `deserialize`,**只允許** `QVaultFormatError`/`QVaultVersionError`;出現任何其他例外(`struct.error`、`MemoryError`、`OverflowError`、`UnicodeDecodeError`)或掛住即失敗。
- **[H5] AAD 位元組界**:
  - [ ] AAD == `serialize()` 完整輸出,即 `.qvt` 的 `offset 0 .. body_offset`(**含 `wrapped_dek`**);`deserialize` 回傳的 `body_offset` 即 AAD 長度。
  - [ ] 測試:固定夾具斷言 `aad == raw[:body_offset]` 且 `len(aad) == 40 + 60`。
- **[H3] 空檔正規佈局**:
  - [ ] 原大小 0 時 body **只有 chunk 0**,且 chunk 0 的 nonce flag == `0x01`;**禁止**補零長度資料塊。
- **[M1] `nonce_for` 的 KAT 必須用字面值,不得由實作輸出反推**(否則欄位錯序也會「KAT 通過」):
  - [ ] `nonce_for(prefix, index, is_last)->12B` = `prefix(7B) ‖ uint32_BE(index) ‖ flag(1B)`;`index >= 2**32` → raise;回傳長度恆 12。
  - [ ] `nonce_for(bytes(range(7)), 0, False) == bytes.fromhex("000102030405060000000000")`
  - [ ] `nonce_for(bytes(range(7)), 1, True)  == bytes.fromhex("000102030405060000000101")`
  - [ ] `nonce_for(b"\xaa"*7, 258, False)     == bytes.fromhex("aaaaaaaaaaaaaa0000010200")`
- [ ] 測試:round-trip 結構相等;每欄位各改/截一次都 raise。
- [ ] 只用 stdlib(`struct`/`dataclasses`);**不碰加密**(那是 #2)。

---

## #2 AES-256-GCM 信封核心

- [ ] `qvault_core/aead.py`:以 `cryptography` 的 `AESGCM` 封裝——`seal(key32, nonce12, pt, aad) -> ct‖tag`、`unseal(key32, nonce12, ct‖tag, aad) -> pt`。**[L] 命名用 `seal`/`unseal`,不得用 `open`**(會遮蔽內建 `open`)。
- [ ] `gen_dek()` = `secrets.token_bytes(32)`。
- [ ] `unseal` 對 ct/tag/nonce/aad/key 任一不符 → `QVaultDecryptError`(包住 `InvalidTag`,**`raise ... from None`**,不外洩原例外、不洩金鑰)。
- [ ] **只用 cryptography,不手刻 AES/GCM**。
- [ ] **[L]** `qvault_core/` 內**禁止 `import random`**(以 AST 或 grep 斷言),所有隨機值限 `secrets`。
- [ ] 測試:round-trip;**≥1 組 NIST AES-256-GCM 官方 KAT**(固定 key/nonce/aad/pt → 固定 ct/tag);ct/tag/aad 各改一 byte → raise;錯 key → raise。

---

## #3 scrypt KEK

- [ ] `qvault_core/kek.py`:`KeyEncapsulation` ABC(`kem_id`、`wrap(dek)->bytes`、`unwrap(wrapped)->bytes`)依 ADR-001。
- [ ] `ScryptKEK(kem_id=1)`:`scrypt(pw, salt, n=2**log2n, r, p, dklen=32)` → KEK,再以 `aead` 包/解 DEK。
- **[C2] wrap 的線格式與 nonce(缺這條會與 C1 合成完全破解)**:
  - [ ] `wrap()` 輸出**恰為** `wrap_nonce(12B) ‖ ct(32B) ‖ tag(16B)` = **60B**;`wrap_nonce = secrets.token_bytes(12)`,**每次 wrap 重新產生**;**禁止**零 nonce、固定 nonce、或重用 header 的 `nonce_prefix`。
  - [ ] wrap/unwrap 的 **AAD = 常數 `b"QVLT-dek-v1"`**(header 含 `wrapped_dek` 本身,不可作為 wrap 的 AAD——循環)。
  - [ ] 測試:`len(wrap(dek)) == 60`;同一 KEK 實例對同一 DEK 連呼叫兩次,**輸出前 12B 不同**;`kem_id==1` 時 header 的 `wrapped_dek_len` 必須 == 60,否則 `QVaultFormatError`。
- **[H4] 金鑰不得可印(在此之前「不洩金鑰」不可證偽)**:
  - [ ] `ScryptKEK` **不得使用預設 dataclass repr**;`__repr__` 固定為 `<ScryptKEK kem_id=1>`。
  - [ ] 測試:以密碼 `"S3cr3t-pw-marker"` 建 KEK,斷言該字串**不出現於** `repr(kek)`、`str(kek)`、`repr(vars(kek))`;`unwrap` 失敗時 `"".join(traceback.format_exception(exc))` 亦不含該字串與 DEK hex。
- **[M4]** 測試:①錯密碼 ②`wrapped_dek` 改 1 byte —— 兩路徑的 `type(exc)` 與 `str(exc)` **完全相同**(逐字元)。
- **[M6]** passphrase → bytes 一律 `unicodedata.normalize("NFC", pw).encode("utf-8")`;測試含非 ASCII 密碼(`"密碼🔑"`)的 round-trip。
- **[M3]** scrypt 參數(15/8/1)**覆寫僅供測試**;`encrypt_file` 一律寫 15/8/1,不得讓測試用的低參數繼承到預設路徑。
- **[L]** ABC 契約改成可證偽:`KeyEncapsulation()` 直接實體化 → `TypeError`;缺 `wrap` 的子類實體化 → `TypeError`;`ScryptKEK.kem_id == 1` 且為類別屬性。

---

## #4 檔案層(STREAM)

- [ ] `qvault_core/vault.py`:`encrypt_file(inp, out, passphrase)`、**[M8]** `decrypt_file(inp, out_dir, passphrase) -> Path`(`out_dir` 是**目錄**;實際檔名取自 chunk 0 並經 C4 淨化,回傳寫出路徑)。
- **[C1] salt 每檔隨機(缺這條 = 全世界共用一把 KEK)**:
  - [ ] `salt = secrets.token_bytes(16)`,**禁止**常數、禁止由密碼/檔名/路徑/時間/任何雜湊派生。
  - [ ] 測試:以**同一密碼**加密**同一份內容**兩次 → 兩份 `.qvt` 的 **salt、nonce_prefix、wrapped_dek、密文本體四者皆不相同**(這一條同時擋掉常數 salt、DEK 重用、prefix 派生三種錯法)。
- [ ] 加密流程:gen DEK → `ScryptKEK.wrap` → 組 header → `nonce_prefix = secrets.token_bytes(7)` → chunk0 = 加密中繼資料 → chunk1..n 資料,每塊 nonce = `nonce_for`、**AAD = header 全段** → 寫 `.qvt`。
- **[M5] chunk 0 明文佈局固定**:`name_len(2B BE) ‖ name_utf8(name_len B) ‖ orig_size(8B BE)`,總長 ≤ 4096;`name_len` 與剩餘長度不符 → `QVaultFormatError`。
- **[C3] 解密具原子性——絕不留下未驗證的部分明文**:
  - [ ] 解密一律寫入**目標目錄下的暫存檔**(權限 `0o600`),**全部** chunk 驗證通過且末塊 flag==`0x01` 之後才 `os.replace()` 到目標;任一步失敗必須 `os.unlink` 暫存檔後 raise。
  - [ ] 測試:竄改 5 塊檔的第 2 塊 → raise `QVaultDecryptError`,且**目標路徑不存在、目錄內無殘留暫存檔**(對照 ADR-001 保證①)。
- **[C4] chunk 0 的檔名是不可信輸入(Zip Slip)**:
  - [ ] 還原檔名一律經 `os.path.basename()` 後檢查:非空、不等於 `.`/`..`、不含 `/`、`\`、**控制字元 `\x00`–`\x1f`**、UTF-8 strict 可解碼、長度 ≤255 bytes;任一不符 → `QVaultFormatError`,**不得回退成寫入原始字串**(「修正」成合法名等於替攻擊者挑一個能寫的位置)。
  - [ ] **Windows 專屬四類——三平台一律套用**(淨化規則不因執行平台而異,否則在 Linux 產生的惡意檔會等到 Windows 才發作):
    - **不得含 `:`**——一條規則同時擋掉磁碟機相對路徑(`C:evil.txt`,Windows 上會寫到 C: 的目前目錄而非 `out_dir`)與交替資料流(`x.txt:hidden`)。
    - **去副檔名後的主檔名(大小寫不分)不得為保留裝置名**:`CON`、`PRN`、`AUX`、`NUL`、`COM1`–`COM9`、`LPT1`–`LPT9`。
    - **不得以 `.` 或空白結尾**(Windows 靜默去尾 → 可造成撞名覆寫)。
  - [ ] 寫出路徑必須為 `out_dir/name` 且 realpath 後仍在 `realpath(out_dir)` 之下;目標已存在**預設拒絕**(`--force` 才覆寫)。
  - [ ] 測試:夾具 `.qvt` 內嵌檔名 `"../../evil"`、`"/etc/passwd"`、`".."`、`"a\x00b"`、**`"C:evil.txt"`、`"CON"`、`"com1.txt"`、`"x.txt:hidden"`、`"evil.txt."`、`"evil.txt "`** 各一 → decrypt **皆 raise**,且 **out_dir 以外無任何檔案被建立**。這些測試**三平台都要跑**,不得以 `skipif(windows)` 之類略過——規則是平台無關的。
- **[H2] 截斷/重排偵測(只測「刪末塊」不夠)**:
  - [ ] `is_last` 必須由**剩餘位元組數推導**(`remaining == chunk_size + 16` → last);**禁止**「先試 flag=0、失敗再試 flag=1」的試誤法。
  - [ ] 解密迴圈結束後必須斷言:至少讀到一個 chunk,且最後一個成功開啟的 chunk 是以 flag==`0x01` 開啟;否則 raise `QVaultDecryptError`。
  - [ ] 還原資料長度必須 == chunk 0 宣告的 `orig_size`,否則 raise `QVaultDecryptError`。
  - [ ] 測試:一個 5 塊檔分別做「刪末塊」「刪末 2 塊」「**只留 header**」「只留 header+chunk0」「body 尾端多接 16B 垃圾」「body 尾端重複接一個前面的合法 chunk」→ **六種皆 raise**。
- **[M3]** 測試:夾具 `.qvt` 以 `kdf_log2n=14` 產生,`decrypt_file` **必須成功**(證明解密真的讀 header 參數,而非硬編碼 15/8/1)。
- **[M2] golden file 凍結格式**:
  - [ ] `tests/vectors/golden_v1.qvt`:以 monkeypatch 固定 `salt=b"\x01"*16`、`nonce_prefix=b"\x02"*7`、`dek=b"\x03"*32`、`wrap_nonce=b"\x04"*12`、密碼 `"correct horse"` 產生並進 repo;測試斷言**逐位元組相等**且可被 `decrypt_file` 還原。
- **[M9]** `.qvt`、還原明文、暫存檔建立時皆 `0o600`。**Windows 上 `os.chmod` 近乎 no-op,列為已知上限**(見 ADR「支援平台」——「保護還原後的明文」在 Windows 明顯較弱);實作不得因此報錯,也**不得**因此跳過其他硬化。
- **[H4]** 測試:在 logging root level=DEBUG 且接記憶體 handler 下跑完整 `encrypt_file`→`decrypt_file`,buffer **不含**密碼字串與 DEK/KEK 的 hex。
- **[L] nonce 不重用要用測試證明,不是斷言**:
  - [ ] 對 ≥5 塊的檔案記錄每次 `AESGCM.encrypt` 實際使用的 nonce,斷言**全部相異**且等於 `nonce_for(prefix, i, is_last)`;再加密第二個檔,斷言**兩檔 nonce 集合交集為空**。
- **[L]** 大檔串流以 `tracemalloc` 證明:加解密 64 MiB 檔,峰值配置 `< 8 * chunk_size + 4 MiB`。
- [ ] 測試:round-trip(**空檔**/剛好整除/跨多塊/大檔);錯密碼 → raise;原檔名還原正確。

---

## #5 CLI

- [ ] `qvault_core/cli.py`:`main()`;`encrypt <f>`(→`<f>.qvt`)、`decrypt <f.qvt> [--out-dir DIR] [--force]`(還原原檔名,經 C4 淨化)、`inspect <f.qvt>`。
- [ ] 密碼走 `getpass`(不進 argv/history);encrypt 二次確認。**[L]** 空密碼直接拒絕(決策 8 不強制「強度」,但空字串不是弱、是無)。
- **[M7] `inspect` 輸出走白名單,不是黑名單**:
  - [ ] 僅輸出 version、`kdf_id`/`aead_id`/`kem_id`、`kdf_log2n`/`r`/`p`、`chunk_size`、`.qvt` 在磁碟上的位元組數。
  - [ ] **不得**輸出 salt、`nonce_prefix`、`wrapped_dek`(即使 hex 截斷)——把 wrapped DEK 印進終端/截圖/工單,等於讓攻擊者不需檔案就能離線爆密碼。
  - [ ] **不得**為了顯示原始大小而在 header 新增任何明文欄位(那會洩漏決策 9 要保護的中繼資料)。
  - [ ] 測試:`inspect` stdout 不含 header 中 salt/`nonce_prefix`/`wrapped_dek` 任一段的 hex 表示。
- [ ] 錯密碼/壞檔 → 乾淨訊息 + 非零 exit,**不吐 traceback**、不洩金鑰;`[project.scripts] qvault=cli:main` 可跑。
- [ ] 測試:CLI encrypt→decrypt round-trip;錯密碼 exit≠0 且無 traceback;缺檔/壞檔乾淨錯誤。
