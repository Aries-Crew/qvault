# QVault P0 issue 驗收準則草稿(依 ADR-001)

> 待 #510 上線 + qvault P0 milestone 建立後,逐張貼進 issue body、設 tier/milestone → ready → dev。
> 每張都繼承 AGENTS.md 鐵則:只用受審庫、不手刻密碼、金鑰不落地、tamper 必測。

## #1 `.qvt` 容器格式

- [ ] `qvault_core/container.py`:`QVaultHeader`(magic/version/kdf_id/aead_id/kem_id/kdf_log2n/kdf_r/kdf_p/salt/nonce_prefix/chunk_size/wrapped_dek)+ `serialize()->bytes`、`deserialize(bytes)->(QVaultHeader, body_offset)`,位元佈局依 ADR-001(多位元組一律 big-endian)。
- [ ] `qvault_core/errors.py`:`QVaultError`→`QVaultFormatError`/`QVaultVersionError`/`QVaultDecryptError`。
- [ ] magic≠`b"QVLT"`→`QVaultFormatError`;version 未知→`QVaultVersionError`;定長欄位長度不符 / `wrapped_dek_len` 與實際不符 / 輸入截斷→`QVaultFormatError`(不外洩 `struct.error`/`IndexError`)。
- [ ] chunk 工具:`nonce_for(nonce_prefix, index, is_last)->12B`(`prefix(7B) ‖ uint32_BE(index) ‖ flag(1B)`)、明文分塊迭代器。
- [ ] 測試:round-trip 結構相等;每欄位各改/截一次都 raise;`nonce_for` KAT;header-as-AAD 位元組正確。
- [ ] 只用 stdlib(`struct`/`dataclasses`);**不碰加密**(#2)。

## #2 AES-256-GCM 信封核心

- [ ] `qvault_core/aead.py`:以 `cryptography` `AESGCM` 封裝——`seal(key32,nonce12,pt,aad)->ct‖tag`、`open(key32,nonce12,ct‖tag,aad)->pt`;`gen_dek()=secrets.token_bytes(32)`。
- [ ] `open` 對 ct/tag/nonce/aad/key 任一不符→`QVaultDecryptError`(包住 `InvalidTag`,不外洩原例外、不洩金鑰)。
- [ ] **只用 cryptography,不手刻 AES/GCM**。
- [ ] 測試:round-trip;≥1 組 NIST AES-256-GCM KAT;ct/tag/aad 各改一 byte→raise;錯 key→raise。

## #3 scrypt KEK

- [ ] `qvault_core/kek.py`:`KeyEncapsulation` ABC(`kem_id`、`wrap(dek)->bytes`、`unwrap(wrapped)->bytes`)依 ADR-001。
- [ ] `ScryptKEK(kem_id=1)`:`scrypt(pw,salt,n=2**log2n,r,p,dklen=32)`→KEK,再以 aead 包/解 DEK;參數(15/8/1)可覆寫、salt 由呼叫端給。
- [ ] `unwrap` 失敗(錯密碼/竄改)→`QVaultDecryptError`,**不區分兩者、不洩金鑰**。
- [ ] **只用 cryptography 的 Scrypt+AESGCM,不手刻**。
- [ ] 測試:wrap→unwrap round-trip;錯密碼→raise;wrapped 改一 byte→raise;scrypt KAT;ABC 介面契約齊備。

## #4 檔案層(STREAM)

- [ ] `qvault_core/vault.py`:`encrypt_file(inp,out,passphrase)`、`decrypt_file(inp,out,passphrase)` 依 ADR-001 STREAM 流程。
- [ ] 加密:gen DEK→`ScryptKEK.wrap`→組 header→`nonce_prefix=secrets.token_bytes(7)`→chunk0=加密中繼資料(原檔名+原大小)→chunk1..n 資料,每塊 nonce=`nonce_for`、**AAD=header**→寫 `.qvt`。
- [ ] 解密:讀 header→unwrap DEK→逐塊 `open`(AAD=header)→**驗末塊 flag=1(否則 raise 防截斷)**→還原檔名/資料。
- [ ] **nonce 永不重用**;大檔以 `chunk_size` 串流不整檔載入;金鑰不落地/不進 log/不進訊息。
- [ ] 測試:round-trip(空/剛好整除/跨多塊/大檔);竄改任一塊→raise;**刪末塊(截斷)→raise**;**重排塊→raise**;錯密碼→raise;原檔名還原正確;跨塊 KAT。

## #5 CLI

- [ ] `qvault_core/cli.py`:`main()`;`encrypt <f>`(→`<f>.qvt`)、`decrypt <f.qvt>`(還原原檔名)、`inspect <f.qvt>`。
- [ ] 密碼走 `getpass`(不進 argv/history);encrypt 二次確認。
- [ ] `inspect` 只印 header 摘要(version/演算法 id/chunk_size/檔大小)——**永不印金鑰/明文/檔名**(檔名在加密體內,inspect 不解密故看不到)。
- [ ] 錯密碼/壞檔→乾淨訊息 + 非零 exit,**不吐 traceback**、不洩金鑰;`[project.scripts] qvault=cli:main` 可跑。
- [ ] 測試:CLI encrypt→decrypt round-trip;inspect 不含敏感值;錯密碼 exit≠0 且無 traceback;缺檔/壞檔乾淨錯誤。
