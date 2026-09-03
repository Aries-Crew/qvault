# 🔐 QVault — Post-Quantum-Ready Local File Vault

> Future-proof file privacy against **Harvest-Now-Decrypt-Later** (HNDL) attacks — hybrid **AES-256-GCM + ML-KEM** envelope encryption.

[![Status](https://img.shields.io/badge/status-WIP_v0-orange)](#-project-status-read-this)
[![Core](https://img.shields.io/badge/core-Python_reference-blue)](#)
[![Crypto](https://img.shields.io/badge/AES--256--GCM-cryptography-brightgreen)](#)
[![PQC](https://img.shields.io/badge/ML--KEM--1024-planned-lightgrey)](#)

---

## ⚠️ Project status — read this

**QVault is early WIP (v0.x) and NOT production-ready. Do not protect real secrets with it yet.**

This repository is being **built autonomously by [asp-ng](https://github.com/Aries-Crew/asp-ng)** — an AI development loop that converts ROADMAP items into issues, implements them, and QA-verifies them. What exists today is the **Python reference core**, delivered slice by slice:

| Layer | What | Status |
|---|---|---|
| **Core (this repo)** | `.qvt` format + AES-256-GCM envelope + scrypt KEK, as a Python reference library | 🚧 in progress (P0) |
| **Post-quantum** | ML-KEM-1024 hybrid KEK (NIST FIPS 203) wrapping the data key | 🔜 planned (P1) |
| **Desktop product** | Rust/Tauri GUI, cross-platform packaging, hardware acceleration | 🗺️ future (out of the automated loop) |

The Python core defines the **`.qvt` cryptographic contract + test vectors**; a later Rust/Tauri product conforms to it.

---

## ⚛️ Why post-quantum, today?

Adversaries run **Harvest-Now-Decrypt-Later**: capture encrypted data now, store it, decrypt once fault-tolerant quantum computers arrive (Shor's algorithm breaks RSA/ECC). QVault's design wraps a symmetric data key in a **hybrid** KEM — classical *and* post-quantum — so data stays private even if one layer falls.

## 🧪 Envelope architecture

```
file ──AES-256-GCM──▶ ciphertext          (DEK = random 256-bit data key)
DEK  ──wrap(KEK)────▶ wrapped DEK          (KEK from scrypt today; ML-KEM-1024 next)
                       └─▶ .qvt container: magic | version | algo-ids | salt | nonce | ct | tag
```

The **KEK layer is a pluggable interface by design**: today a passphrase-derived scrypt KEK, tomorrow an ML-KEM-1024 KEK — the envelope layer does not change.

## 🔒 Crypto discipline

QVault **only uses vetted cryptographic libraries** (`cryptography` for AES-256-GCM/scrypt; a real ML-KEM implementation for PQC). It **never hand-rolls cryptographic primitives** — no bespoke Kyber, no bespoke AES. See `AGENTS.md`.

## 📦 Install / use

Early core only (library + CLI):

```bash
pip install -e .
qvault encrypt secret.txt      # → secret.txt.qvt
qvault decrypt secret.txt.qvt  # → secret.txt
qvault inspect secret.txt.qvt  # → header / algorithms (no secrets)
```

## 📄 License

MIT — see [LICENSE](LICENSE).
