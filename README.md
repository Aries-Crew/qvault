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

### In a browser

Same three operations as web forms, served by Python's standard library only:

```bash
qvault ui                      # prints the URL, opens it in your browser
qvault ui --port 8765          # fixed port (default: 0 = whatever is free)
qvault ui --no-browser         # just print the URL
```

The URL it prints looks like `http://127.0.0.1:52231/#<token>`. Five things
to know before you use it:

- It binds `127.0.0.1` and nothing else. There is no `--host` / `--bind` —
  the address is a constant in the source, so no flag and no environment
  variable can expose it to your network.
- The part after the `#` is a **one-time token**, minted at startup. Do not
  paste that URL to anyone and do not put it in a bug report: whoever holds
  it can encrypt and decrypt files on this machine as you. (It rides in the
  URL fragment, so the browser never puts it in a request line — it stays out
  of access logs and `Referer` headers. The page's JavaScript *does* send it
  to the server, in an `Authorization: Bearer` header, on every API call: it
  is the credential the server checks.)
- The token dies with the command: it never goes
  into a cookie or into browser storage, and stopping the command — Ctrl-C,
  `SIGTERM`, or close the terminal — retires it for good. The next
  `qvault ui` mints a fresh one.
- It is *not* handed to the browser on a command line, where `ps` can see it
  — and on a stock Linux (no `hidepid`) that process list is readable by
  **other users on this machine**, not only by processes running as you.
  What the browser gets instead is a local redirect page that only you can
  read: a `0600` file in a `0700` private temporary directory, holding one
  line of script that jumps to the URL above. That file is
  the only file the token is ever written to, and it is deleted when the
  command stops the ways it knows how to stop — Ctrl-C, `SIGTERM`, `SIGHUP`,
  or an error. A signal it cannot catch or does not handle (`kill -9`,
  `SIGQUIT` from Ctrl-\, a crash) leaves it behind; a leftover is still
  readable only by you. (Decided by the maintainer on 2026-11-10; see
  [ADR-002](docs/adr/ADR-002-local-web-ui.md) decision 12.)
- It is *not* hidden from this machine, though: it is printed on your
  terminal, so it is in the scrollback and in whatever you piped stdout into.
  Use `--no-browser` if you would rather hand the URL over yourself:
  then no redirect page is written at all.

## 📄 License

MIT — see [LICENSE](LICENSE).
