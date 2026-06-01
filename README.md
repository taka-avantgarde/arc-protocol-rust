<div align="center">

# Arc Protocol · Cryptographic Core

**The post-quantum, end-to-end encryption engine behind [Arc](https://www.atlasassociates.io)**
A thin, faithful Rust binding over the [Signal Protocol](https://signal.org/docs/) — exposed to Flutter via FFI.

<br/>

[![Rust](https://img.shields.io/badge/Rust-Edition_2021-000000?style=for-the-badge&logo=rust&logoColor=FF9580)](https://www.rust-lang.org)
[![Signal Protocol](https://img.shields.io/badge/Signal_Protocol-libsignal_v0.94.1-3A76F0?style=for-the-badge&logo=signal&logoColor=white)](https://github.com/signalapp/libsignal)
[![flutter_rust_bridge](https://img.shields.io/badge/FFI-flutter__rust__bridge_2.12-02569B?style=for-the-badge&logo=flutter&logoColor=white)](https://github.com/fzyzcjy/flutter_rust_bridge)
[![License](https://img.shields.io/badge/License-AGPL_3.0-A42E2B?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)

[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--1024-6C5CF7?style=flat-square)](#-cryptography)
[![Forward Secrecy](https://img.shields.io/badge/Double_Ratchet-FS_+_PCS-5271FF?style=flat-square)](#-cryptography)
[![Group E2EE](https://img.shields.io/badge/Sender_Keys-group_E2EE-00D8C4?style=flat-square)](#-cryptography)
[![iOS 16+](https://img.shields.io/badge/iOS-16+-000000?style=flat-square&logo=apple&logoColor=white)](#-platforms)
[![Android](https://img.shields.io/badge/Android-16KB_pages-3DDC84?style=flat-square&logo=android&logoColor=white)](#-platforms)
[![Scope](https://img.shields.io/badge/scope-crypto_core_only-F48771?style=flat-square)](#-what-this-is)

</div>

---

## 📖 What this is

A thin, faithful binding over the **Signal Protocol** via
[libsignal](https://github.com/signalapp/libsignal), exposed to the Arc client
(Flutter) through [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge).
Every E2EE operation is delegated to libsignal — this crate adds **no
cryptographic primitives of its own**.

It contains **no application logic** — no UI, no message-lifecycle features,
no business logic. Those live in the (separate, proprietary) Arc application,
which is **not** part of this crate.

## 🔐 Cryptography

All primitives are implemented by libsignal; this crate only wires them to the
Flutter FFI surface.

| Primitive | Role | |
|-----------|------|--|
| **PQXDH** | Post-quantum session establishment | ![ML-KEM-1024](https://img.shields.io/badge/ML--KEM--1024-6C5CF7?style=flat-square) |
| **Double Ratchet** | Message encryption — forward secrecy + post-compromise security | ![FS + PCS](https://img.shields.io/badge/FS_+_PCS-5271FF?style=flat-square) |
| **Sender Keys** | Efficient group messaging | ![group E2EE](https://img.shields.io/badge/group_E2EE-00D8C4?style=flat-square) |
| **XEdDSA** | Signing / verification | ![signatures](https://img.shields.io/badge/signatures-F48771?style=flat-square) |

## 🧰 Tech Stack

| | Component | Version | Role |
|--|-----------|---------|------|
| <img src="https://cdn.simpleicons.org/rust/E43717" width="18"/> | **Rust** | Edition 2021 | Memory-safe crypto core — `cdylib` + `staticlib` |
| <img src="https://cdn.simpleicons.org/signal/3A76F0" width="18"/> | **libsignal-protocol** | v0.94.1 | Signal Protocol implementation (X3DH / PQXDH / Double Ratchet / Sender Keys) |
| <img src="https://cdn.simpleicons.org/flutter/02569B" width="18"/> | **flutter_rust_bridge** | 2.12.0 | Type-safe Dart ⇄ Rust FFI codegen |
| <img src="https://cdn.simpleicons.org/tokio/8A2BE2" width="18"/> | **tokio** | 1.x (`rt`) | Async runtime for libsignal store traits |
| <img src="https://cdn.simpleicons.org/rust/E43717" width="18"/> | **rand · base64 · uuid · lazy_static · async-trait** | — | Supporting crates (RNG, encoding, registration IDs, FFI glue) |

> **Build dependency:** the [protobuf compiler](https://grpc.io/docs/protoc-installation/) (`protoc`) is required to build libsignal.

## 📱 Platforms

Built as a native library for every Arc client target via `flutter_rust_bridge`:

| | Platform | Notes |
|--|----------|-------|
| <img src="https://cdn.simpleicons.org/apple/A2AAAD" width="16"/> | **iOS 16+** | `aarch64-apple-ios` — stack-check workaround for ML-KEM C code |
| <img src="https://cdn.simpleicons.org/android/3DDC84" width="16"/> | **Android** | `aarch64` / `armv7` / `x86_64` / `i686` — **16 KB page sizes** (Google Play, May 31 2026) |

## 🗂️ Layout

```text
src/
├── lib.rs                  # crate root
├── frb_generated.rs        # flutter_rust_bridge codegen (do not edit)
├── sender_key_store.rs     # SenderKeyStore impl for group messaging
└── api/                    # FFI surface exposed to Flutter
    ├── signal_protocol.rs  # 1:1 sessions — PQXDH + Double Ratchet
    ├── signal_group.rs     # group messaging — Sender Keys
    ├── signal_store.rs     # protocol store — identities, prekeys, sessions
    └── simple.rs           # small helpers
```

## ⚖️ Why this is open source

This crate links libsignal, which is licensed under **AGPL-3.0**. To honor that
copyleft, the libsignal-linked code is published here under the same license.

The Signal Protocol — X3DH, PQXDH (ML-KEM-1024), the Double Ratchet, and Sender
Keys — was designed and is maintained by **Signal Messenger, LLC** (formerly
Open Whisper Systems). This crate is an independent integration and is **not
affiliated with, sponsored by, or endorsed by Signal**.

## 📜 License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-A42E2B?style=flat-square&logo=gnu&logoColor=white)](LICENSE)

**AGPL-3.0-only.** See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

<div align="center">
<sub>© 2026 Atlas Associates Inc. · Crafted for <a href="https://www.atlasassociates.io">Arc</a></sub>
</div>
