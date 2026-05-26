# Arc Protocol — Cryptographic Core

The cryptographic core of [Arc](https://www.atlasassociates.io), an
end-to-end encrypted messenger by Atlas Associates Inc. This Rust crate is
the FFI layer that delegates all E2EE operations to
[libsignal](https://github.com/signalapp/libsignal).

## What this is

A thin, faithful binding over the Signal Protocol via libsignal, exposed to
the Arc client (Flutter) through [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge):

- **PQXDH (ML-KEM-1024)** — post-quantum session establishment
- **Double Ratchet** — message encryption (forward secrecy + post-compromise security)
- **Sender Keys** — group messaging
- **XEdDSA** — signing / verification

It contains **no application logic** — no UI, no message-lifecycle features,
no business logic. Those live in the (separate, proprietary) Arc
application, which is not part of this crate.

## Why this is open source

This crate links libsignal, which is licensed under **AGPL-3.0**. To honor
that copyleft, the libsignal-linked code is published here under the same
license. The Signal Protocol itself is the work of Signal Messenger, LLC;
this crate is an independent integration and is **not affiliated with or
endorsed by Signal**.

## License

**AGPL-3.0-only.** See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
