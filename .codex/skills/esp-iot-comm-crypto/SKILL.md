---
name: esp-iot-comm-crypto
description: Work on cryptographic primitives and key-material handling in esp-iot-comm. Use when Codex is changing `src/crypto/*.cpp`, `include/iot_comm/crypto/*.h`, AES-GCM helpers, HKDF derivation, P-256 ECDH/ECDSA operations, SHA wrappers, Base64 key serialization, or ESP-IDF 5.x versus 6.x crypto backend behavior.
---

# Esp Iot Comm Crypto

Use this skill for security-sensitive primitive code and key handling. This area has API branching for different ESP-IDF major versions and is shared by both the authenticated server and the captive portal.

## Workflow

1. Read [references/crypto-map.md](references/crypto-map.md).
2. Identify whether the change affects primitive semantics, serialization/encoding, or backend compatibility.
3. Preserve key wiping and error handling when touching private key, shared secret, derived key, or authentication-tag paths.
4. Keep header requirements in sync with implementation if a dependency or capability changes.
5. Add or update targeted tests when behavior changes in deterministic helper code.

## Rules

- Treat private keys, shared secrets, derived keys, and signature material as sensitive data.
- Preserve ESP-IDF version split behavior where PSA Crypto is used on 6.x and MbedTLS wrappers are used on older versions.
- Do not weaken public-key validation or signature verification paths.
- Keep public constants and key sizes stable unless the task explicitly changes the supported cryptosystem.

## References

- [references/crypto-map.md](references/crypto-map.md)
