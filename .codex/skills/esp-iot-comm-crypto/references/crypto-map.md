# Crypto Map

## Main Files

- `src/crypto/aes.cpp`: AES-GCM encrypt/decrypt wrapper with PSA Crypto on ESP-IDF 6.x and MbedTLS GCM on older versions.
- `src/crypto/hkdf.cpp`: HKDF-SHA256 wrapper with PSA or MbedTLS backend split.
- `src/crypto/p256.cpp`: key container helpers, P-256 key import/export, ECDH shared secret, ECDSA sign/verify.
- `src/crypto/sha.cpp`: SHA-256 and SHA-512 wrappers.
- `src/crypto/utils.cpp`: helper utilities used by crypto code.
- `include/iot_comm/crypto/*.h`: exported constants, type definitions, and API contracts.

## Shared Consumers

- `src/iot_comm.cpp` uses:
  - session and transport key derivation
  - authenticated encryption/decryption
  - challenge/session material
  - UDP transport derivation
- `src/captive_portal/captive_portal.cpp` uses:
  - server ECDH key pair generation
  - shared secret computation
  - HKDF-derived AES key
  - AES-GCM payload decryption

## Version Split

- ESP-IDF 6.x paths use PSA Crypto for AES, HKDF, ECDH/ECDSA import/export, and hashing wrappers.
- Older ESP-IDF paths use MbedTLS APIs directly.
- If behavior changes, keep the success/failure contract aligned across both backends.

## Validation Focus

- Key-size and buffer-size checks.
- Public-key validation strictness.
- Signature verification behavior.
- Shared-secret and derived-key handling.
- Sensitive-buffer wiping on failure or after export/import helpers.
