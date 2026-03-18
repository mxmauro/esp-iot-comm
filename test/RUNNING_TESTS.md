# Tests

To run test, open an ESP-IDF v5.5 or later terminal and run the following commands:

```bash
idf.py set-target esp32c3    # replace esp32c3 with your device type
idf.py build
idf.py -p COM3 flash monitor    # replace COM3 with the port your device is connected
```

Current automated coverage includes:

- `test_iot_comm.cpp`: default public config helpers
- `test_mdns.cpp`: hostname validation rules
- `test_crypto.cpp`: constant-time compare, HKDF, AES-GCM, P-256 key encode/decode, ECDH, and ECDSA

The captive portal UI flow is intentionally not part of this battery because it depends on manual user interaction.
