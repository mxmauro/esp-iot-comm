# Tests

To run the test suite, open an ESP-IDF v5.5 or later terminal and run:

```bash
idf.py set-target esp32c3    # replace esp32c3 with your device type
idf.py build
idf.py -p COM3 flash monitor    # replace COM3 with the port your device is connected
```

Current automated coverage includes:

* `test_iot_comm.cpp`: Default public config helpers.
* `test_mdns.cpp`: Hostname validation rules.
* `test_crypto.cpp`: Constant-time compare, HKDF, AES-GCM, P-256 key encode/decode, ECDH, and ECDSA.

The captive portal UI flow is intentionally not part of this automated coverage because it depends on manual user interaction.
