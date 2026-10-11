# Provisioning example

To build and run the example, open an ESP-IDF v5.5 or later terminal and run:

```bash
idf.py set-target esp32c3    # replace esp32c3 with your device type
idf.py build
idf.py -p COM3 flash monitor    # replace COM3 with the port your device is connected
```

The Wi-Fi manager initializes and deinitializes mDNS for this example. The hostname collected by the captive portal is applied with
`wifiMgrSetHostname()`; do not call `mdns_init()` or `mdns_hostname_set()` separately.

The example initializes IotComm before the Wi-Fi manager, queries whether a root public key is configured, and passes that state to the
Wi-Fi manager. It starts bootstrap setup when no root public key is configured, or authorized recovery when a root key exists but Wi-Fi
credentials are unavailable.

This example uses a 30-second STA attempt and a five-minute recovery portal window. If stored credentials do not obtain an IPv4 or IPv6
address, it opens a recovery portal that can replace only Wi-Fi credentials after a P-256 signature from the existing root private key,
then returns to STA mode when the window expires. The example keeps the SoftAP open for local-access compatibility; set a per-device
SoftAP password in `main.cpp` to require WPA2 association. Losing the root key requires a physical reset.
