# Wi-Fi Provisioning

This module handles how the device gets onto the network. It covers first-boot provisioning, the transition from SoftAP mode to STA mode,
reconnect notifications, and hostname management through `include/iot_comm/provisioning/wifi.h`.

If you are wiring the library into a product, this is usually the second piece to read after `iot_comm`. It is responsible for getting the
device connected, but it does not own the application protocol itself.

## Responsibilities

* Starts a provisioning SoftAP when no STA credentials are stored.
* Switches the device into STA mode once credentials are available.
* Notifies the application about connection, disconnection, and auth-failure events.
* Stores an optional device hostname and applies it to both Wi-Fi netifs.

## Typical Flow

The normal boot sequence looks like this:

1. Fill `WifiMgrConfig_t` with your event handler and provisioning SoftAP settings.
2. Optionally call `wifiMgrSetHostname()` before initialization.
3. Call `wifiMgrInit()`.

From there, the manager follows one of two paths:

* If stored STA credentials already exist, it goes straight into STA mode.
* If not, it starts the provisioning SoftAP and waits for your onboarding flow to provide credentials.

After the captive portal collects the credentials, the application usually calls `wifiMgrStoreSTA()` and then `wifiMgrStartSTA()`.

## Main APIs

| API                      | Purpose                                          |
|--------------------------|--------------------------------------------------|
| `wifiMgrInit()`          | Initializes Wi-Fi, provisioning, and callbacks.  |
| `wifiMgrDeinit()`        | Stops Wi-Fi and releases resources.              |
| `wifiMgrIsProvisioned()` | Reports whether STA credentials are stored.      |
| `wifiMgrDeleteConfig()`  | Deletes the stored STA credentials.              |
| `wifiMgrStoreSTA()`      | Stores the SSID and password collected on setup. |
| `wifiMgrStartSTA()`      | Leaves provisioning mode and starts STA mode.    |

## Hostname APIs

| API                    | Purpose                                                                                                     |
|------------------------|-------------------------------------------------------------------------------------------------------------|
| `wifiMgrSetHostname()` | Stores or clears the device hostname.                                                                       |
| `wifiMgrGetHostname()` | Returns the stored hostname. On `ESP_ERR_NOT_FOUND`, the value of `CONFIG_LWIP_LOCAL_HOSTNAME` is returned. |

* Hostnames are optional.
* The accepted format is a single DNS label using letters, digits, and `-`. ([RFC 1123](https://www.rfc-editor.org/rfc/rfc1123.html))
* Passing `nullptr` or an empty string clears the stored hostname.
* These two APIs can be used even before `wifiMgrInit()`.

If you never set a hostname, the manager falls back to `CONFIG_LWIP_LOCAL_HOSTNAME`.

## Events

* `WifiMgrEventConnected`: the station acquired IPv4 or IPv6 connectivity.
* `WifiMgrEventDisconnected`: an established STA connection was lost.
* `WifiMgrEventAuthenticationFailed`: a reconnect attempt failed with `WIFI_REASON_AUTH_FAIL`.

The manager automatically retries after a disconnect. The auth-failure event is there to distinguish a normal link drop from a reconnect
attempt where the stored credentials are no longer accepted.

## What Gets Stored

* STA credentials are stored through the ESP-IDF Wi-Fi driver storage.
* The optional hostname is stored separately by this component.
* `wifiMgrDeleteConfig()` clears the stored Wi-Fi credentials. If your application treats hostname as part of the onboarding state, make
  sure your reset flow handles that consistently too.

## See Also

* [Captive portal](CAPTIVE_PORTAL.md)
