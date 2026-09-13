# Captive Portal

This module provides the onboarding UI flow declared in `include/iot_comm/captive_portal/captive_portal.h`. In practice, it turns the
provisioning SoftAP into an actual setup experience instead of leaving it as just a raw network.

The captive portal has a narrow job: collect the provisioning config the device needs on first boot and pass it back to the application.

## Provisioning Config

When the user submits provisioning data through the captive portal, your callback receives a `CaptivePortalProvisioningConfig_t`. You can
use that information to configure the Wi-Fi manager and the IotComm engine. The struct contains the following fields:

* `wifiSSID`: the STA network the device should join after onboarding.
* `wifiPassword`: the password for that STA network. It may be empty for open networks.
* `rootUserPublicKey`: the initial public key for the root user. This is the key later used by `iot_comm` for authenticated administration.
* `hostname`: the optional device hostname that should be applied to the Wi-Fi interfaces.

Three `CaptivePortalConfig_t` flags decide which parts of that struct the portal actually collects:

* `requestWifiCredentials`: enables SSID and password collection.
* `setupRootUser`: enables the root-user key flow in the UI.
* `setupDeviceHostname`: enables hostname collection in the UI.

In other words, the struct is broader than any single onboarding screen. Your application can decide whether a given product setup only asks
for Wi-Fi credentials, or whether it also asks for a hostname and the initial root user key.

## Authorized Recovery

For a recovery portal, set `requireRootAuthorization` and provide `rootAuthorization`. The portal then exposes a fresh 32-byte challenge from `/init-params` and requires
a raw 64-byte P-256 signature accepted by that callback before invoking the credential callback. The browser signs the SHA-256
transcript `"iot-comm/captive-portal-recovery/v1" || challenge || ssidLength || ssid || passwordLength || password`; lengths are bytes.
Recovery UI accepts the Base64 raw root private key only to sign locally, clears it, and never sends it to the device.

Applications using IotComm can implement `rootAuthorization` by calling `iotCommVerifyRootUserSignature()`. This keeps the portal usable
with a different authorization backend.

Configure recovery with `setupRootUser` and `setupDeviceHostname` disabled. Its callback should only store the replacement STA credentials
and start STA mode. A lost root key requires a physical reset.

## Typical Integration

1. Initialize Wi-Fi and react to `WifiMgrEventProvisioningRequired`.
2. Initialize `capPortal` in a `WifiMgrProvisioningHandlerConfig_t::start` callback.
3. Forward requests through `capPortalHandleRequest()` and release it in the `stop` callback.
4. Start that configuration with `wifiMgrStartProvisioning()`.
5. Receive and apply the selected fields in your `CaptivePortalProvisioningConfigHandler_t` callback.

Once your callback receives the provisioning config, the usual handoff looks like this:

* `wifiMgrSetHostname()` for the device hostname.
* `iotCommInitRootUserPublicKey()` for the root user key.
* `wifiMgrStoreSTA()` for the STA credentials.
* `wifiMgrStartSTA()` to leave provisioning mode.

## UI Source Layout

* The editable frontend sources live under `src/captive_portal/web-src/`.
* The files under `src/captive_portal/web-dist/` are generated assets embedded by the component.
* When changing the portal UI, edit the sources and rebuild the embedded assets instead of patching `dist/` by hand.

## Related APIs

* `wifiMgrStoreSTA()`
* `wifiMgrSetHostname()`
* `iotCommInitRootUserPublicKey()`
