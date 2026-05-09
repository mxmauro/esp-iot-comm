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

Two `CaptivePortalConfig_t` flags decide which parts of that struct the portal actually collects:

* `setupRootUser`: enables the root-user key flow in the UI.
* `setupDeviceHostname`: enables hostname collection in the UI.

In other words, the struct is broader than any single onboarding screen. Your application can decide whether a given product setup only asks
for Wi-Fi credentials, or whether it also asks for a hostname and the initial root user key.

## Typical Integration

1. Initialize the portal with `capPortalInit()`.
2. Forward captive portal HTTP requests to `capPortalHandleRequest()`.
3. Receive the validated config in your `CaptivePortalProvisioningConfigHandler_t` callback.
4. Store the Wi-Fi credentials, hostname, and root key with the corresponding library APIs.

Once your callback receives the provisioning config, the usual handoff looks like this:

* `wifiMgrSetHostname()` for the device hostname.
* `iotCommInitRootUserPublicKey()` for the root user key.
* `wifiMgrStoreSTA()` for the STA credentials.
* `wifiMgrStartSTA()` to leave provisioning mode.

## UI Source Layout

* The editable frontend sources live under `src/captive_portal/web/`.
* The files under `src/captive_portal/web/dist/` are generated assets embedded by the component.
* When changing the portal UI, edit the sources and rebuild the embedded assets instead of patching `dist/` by hand.

## Related APIs

* `wifiMgrStoreSTA()`
* `wifiMgrSetHostname()`
* `iotCommInitRootUserPublicKey()`
