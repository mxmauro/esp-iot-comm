# Onboarding Flow

## Main Components

- `src/provisioning/wifi.cpp`: provisioning state machine and Wi-Fi lifecycle.
- `src/captive_portal/captive_portal.cpp`: HTTP endpoints, embedded asset serving, scan API, server key exposure, encrypted provisioning payload processing.
- `include/iot_comm/provisioning/wifi.h`: Wi-Fi manager API.
- `include/iot_comm/captive_portal/captive_portal.h`: captive portal API and provisioning config struct.

## Normal Handoff

1. Device starts provisioning SoftAP when STA credentials are absent.
2. Captive portal serves the embedded UI and collects onboarding fields.
3. `handleProvision()` decrypts and validates the payload.
4. App callback receives `CaptivePortalProvisioningConfig_t`.
5. Application usually calls:
   - `wifiMgrSetHostname()`
   - `iotCommInitRootUserPublicKey()`
   - `wifiMgrStoreSTA()`
   - `wifiMgrStartSTA()`

## Validation Boundaries

- SSID: required, 1..32 chars.
- Password: empty or 8..64 chars.
- Root key: only required when `setupRootUser` is enabled; must decode to a valid P-256 public key.
- Hostname: only required when `setupDeviceHostname` is enabled; must pass RFC1123-style validation.

## Manual Verification Targets

- Fresh-boot provisioning with no stored STA credentials.
- Transition from captive portal submission to STA connection.
- Optional root user disabled/enabled flows.
- Optional hostname disabled/enabled flows.
- Reconnect/auth-failure event behavior after credentials are stored.
