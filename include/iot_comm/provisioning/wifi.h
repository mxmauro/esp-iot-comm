#pragma once

#include "sdkconfig.h"
#include <esp_err.h>

#if (!defined(CONFIG_BT_ENABLED)) || (!defined(CONFIG_BT_NIMBLE_ENABLED)) || (!defined(CONFIG_BT_CONTROLLER_ENABLED))
    #error This library requires CONFIG_BT_ENABLED, CONFIG_BT_NIMBLE_ENABLED and CONFIG_BT_CONTROLLER_ENABLED to be enabled
#endif

#if (!defined(CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE)) || CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE < 5120
    #error This library requires CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE to have a minimum value of 5120
#endif

#if (!defined(CONFIG_NETWORK_PROV_NETWORK_TYPE_WIFI)) || (!defined(CONFIG_NETWORK_PROV_BLE_BONDING)) || (!defined(CONFIG_NETWORK_PROV_BLE_SEC_CONN))
    #error This library requires CONFIG_NETWORK_PROV_NETWORK_TYPE_WIFI, CONFIG_NETWORK_PROV_BLE_BONDING and CONFIG_NETWORK_PROV_BLE_SEC_CONN to be enabled
#endif

// -----------------------------------------------------------------------------

typedef enum WifiMgrEvent_e {
    WifiMgrEventConnected    = 1,
    WifiMgrEventDisconnected = 2
} WifiMgrEvent_t;

typedef void (*WifiMgrEventHandler_t)(WifiMgrEvent_t event);

typedef struct WifiMgrConfig_s {
    const char            *providerPrefix; // Optional. Defaults to "PROV".
    const char            *popCode;        // Optional. Defaults to no security on provisioning.
    const uint8_t         bleServiceUUID[16];
    WifiMgrEventHandler_t handler;
} WifiMgrConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void wifiMgrInit(WifiMgrConfig_t *config);
void wifiMgrDone();

bool wifiMgrDeleteConfig();

#ifdef __cplusplus
}
#endif // __cplusplus
