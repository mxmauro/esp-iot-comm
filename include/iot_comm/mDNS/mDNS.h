#pragma once

#include "sdkconfig.h"
#include <esp_err.h>

#if (!defined(CONFIG_MDNS_PREDEF_NETIF_STA)) || (!defined(CONFIG_MDNS_PREDEF_NETIF_AP))
    #error This library requires CONFIG_MDNS_PREDEF_NETIF_STA and CONFIG_MDNS_PREDEF_NETIF_AP to be enabled
#endif

#if (!defined(CONFIG_MDNS_TASK_STACK_SIZE)) || CONFIG_MDNS_TASK_STACK_SIZE < 4096
    #error This library requires CONFIG_MDNS_TASK_STACK_SIZE to have a minimum value of 4096
#endif

// -----------------------------------------------------------------------------

typedef struct mDnsServiceTxt_s {
    const char *key;
    const char *value;
} mDnsServiceTxt_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// The initialization function must be called right after the network
// provisioning engine is started.
void mDnsInit();
void mDnsDone();

// If hostname is null or empty, it is replaced with mx-iot-$mac.
// $mac is replaced with the last three hexa digits of the MAC address.
// $fullmac is replaced with the whole six hexa digits of the MAC address.
esp_err_t mDnsSetHostname(const char *hostname);

esp_err_t mDnsAddService(const char *service, const char *proto, uint16_t port,
                         const mDnsServiceTxt_t *txtList = nullptr, size_t txtListCount = 0);
esp_err_t mDnsRemoveService(const char *service, const char *proto);

#ifdef __cplusplus
}
#endif // __cplusplus
