#pragma once

#include "iot_comm/http/helpers.h"
#include "iot_comm/iot_comm.h"

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t httpConfigureTrustedProxies(const IotCommProxyConfig_t* config);
void httpClearTrustedProxies();
bool httpValidateTrustedProxy(const IotCommTrustedProxy_t* proxy);
bool httpIsTrustedProxy(const IPAddress_t* addr, const IotCommTrustedProxy_t* trustedProxies, size_t trustedProxiesCount);
bool httpSelectClientIpFromXForwardedFor(const char* header, const IotCommTrustedProxy_t* trustedProxies,
                                         size_t trustedProxiesCount, IPAddress_t* out);

#ifdef __cplusplus
}
#endif // __cplusplus
