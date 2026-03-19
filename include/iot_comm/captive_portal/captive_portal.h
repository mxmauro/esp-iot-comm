#pragma once

#include "iot_comm/utils/network.h"
#include "iot_comm/crypto/p256.h"
#include <esp_err.h>
#include <esp_http_server.h>

// -----------------------------------------------------------------------------

typedef struct CaptivePortalCredentials_s {
    char    wifiSSID[32];
    char    wifiPassword[64];
    uint8_t rootUserPublicKey[P256_PUBLIC_KEY_SIZE];
    char    hostname[MAX_HOSTNAME_LEN + 1];
} CaptivePortalCredentials_t;

typedef esp_err_t (*CaptivePortalCredentialsHandler_t)(CaptivePortalCredentials_t *creds, void *ctx);

typedef struct CaptivePortalConfig_s {
    CaptivePortalCredentialsHandler_t handler;
    void *handlerCtx;
    bool setupRootUser;
    bool setupDeviceHostname;
} CaptivePortalConfig_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t capPortalInit(CaptivePortalConfig_t *config);
void capPortalDeinit();

esp_err_t capPortalHandleRequest(httpd_req_t *req);

#ifdef __cplusplus
}
#endif // __cplusplus

// -----------------------------------------------------------------------------
