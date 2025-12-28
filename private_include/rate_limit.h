#pragma once

#include "ip_address.h"
#include <esp_err.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t rateLimitInit(size_t maxSlots, uint32_t windowSizeInMs, uint8_t maxRequestsPerWindow,
                        uint8_t maxConsecutiveFailures);
void rateLimitDone();

bool rateLimitCheckRequest(const IPAddress_t *addr);

void rateLimitIncrementFailedAuth(const IPAddress_t *addr);

bool rateLimitIsAddressBlocked(const IPAddress_t *addr);

void rateLimitResetAddress(const IPAddress_t *addr);
void rateLimitResetAll();

#ifdef __cplusplus
}
#endif // __cplusplus
