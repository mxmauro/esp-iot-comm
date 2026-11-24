#pragma once

#include "iot_comm/utils/network.h"
#include <esp_err.h>
#include <esp_http_server.h>
#include <growable_buffer.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
    #include <lightstd/string.h>
#endif // __cplusplus

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Returns ESP_OK and sets *originOut to nullptr when the Origin header is not present.
// Also, allocated memory for *originOut must be freed with httpFreeCORSOrigin() when no longer needed.
esp_err_t httpGetCORSOrigin(httpd_req_t* req, char** originOut);
void httpFreeCORSOrigin(char* origin);

esp_err_t httpSendCORSHeaders(httpd_req_t* req, const char* origin, const char* allowMethods, const char* allowHeaders);

esp_err_t httpGetRequestBody(httpd_req_t* req, GrowableBuffer_t* rawBodyBuffer);
esp_err_t httpGetRequestQueryParams(httpd_req_t* req, size_t maxSize, GrowableBuffer_t* rawQueryParams);

esp_err_t httpSendNotFound(httpd_req_t* req);
esp_err_t httpSendInternalErrorResponse(httpd_req_t* req, esp_err_t err, const char* message);

// Resolves the client address for a request handled by an initialized IoT-Comm server.
// Trusted proxies configured through iotCommInit() may supply X-Forwarded-For.
// Returns false without modifying out when the runtime configuration is unavailable
// or the peer address cannot be determined.
bool httpGetClientIpFromRequest(httpd_req_t* req, IPAddress_t* out);

#ifdef __cplusplus
}
#endif // __cplusplus

// -----------------------------------------------------------------------------

#ifdef __cplusplus
// Returns ESP_OK and sets originOut to an empty string when the Origin header is not present.
esp_err_t httpGetCORSOrigin(httpd_req_t* req, lightstd::string &originOut);
#endif // __cplusplus
