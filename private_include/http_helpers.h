#pragma once

#include "sdkconfig.h"
#include "iot_comm/utils/network.h"
#include <esp_err.h>
#include <esp_http_server.h>
#include <growable_buffer.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t httpSendDefaultCORS(httpd_req_t *req);
esp_err_t httpSendPreflightResponse(httpd_req_t *req);

esp_err_t httpGetRequestBody(GrowableBuffer_t *rawBodyBuffer, httpd_req_t *req);
esp_err_t httpGetRequestQueryParams(GrowableBuffer_t *rawQueryParams, httpd_req_t *req, size_t maxSize = 1024);

esp_err_t httpSendNotFound(httpd_req_t *req);
esp_err_t httpSendInternalErrorResponse(httpd_req_t *req, esp_err_t err, const char *message);

bool httpGetClientIpFromRequest(httpd_req_t *req, IPAddress_t *out);

#ifdef __cplusplus
}
#endif // __cplusplus
