#include "http_helpers.h"
#include <lwip/sockets.h>

// -----------------------------------------------------------------------------

static bool getIpFromPeer(int sockfd, IPAddress_t *out);

// -----------------------------------------------------------------------------

esp_err_t httpSendDefaultCORS(httpd_req_t *req)
{
    esp_err_t err;

    assert(req);

    // NOTE: No need to save values until response is sent because they are constant values.
    err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Vary", "Origin");
    }
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    }
    return err;
}

esp_err_t httpSendPreflightResponse(httpd_req_t *req)
{
    esp_err_t err;

    assert(req);

    err = httpd_resp_set_status(req, "204 No Content");
    if (err == ESP_OK) {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
        if (err == ESP_OK) {
            err = httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            if (err == ESP_OK) {
                err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers",
                                         "Content-Type, Authorization");
                if (err == ESP_OK) {
                    err = httpd_resp_send(req, nullptr, 0);
                }
            }
        }
    }

    // Done
    return err;
}

esp_err_t httpGetRequestBody(GrowableBuffer_t *rawBodyBuffer, httpd_req_t *req)
{
    char *rawBody;
    size_t curLen;
    int received;

    gbReset(rawBodyBuffer, false);
    rawBody = (char *)gbReserve(rawBodyBuffer, req->content_len + 1);
    if (!rawBody) {
        return ESP_ERR_NO_MEM;
    }

    for (curLen = 0; curLen < req->content_len; curLen += (size_t)received) {
        received = httpd_req_recv(req, rawBody + curLen, req->content_len - curLen);
        if (received <= 0) {
            return ESP_FAIL;
        }
    }
    rawBody[req->content_len] = 0;

    // Done
    return ESP_OK;
}

esp_err_t httpGetRequestQueryParams(GrowableBuffer_t *rawQueryParams, httpd_req_t *req, size_t maxSize)
{
    char *rawQuery;
    size_t queryLen;
    esp_err_t err;

    queryLen = httpd_req_get_url_query_len(req);
    if (queryLen > maxSize) {
        return ESP_ERR_INVALID_SIZE;
    }

    gbReset(rawQueryParams, false);
    rawQuery = (char *)gbReserve(rawQueryParams, queryLen + 1);
    if (!rawQuery) {
        return ESP_ERR_NO_MEM;
    }

    if (queryLen > 1) {
        err = httpd_req_get_url_query_str(req, rawQuery, queryLen + 1);
        if (err != ESP_OK) {
            return err;
        }
    }
    rawQuery[queryLen] = 0;

    // Done
    return ESP_OK;
}

esp_err_t httpSendNotFound(httpd_req_t *req)
{
    return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
}

esp_err_t httpSendInternalErrorResponse(httpd_req_t *req, esp_err_t err, const char *message)
{
    if (err != ESP_OK) {
        switch (err) {
            case ESP_ERR_NO_MEM:
                message = "Failed to allocate memory";
                break;

            default:
                if (!message) {
                    message = "Unexpected error";
                }
                break;
        }
        err = httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, message);
    }
    return err;
}

bool httpGetClientIpFromRequest(httpd_req_t *req, IPAddress_t *out)
{
    char hdr[256];
    size_t len;
    esp_err_t err;

    assert(req);
    assert(out);

    err = httpd_req_get_hdr_value_str(req, "Forwarded", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        hdr[sizeof(hdr) - 1] = '\0';

        const char *p = hdr;
        const char *pEnd = hdr + sizeof(hdr);
        while (p < pEnd && (p = strcasestr(p, "for=")) != nullptr) {
            p += 4; // skip "for="

            len = 0;
            while (p[len] != 0 && p[len] != ',' && p + len < pEnd - 1) {
                len++;
            }

            if (parseIP(out, p, len)) {
                return true;
            }

            p += len;
        }
    }

    err = httpd_req_get_hdr_value_str(req, "X-Forwarded-For", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        len = 0;
        while (hdr[len] != 0 && hdr[len] != ',' && len < sizeof(hdr) - 1) {
            len++;
        }

        if (parseIP(out, hdr, len)) {
            return true;
        }
    }

    err = httpd_req_get_hdr_value_str(req, "X-Real-IP", hdr, sizeof(hdr));
    if (err == ESP_OK && hdr[0] != 0) {
        hdr[sizeof(hdr) - 1] = '\0';
        if (parseIP(out, hdr)) {
            return true;
        }
    }

    if (getIpFromPeer(httpd_req_to_sockfd(req), out)) {
        return true;
    }

    // We were unable to determine the IP
    return false;
}

// -----------------------------------------------------------------------------

static bool getIpFromPeer(int sockfd, IPAddress_t *out)
{
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);

    if (getpeername(sockfd, (struct sockaddr *)&addr, &addrLen) == 0) {
        switch (addr.ss_family) {
            case AF_INET:
                parseIPv4(out, (const struct sockaddr_in *)&addr);
                return true;

            case AF_INET6:
                parseIPv6(out, (const struct sockaddr_in6 *)&addr);
                return true;
        }
    }
    return false;
}
