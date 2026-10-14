#include "http_helpers.h"
#include <lwip/sockets.h>

// -----------------------------------------------------------------------------

static bool getIpFromPeer(int sockfd, IPAddress_t* out);

// -----------------------------------------------------------------------------

esp_err_t httpGetCORSOrigin(httpd_req_t* req, char** originOut)
{
    size_t originLen;
    char* origin;
    esp_err_t err;

    assert(req);
    assert(originOut);

    *originOut = nullptr;

    originLen = httpd_req_get_hdr_value_len(req, "Origin");
    if (originLen == 0)
    {
        return ESP_OK;
    }

    origin = static_cast<char*>(malloc(originLen + 1));
    if (!origin)
    {
        return ESP_ERR_NO_MEM;
    }

    err = httpd_req_get_hdr_value_str(req, "Origin", origin, originLen + 1);
    if (err != ESP_OK)
    {
        memset(origin, 0, originLen + 1);
        free(origin);
        return err;
    }

    *originOut = origin;
    return ESP_OK;
}

void httpFreeCORSOrigin(char* origin)
{
    if (origin)
    {
        memset(origin, 0, strlen(origin));
        free(origin);
    }
}

esp_err_t httpSendDefaultCORS(httpd_req_t* req, const char* origin)
{
    esp_err_t err;

    assert(req);

    err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", (origin && *origin != 0) ? origin : "*");
    if (err == ESP_OK)
    {
        err = httpd_resp_set_hdr(req, "Vary", "Origin");
    }
    if (err == ESP_OK)
    {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    }
    return err;
}

esp_err_t httpSendPreflightResponse(httpd_req_t* req, const char* origin)
{
    esp_err_t err;

    assert(req);

    err = httpd_resp_set_status(req, "204 No Content");
    if (err == ESP_OK)
    {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", (origin && *origin != 0) ? origin : "*");
    }
    if (err == ESP_OK)
    {
        err = httpd_resp_set_hdr(req, "Vary", "Origin");
    }
    if (err == ESP_OK)
    {
        err = httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        if (err == ESP_OK)
        {
            err = httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
            if (err == ESP_OK)
            {
                err = httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Authorization");
                if (err == ESP_OK)
                {
                    err = httpd_resp_send(req, nullptr, 0);
                }
            }
        }
    }

    // Done
    return err;
}

esp_err_t httpGetRequestBody(GrowableBuffer_t* rawBodyBuffer, httpd_req_t* req)
{
    gbReset(rawBodyBuffer, false);
    if (req->content_len > 0)
    {
        char* rawBody;
        size_t curLen;
        int received;

        rawBody = static_cast<char*>(gbReserve(rawBodyBuffer, req->content_len));
        if (!rawBody)
        {
            return ESP_ERR_NO_MEM;
        }

        for (curLen = 0; curLen < req->content_len; curLen += static_cast<size_t>(received))
        {
            received = httpd_req_recv(req, rawBody + curLen, req->content_len - curLen);
            if (received <= 0)
            {
                return ESP_FAIL;
            }
        }
    }

    // Done
    return ESP_OK;
}

esp_err_t httpGetRequestQueryParams(GrowableBuffer_t* rawQueryParams, httpd_req_t* req, size_t maxSize)
{
    char* rawQuery;
    size_t queryLen;
    esp_err_t err;

    queryLen = httpd_req_get_url_query_len(req);
    if (queryLen > maxSize)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    gbReset(rawQueryParams, false);
    rawQuery = static_cast<char*>(gbReserve(rawQueryParams, queryLen + 1));
    if (!rawQuery)
    {
        return ESP_ERR_NO_MEM;
    }

    if (queryLen > 1)
    {
        err = httpd_req_get_url_query_str(req, rawQuery, queryLen + 1);
        if (err != ESP_OK)
        {
            return err;
        }
    }
    rawQuery[queryLen] = 0;

    // Done
    return ESP_OK;
}

esp_err_t httpSendNotFound(httpd_req_t* req)
{
    return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
}

esp_err_t httpSendInternalErrorResponse(httpd_req_t* req, esp_err_t err, const char* message)
{
    if (err != ESP_OK)
    {
        char msgHolder[40];

        switch (err)
        {
            case ESP_ERR_NO_MEM:
                message = "Failed to allocate memory";
                break;

            default:
                if ((!message) || *message == 0)
                {
                    snprintf(msgHolder, sizeof(msgHolder), "Unexpected error %d", err);
                    message = msgHolder;
                }
                break;
        }
        err = httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, message);
    }
    return err;
}

bool httpValidateTrustedProxy(const IotCommTrustedProxy_t* proxy)
{
    size_t addressLen;
    size_t firstHostByte;

    if (!proxy)
    {
        return false;
    }
    addressLen = proxy->network.isIPv6 ? 16 : 4;
    if (proxy->prefixLength > addressLen * 8)
    {
        return false;
    }

    firstHostByte = proxy->prefixLength / 8;
    if (proxy->prefixLength % 8 != 0)
    {
        uint8_t hostMask = static_cast<uint8_t>((1U << (8 - (proxy->prefixLength % 8))) - 1U);

        if ((proxy->network.ip[firstHostByte] & hostMask) != 0)
        {
            return false;
        }
        firstHostByte++;
    }
    for (size_t i = firstHostByte; i < addressLen; i++)
    {
        if (proxy->network.ip[i] != 0)
        {
            return false;
        }
    }
    return true;
}

bool httpIsTrustedProxy(const IPAddress_t* addr, const IotCommTrustedProxy_t* trustedProxies, size_t trustedProxiesCount)
{
    if ((!addr) || (!trustedProxies))
    {
        return false;
    }

    for (size_t i = 0; i < trustedProxiesCount; i++)
    {
        const IotCommTrustedProxy_t* proxy = &trustedProxies[i];
        size_t fullBytes;
        uint8_t remainingBits;

        if (!httpValidateTrustedProxy(proxy) || addr->isIPv6 != proxy->network.isIPv6)
        {
            continue;
        }
        fullBytes = proxy->prefixLength / 8;
        remainingBits = proxy->prefixLength % 8;
        if (fullBytes > 0 && memcmp(addr->ip, proxy->network.ip, fullBytes) != 0)
        {
            continue;
        }
        if (remainingBits > 0)
        {
            uint8_t mask = static_cast<uint8_t>(0xFFU << (8 - remainingBits));

            if ((addr->ip[fullBytes] & mask) != (proxy->network.ip[fullBytes] & mask))
            {
                continue;
            }
        }
        return true;
    }
    return false;
}

bool httpSelectClientIpFromXForwardedFor(const char* header, const IotCommTrustedProxy_t* trustedProxies, size_t trustedProxiesCount,
                                         IPAddress_t* out)
{
    const char* tokenEnd;

    if ((!header) || (!out) || ((!trustedProxies) && trustedProxiesCount != 0))
    {
        return false;
    }

    tokenEnd = header + strlen(header);
    while (tokenEnd > header)
    {
        const char* tokenStart = tokenEnd;
        IPAddress_t candidate;

        while (tokenStart > header && *(tokenStart - 1) != ',')
        {
            tokenStart--;
        }
        if (!parseIP(&candidate, tokenStart, static_cast<size_t>(tokenEnd - tokenStart)))
        {
            return false;
        }
        if (!httpIsTrustedProxy(&candidate, trustedProxies, trustedProxiesCount))
        {
            memcpy(out, &candidate, sizeof(candidate));
            return true;
        }
        if (tokenStart == header)
        {
            break;
        }
        tokenEnd = tokenStart - 1;
    }
    return false;
}

bool httpGetClientIpFromRequest(httpd_req_t* req, const IotCommTrustedProxy_t* trustedProxies, size_t trustedProxiesCount,
                                IPAddress_t* out)
{
    IPAddress_t peerAddr;
    char hdr[256];
    esp_err_t err;

    assert(req);
    assert(out);

    if (!getIpFromPeer(httpd_req_to_sockfd(req), &peerAddr))
    {
        return false;
    }
    if (httpIsTrustedProxy(&peerAddr, trustedProxies, trustedProxiesCount))
    {
        err = httpd_req_get_hdr_value_str(req, "X-Forwarded-For", hdr, sizeof(hdr));
        if (err == ESP_OK && hdr[0] != 0 && httpSelectClientIpFromXForwardedFor(hdr, trustedProxies, trustedProxiesCount, out))
        {
            return true;
        }
    }

    memcpy(out, &peerAddr, sizeof(peerAddr));
    return true;
}

// -----------------------------------------------------------------------------

static bool getIpFromPeer(int sockfd, IPAddress_t* out)
{
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);

    if (getpeername(sockfd, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0)
    {
        switch (addr.ss_family)
        {
            case AF_INET:
                parseIPv4(out, reinterpret_cast<const sockaddr_in*>(&addr));
                return true;

            case AF_INET6:
                parseIPv6(out, reinterpret_cast<const sockaddr_in6*>(&addr));
                return true;
        }
    }
    return false;
}
