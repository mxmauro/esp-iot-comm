#include "iot_comm/mDNS/mDNS.h"
#include <convert.h>
#include <ctype.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <mdns.h>
#include <mutex.h>

static const char* TAG = "mDNS";

// -----------------------------------------------------------------------------

static Mutex mtx;
static bool running = false;

// -----------------------------------------------------------------------------

static void generateHostname(char* finalHostname, size_t maxLen, const char* hostname);
static bool isValidHostname(const char *hostname);

// -----------------------------------------------------------------------------

void mDnsInit()
{
    AutoMutex lock(&mtx);

    mdns_free();
    running = false;

    ESP_ERROR_CHECK(mdns_init());

    // Done
    ESP_LOGI(TAG, "Initialized.");
    running = true;
}

void mDnsDone()
{
    AutoMutex lock(&mtx);

    mdns_free();
    running = false;
}

esp_err_t mDnsSetHostname(const char *hostname)
{
    AutoMutex lock(&mtx);
    char finalHostname[256];
    esp_err_t err;

    if (!running) {
        return ESP_ERR_INVALID_STATE;
    }

    // Generate hostname
    generateHostname(finalHostname, sizeof(finalHostname), hostname);
    if (hostname && (!isValidHostname(finalHostname))) {
        return ESP_ERR_INVALID_ARG;
    }

    err = mdns_hostname_set(finalHostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set hostname. Error: %d.", err);
        return err;
    }

    // Done
    ESP_LOGI(TAG, "Hostname: %s.local", finalHostname);
    return ESP_OK;
}

esp_err_t mDnsAddService(const char *service, const char *proto, uint16_t port,
                         const mDnsServiceTxt_t *txtList, size_t txtListCount)
{
    AutoMutex lock(&mtx);
    mdns_txt_item_t *txtItems;
    esp_err_t err;

    if (!running) {
        return ESP_ERR_INVALID_STATE;
    }
    if (service == nullptr || *service == 0 || proto == nullptr || *proto == 0 || port == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (txtList == nullptr && txtListCount > 0) {
        return ESP_ERR_INVALID_ARG;
    }

    txtItems = nullptr;
    if (txtListCount > 0) {
        txtItems = (mdns_txt_item_t *)malloc(txtListCount * sizeof(mdns_txt_item_t));
        if (!txtItems) {
            ESP_LOGE(TAG, "Insufficient memory while populating services.");
            return ESP_ERR_NO_MEM;
        }
        for (size_t txtIndex = 0; txtIndex < txtListCount; txtIndex++) {
            if (txtList[txtIndex].key == nullptr || txtList[txtIndex].key[0] == 0 ||
                txtList[txtIndex].value == nullptr || txtList[txtIndex].value[0] == 0
            ) {
                free(txtItems);
                return ESP_ERR_INVALID_ARG;
            }

            txtItems[txtIndex].key = txtList[txtIndex].key;
            txtItems[txtIndex].value = txtList[txtIndex].value;
        }
    }
    err = mdns_service_add(nullptr, service, proto, port, txtItems, txtListCount);
    if (txtItems) {
        free(txtItems);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add %s service. Error: %d.", service, err);
        return err;
    }

    // Done
    ESP_LOGI(TAG, "Service %s successfully added.", service);
    return ESP_OK;
}

esp_err_t mDnsRemoveService(const char *service, const char *proto)
{
    AutoMutex lock(&mtx);
    esp_err_t err;

    if (!running) {
        return ESP_ERR_INVALID_STATE;
    }
    if (service == nullptr || *service == 0 || proto == nullptr || *proto == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    err = mdns_service_remove(service, proto);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to remove %s service. Error: %d.", service, err);
        return err;
    }

    // Done
    ESP_LOGI(TAG, "Service %s successfully removed.", service);
    return ESP_OK;
}

// -----------------------------------------------------------------------------

static void generateHostname(char* finalHostname, size_t maxLen, const char* hostname)
{
    uint8_t macAddr[6];
    char macAddrHex[12 + 1];
    size_t ofs, toCopy, macAddrHexLen;

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, macAddr));
    if (hostname == nullptr || *hostname == 0) {
        hostname = "mx-iot-$mac";
    }

    maxLen -= 1; // reserve final spcae for trailing \0
    ofs = 0;
    while (ofs < maxLen && *hostname != 0) {
        if (*hostname == '$') {
            if (hostname[1] == 'm' && hostname[2] == 'a' && hostname[3] == 'c') {
                hostname += 4;

                macAddrHexLen = sizeof(macAddrHex);
                toHex(macAddr + 3, 3, macAddrHex, &macAddrHexLen);

                toCopy = 6;
                if (toCopy > maxLen - ofs) {
                    toCopy = maxLen - ofs;
                }
                memcpy(finalHostname + ofs, macAddrHex, toCopy);
                ofs += toCopy;

                continue;
            }

            if (hostname[1] == 'f' && hostname[2] == 'u' && hostname[3] == 'l' && hostname[4] == 'l' &&
                hostname[5] == 'm' && hostname[6] == 'a' && hostname[7] == 'c'
            ) {
                hostname += 8;

                macAddrHexLen = sizeof(macAddrHex);
                toHex(macAddr, 6, macAddrHex, &macAddrHexLen);

                toCopy = 12;
                if (toCopy > maxLen - ofs) {
                    toCopy = maxLen - ofs;
                }
                memcpy(finalHostname + ofs, macAddrHex, toCopy);
                ofs += toCopy;

                continue;
            }
        }

        finalHostname[ofs++] = *hostname++;
    }

    finalHostname[ofs] = 0;
}

static bool isValidHostname(const char *hostname)
{
    size_t i, j;
    size_t len, effectiveLen;
    size_t labelStart, labelLen;
    char ch;

    if ((!hostname) || *hostname == 0) {
        return false;
    }

    len = strlen(hostname);
    if (len > 253) {
        return false;
    }

    // Handle trailing dot (FQDN)
    effectiveLen = (hostname[len - 1] == '.') ? len - 1 : len;

    labelStart = 0;
    labelLen = 0;
    for (i = 0; i <= effectiveLen; i++) {
        ch = (i < effectiveLen) ? hostname[i] : '.';

        if (ch == '.') {
            // End of label - validate it
            if (labelLen == 0 || labelLen > 63) {
                return false;
            }

            // Check first character of label
            if (!isalnum((unsigned char)hostname[labelStart])) {
                return false;
            }

            // Check last character of label
            if (!isalnum((unsigned char)hostname[labelStart + labelLen - 1])) {
                return false;
            }

            // Check all characters in label
            for (j = labelStart; j < labelStart + labelLen; j++) {
                ch = hostname[j];
                if (!isalnum((unsigned char)ch) && ch != '-') {
                    return false;
                }
            }

            // Start next label
            labelStart = i + 1;
            labelLen = 0;
        }
        else {
            labelLen += 1;
        }
    }

    // Done
    return true;
}
