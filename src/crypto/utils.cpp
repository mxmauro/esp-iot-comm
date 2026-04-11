#include "iot_comm/crypto/utils.h"
#include <assert.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mutex.h>
#include <string.h>
#include <task.h>

#if ESP_IDF_VERSION_MAJOR >= 6
    #include <psa/crypto.h>
#else
    #include <mbedtls/ctr_drbg.h>
    #include <mbedtls/entropy.h>
#endif

static const char* TAG = "Crypto-Utils";

// -----------------------------------------------------------------------------

static Mutex initMtx;
static bool initialized = false;

#if ESP_IDF_VERSION_MAJOR < 6
static mbedtls_entropy_context entropyCtx;
static mbedtls_ctr_drbg_context ctrDrbgCtx;
#endif

// -----------------------------------------------------------------------------

static esp_err_t init();
#if ESP_IDF_VERSION_MAJOR < 6
static void initTask(Task_t *task, void *arg);
#endif

// -----------------------------------------------------------------------------

esp_err_t randomize(uint8_t *dest, size_t destLen)
{
    esp_err_t err;

    assert(dest);

    err = init();
    if (err == ESP_OK && destLen > 0) {
#if ESP_IDF_VERSION_MAJOR >= 6
        err = psa_generate_random(dest, destLen);
#else
        err = mbedtls_ctr_drbg_random(&ctrDrbgCtx, dest, destLen);
#endif
    }
    return err;
}

bool constantTimeCompare(const void *buf1, const void *buf2, size_t len)
{
    const uint8_t *b1 = (const uint8_t *)buf1;
    const uint8_t *b2 = (const uint8_t *)buf2;
    uint8_t diff = 0;

    while (len > 0) {
        diff |= (*b1) ^ (*b2);
        b1 += 1;
        b2 += 1;
        len -= 1;
    }
    return !!(diff == 0);
}

// -----------------------------------------------------------------------------

static esp_err_t init()
{
    AutoMutex lock(initMtx);

    if (!initialized) {
#if ESP_IDF_VERSION_MAJOR >= 6
        psa_status_t status;
#else
        Task_t task;
        esp_err_t err, taskErr;
#endif

#if ESP_IDF_VERSION_MAJOR >= 6
        status = psa_crypto_init();
        if (status != PSA_SUCCESS && status != PSA_ERROR_BAD_STATE) {
            ESP_LOGE(TAG, "Failed to initialize PSA Crypto. Error: %d.", status);
            return status;
        }
#else
        taskInit(&task);
        taskErr = ESP_FAIL;
        err = taskCreate(&task, initTask, "rand-init", 3072, &taskErr, uxTaskPriorityGet(nullptr) + 1, tskNO_AFFINITY);
        if (err == ESP_OK) {
            taskJoin(&task);
            err = taskErr;
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to seed the random number generator. Error: %d.", err);
            return err;
        }
#endif

        initialized = true;
    }

    // Done
    return ESP_OK;
}

#if ESP_IDF_VERSION_MAJOR < 6
static void initTask(Task_t *task, void *arg)
{
    esp_err_t *err = (esp_err_t *)arg;
    char pers[10 + 20 + 1];

    taskSignalContinue(task);

    mbedtls_entropy_init(&entropyCtx);
    mbedtls_ctr_drbg_init(&ctrDrbgCtx);

    snprintf(pers, sizeof(pers), "iotcomm%llu", esp_timer_get_time());
    *err = mbedtls_ctr_drbg_seed(&ctrDrbgCtx, mbedtls_entropy_func, &entropyCtx, (const unsigned char*)pers, strlen(pers));
    if (*err != ESP_OK) {
        mbedtls_ctr_drbg_free(&ctrDrbgCtx);
        mbedtls_entropy_free(&entropyCtx);
    }
}
#endif
