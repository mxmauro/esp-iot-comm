#include "iot_comm/ota/ota.h"
#include <esp_app_desc.h>
#include <esp_log.h>
#include <esp_ota_ops.h>
#include <inttypes.h>

static const char *TAG = "OTA";

// -----------------------------------------------------------------------------

static bool isActive = false;
static esp_ota_handle_t handle = 0;
static const esp_partition_t *updatePartition = nullptr;
static size_t imageSize = 0;
static size_t writtenSize = 0;

// -----------------------------------------------------------------------------

esp_err_t otaBegin(uint32_t _imageSize)
{
    esp_err_t err;

    if (isActive) {
        ESP_LOGW(TAG, "An update is already in progress.");
        return ESP_FAIL;
    }

    updatePartition = esp_ota_get_next_update_partition(nullptr);
    if (!updatePartition) {
        ESP_LOGE(TAG, "No update partition is available.");
        return ESP_FAIL;
    }

    if (_imageSize > static_cast<size_t>(updatePartition->size)) {
        ESP_LOGE(TAG, "The image is larger than the update partition.");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Starting update on partition subtype %d at 0x%" PRIX32 ".", updatePartition->subtype, updatePartition->address);

    err = esp_ota_begin(updatePartition, _imageSize, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start the write operation. Error: %d.", err);
        updatePartition = nullptr;
        handle = 0;
        return err;
    }

    isActive = true;
    imageSize = _imageSize;
    writtenSize = 0;

    // Done
    return ESP_OK;
}

esp_err_t otaWrite(const uint8_t *data, size_t len, bool *completed)
{
    const esp_partition_t *_updatePartition;
    esp_err_t err;

    if (!completed) {
        return ESP_ERR_INVALID_ARG;
    }
    *completed = false;

    if (!isActive) {
        ESP_LOGW(TAG, "No update is in progress.");
        return ESP_ERR_INVALID_STATE;
    }

    if ((!data) || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (len > imageSize - writtenSize) {
        ESP_LOGE(TAG, "The write would exceed the expected image size. Written=" PRIuPTR " / Expected=" PRIuPTR " / To write=" PRIuPTR ".",
                 writtenSize, imageSize, len);
        otaCancel();
        return ESP_FAIL;
    }

    err = esp_ota_write(handle, data, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write " PRIuPTR " bytes at offset " PRIuPTR ". Error: %d.", len, writtenSize, err);
        otaCancel();
        return err;
    }

    writtenSize += len;
    if (writtenSize < imageSize) {
        // Done
        ESP_LOGI(TAG, "Written " PRIuPTR " of " PRIuPTR " bytes.", writtenSize, imageSize);
        return ESP_OK;
    }

    *completed = true;

    err = esp_ota_end(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to finalize the image. Error: %d.", err);
        otaCancel();
        return err;
    }

    handle = 0;
    _updatePartition = updatePartition;
    updatePartition = nullptr;
    writtenSize = 0;
    imageSize = 0;
    isActive = false;

    err = esp_ota_set_boot_partition(_updatePartition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to select the new boot partition. Error: %d.", err);
        return err;
    }

    // Done
    ESP_LOGI(TAG, "The image was written successfully.");
    return ESP_OK;
}

void otaCancel()
{
    if (handle) {
        ESP_LOGW(TAG, "Aborting the update.");
        esp_ota_abort(handle);
        handle = 0;
    }
    updatePartition = nullptr;
    isActive = false;
    imageSize = 0;
    writtenSize = 0;
}

esp_err_t otaVerifyAndConfirmNewFirmware(OtaFirmwareCheckCallback_t cb, void *ctx, bool *mustReboot)
{
    const esp_partition_t *runningPartition;
    esp_ota_img_states_t state;
    bool valid;
    esp_err_t err;

    if (!mustReboot) {
        return ESP_ERR_INVALID_ARG;
    }
    *mustReboot = false;
    if (!cb) {
        return ESP_ERR_INVALID_ARG;
    }

    runningPartition = esp_ota_get_running_partition();
    err = esp_ota_get_state_partition(runningPartition, &state);
    if (err != ESP_OK || state != ESP_OTA_IMG_PENDING_VERIFY) {
        return ESP_OK;
    }

    valid = cb(ctx);
    if (valid) {
        err = esp_ota_mark_app_valid_cancel_rollback();
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Marked the image as valid.");
        }
        else {
            ESP_LOGE(TAG, "Failed to mark the image as valid. Error: %d.", err);
            goto rollback;
        }
    } else {
rollback:

        err = esp_ota_mark_app_invalid_rollback();
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Firmware validation failed; rollback was started successfully.");
        }
        else {
            ESP_LOGE(TAG, "Firmware validation failed and rollback could not be started. Error: %d.", err);
        }
    }

    // Done
    if (err == ESP_OK) {
        *mustReboot = true;
    }
    return err;
}
