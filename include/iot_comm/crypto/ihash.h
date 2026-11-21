#pragma once

#include <esp_err.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

#ifdef __cplusplus

class IHash
{
public:
    IHash() noexcept = default;
    IHash(const IHash&) noexcept = delete;
    IHash(IHash&&) noexcept = delete;

    virtual ~IHash() noexcept
    {
    }

    IHash& operator=(const IHash&) noexcept = delete;
    IHash& operator=(IHash&&) noexcept = delete;

    virtual esp_err_t Start() noexcept = 0;
    virtual esp_err_t Update(const uint8_t* data, size_t len) noexcept = 0;
    virtual esp_err_t Finish() noexcept = 0;

    virtual const uint8_t* Output() const noexcept = 0;
    virtual size_t OutputSize() const noexcept = 0;
};

#endif // __cplusplus
