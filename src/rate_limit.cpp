#include "rate_limit.h"
#include <esp_log.h>
#include <string.h>
#include <time.h>

static const char* TAG = "RateLimit";

// -----------------------------------------------------------------------------

typedef struct RateLimit_s {
    IPAddress_t clientIP;
    uint64_t    windowStart; // If zero, means empty slot
    uint64_t    blockedUntil;
    uint8_t     requestsCount;
    uint8_t     consecutiveFailures;
} RateLimit_t;

// -----------------------------------------------------------------------------

static RateLimit_t *rateLimits = nullptr;
static size_t maxSlots = 0;
static uint32_t windowSizeInMs = 0;
static uint8_t maxRequestsPerWindow = 0;
static uint8_t maxConsecutiveFailures = 0;

// -----------------------------------------------------------------------------

static RateLimit_t* findAddress(const IPAddress_t *addr);
static RateLimit_t* internalRateLimitCheck(const IPAddress_t *addr);

// -----------------------------------------------------------------------------

esp_err_t rateLimitInit(size_t _maxSlots, uint32_t _windowSizeInMs, uint8_t _maxRequestsPerWindow,
                        uint8_t _maxConsecutiveFailures)
{
    assert(_windowSizeInMs > 0);
    assert(_maxSlots > 0);
    assert(_maxRequestsPerWindow > 1);
    assert(_maxConsecutiveFailures > 1);

    rateLimits = (RateLimit_t *)malloc(_maxSlots * sizeof(RateLimit_t));
    if (!rateLimits) {
        ESP_LOGE(TAG, "Unable to allocate memory for rate limits.");
        return ESP_ERR_NO_MEM;
    }
    memset(rateLimits, 0, _maxSlots * sizeof(RateLimit_t));

    maxSlots = _maxSlots;
    windowSizeInMs = _windowSizeInMs;
    maxRequestsPerWindow = _maxRequestsPerWindow;
    maxConsecutiveFailures = _maxConsecutiveFailures;

    // Done
    return ESP_OK;
}

void rateLimitDone()
{
    if (rateLimits) {
        memset(rateLimits, 0, maxSlots * sizeof(RateLimit_t));
        free(rateLimits);
        rateLimits = nullptr;
    }

    maxSlots = 0;
    windowSizeInMs = 0;
    maxRequestsPerWindow = 0;
    maxConsecutiveFailures = 0;
}

bool rateLimitCheckRequest(const IPAddress_t *addr)
{
    RateLimit_t* limit = internalRateLimitCheck(addr);

    // Check limits
    if ((!limit) || limit->requestsCount >= maxRequestsPerWindow) {
        return false;
    }
    limit->requestsCount += 1;
    return true;
}

void rateLimitIncrementFailedAuth(const IPAddress_t *addr)
{
    RateLimit_t* limit;

    // Find rate limit entry
    limit = findAddress(addr);
    if (!limit) {
        return;
    }

    // Exponential backoff after MAX_CONSECUTIVE_FAILURES
    if (limit->consecutiveFailures < 255) {
        limit->consecutiveFailures += 1;
    }
    if (limit->consecutiveFailures >= maxConsecutiveFailures) {
        uint64_t now;
        uint8_t exponent;
        uint64_t backoffSeconds;

        now = now_ms();

        // Calculate backoff time: 2^(failures - threshold + 1) seconds
        // failures=3: 2^1 = 2 seconds
        // failures=4: 2^2 = 4 seconds
        // failures=5: 2^3 = 8 seconds
        // failures=6: 2^4 = 16 seconds
        // failures=7: 2^5 = 32 seconds
        // failures=8: 2^6 = 64 seconds
        // Cap at 5 minutes (300 seconds)
        exponent = limit->consecutiveFailures - maxConsecutiveFailures + 1;
        backoffSeconds = 1UL << exponent; // 2^exponent

        // Cap maximum backoff at 5 minutes
        if (backoffSeconds > 300) {
            backoffSeconds = 300;
        }

        limit->blockedUntil = now + (backoffSeconds * 1000);
    }
}

bool rateLimitIsAddressBlocked(const IPAddress_t *addr)
{
    RateLimit_t* limit;
    uint64_t now;

    // Find rate limit entry
    limit = findAddress(addr);
    if (!limit) {
        return false;
    }

    now = now_ms();
    return !!(limit->blockedUntil > 0 && now < limit->blockedUntil);
}

void rateLimitResetAddress(const IPAddress_t *addr)
{
    RateLimit_t* limit;

    // Find rate limit entry
    limit = findAddress(addr);
    if (limit) {
        limit->requestsCount = 0;
        limit->consecutiveFailures = 0;
        limit->blockedUntil = 0;
    }
}

void rateLimitResetAll()
{
    memset(rateLimits, 0, maxSlots * sizeof(RateLimit_t));
}

// -----------------------------------------------------------------------------

static RateLimit_t* findAddress(const IPAddress_t *addr)
{
    for (size_t i = 0; i < maxSlots; i++) {
        if (rateLimits[i].windowStart != 0 && ipAddressEqual(&rateLimits[i].clientIP, addr)) {
            return &rateLimits[i];
        }
    }
    return nullptr;
}

static RateLimit_t* internalRateLimitCheck(const IPAddress_t *addr)
{
    RateLimit_t* limit = nullptr;
    size_t emptySlot = (size_t)-1;
    uint32_t oldestSlot = 0;
    uint64_t oldestSlotTime = 0;
    uint64_t now = now_ms();

    if (now == 0) {
        now = 1;
    }

    // Find or create rate limit entry
    for (size_t i = 0; i < maxSlots; i++) {
        if (rateLimits[i].windowStart != 0 && ipAddressEqual(&rateLimits[i].clientIP, addr)) {
            limit = &rateLimits[i];
            break;
        }
        if (emptySlot == -1) {
            if (rateLimits[i].windowStart == 0 || now - rateLimits[i].windowStart > windowSizeInMs) {
                emptySlot = i;
            }
            else if (oldestSlot == -1 || rateLimits[i].windowStart < oldestSlotTime) {
                oldestSlot = i;
                oldestSlotTime = rateLimits[i].windowStart;
            }
        }
    }

    // Create new entry if needed
    if (limit == nullptr) {
        if (emptySlot == (size_t)-1) {
            emptySlot = oldestSlot;
        }
        limit = &rateLimits[emptySlot];
        memcpy(&limit->clientIP, addr, sizeof(IPAddress_t));
        limit->requestsCount = 0;
        limit->windowStart = now;
        limit->blockedUntil = 0;
        limit->consecutiveFailures = 0;
    }

    // Check if IP is currently blocked (exponential backoff)
    if (limit->blockedUntil > 0 && now < limit->blockedUntil) {
        return nullptr;
    }

    // Reset window if expired
    if (now - limit->windowStart > windowSizeInMs) {
        limit->requestsCount = 0;
        limit->windowStart = now;
        limit->blockedUntil = 0;
        // We don't reset consecutive failures
    }

    // Done
    return limit;
}
