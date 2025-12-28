#include "challenge.h"
#include <esp_log.h>
#include <string.h>
#include <time.h>

static const char* TAG = "Challenge";

// -----------------------------------------------------------------------------

typedef struct SuperChallenge_s {
    ChallengeCookie_t cookie;
    IPAddress_t       clientIP;
    uint64_t          createdAt;
    Challenge_t       challenge;
} SuperChallenge_t;

// -----------------------------------------------------------------------------

static SuperChallenge_t *challenges = nullptr;
static size_t maxChallengesCount = 0;
static uint32_t windowSizeInMs = 0;

// -----------------------------------------------------------------------------

esp_err_t challengesInit(size_t _maxChallengesCount, uint32_t _windowSizeInMs)
{
    assert(_maxChallengesCount > 0);
    assert(_windowSizeInMs > 0);

    challenges = (SuperChallenge_t *)malloc(_maxChallengesCount * sizeof(SuperChallenge_t));
    if (!challenges) {
        ESP_LOGE(TAG, "Unable to allocate memory for challenges.");
        return ESP_ERR_NO_MEM;
    }
    memset(challenges, 0, _maxChallengesCount * sizeof(SuperChallenge_t));

    maxChallengesCount = _maxChallengesCount;
    windowSizeInMs = _windowSizeInMs;

    // Done
    return ESP_OK;
}

void challengesDone()
{
    if (challenges) {
        memset(challenges, 0, maxChallengesCount * sizeof(SuperChallenge_t));
        free(challenges);
        challenges = nullptr;
    }
    maxChallengesCount = 0;
    windowSizeInMs = 0;
}

void challengesAdd(const ChallengeCookie_t cookie, const IPAddress_t *addr, Challenge_t *challenge)
{
    uint64_t now = now_ms();
    uint64_t oldestSlotTime;
    size_t i, oldest;

    if (now == 0) {
        now = 1;
    }

    // First try to find existing slot for this IP (replace old nonce)
    for (i = 0; i < maxChallengesCount; i++) {
        if (ipAddressEqual(&challenges[i].clientIP, addr)) {
            memcpy(challenges[i].cookie, cookie, sizeof(ChallengeCookie_t));
            memcpy(&challenges[i].challenge, challenge, sizeof(Challenge_t));
            challenges[i].createdAt = now;
            return;
        }
    }

    // Find empty or expired slot
    for (i = 0; i < maxChallengesCount; i++) {
        if (challenges[i].createdAt == 0 || now - challenges[i].createdAt > windowSizeInMs) {
            memcpy(&challenges[i].clientIP, addr, sizeof(IPAddress_t));
            memcpy(challenges[i].cookie, cookie, sizeof(ChallengeCookie_t));
            memcpy(&challenges[i].challenge, challenge, sizeof(Challenge_t));
            challenges[i].createdAt = now;
            return;
        }
    }

    // If still no slot, replace oldest
    oldest = 0;
    oldestSlotTime = challenges[0].createdAt;
    for (i = 1; i < maxChallengesCount; i++) {
        if (challenges[i].createdAt < oldestSlotTime) {
            oldest = i;
            oldestSlotTime = challenges[i].createdAt;
        }
    }

    memcpy(&challenges[oldest].clientIP, addr, sizeof(IPAddress_t));
    memcpy(challenges[oldest].cookie, cookie, sizeof(ChallengeCookie_t));
    memcpy(&challenges[oldest].challenge, challenge, sizeof(Challenge_t));
    challenges[oldest].createdAt = now;
}

void challengesRemove(const ChallengeCookie_t cookie)
{
    for (size_t i = 0; i < maxChallengesCount; i++) {
        if (challenges[i].createdAt != 0 &&
            constantTimeCompare(challenges[i].cookie, cookie, sizeof(ChallengeCookie_t))
        ) {
            memset(&challenges[i], 0, sizeof(SuperChallenge_t));
            break;
        }
    }
}

void challengesRemoveAll()
{
    memset(challenges, 0, maxChallengesCount * sizeof(SuperChallenge_t));
}

Challenge_t* challengesFind(const ChallengeCookie_t cookie, const IPAddress_t *addr)
{
    uint64_t now = now_ms();

    for (size_t i = 0; i < maxChallengesCount; i++) {
        if (challenges[i].createdAt != 0 &&
            constantTimeCompare(challenges[i].cookie, cookie, sizeof(ChallengeCookie_t)) &&
            ipAddressEqual(&challenges[i].clientIP, addr) &&
            now - challenges[i].createdAt < windowSizeInMs
        ) {
            return &challenges[i].challenge;
        }
    }
    return nullptr;
}
