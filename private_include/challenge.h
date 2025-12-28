
#pragma once

#include "iot_comm/crypto/p256.h"
#include "ip_address.h"
#include <esp_err.h>

#define CHALLENGE_COOKIE_SIZE 12
#define CHALLENGE_NONCE_SIZE  16

// -----------------------------------------------------------------------------

typedef uint8_t ChallengeCookie_t[CHALLENGE_COOKIE_SIZE];
typedef uint8_t ChallengeNonce_t[CHALLENGE_NONCE_SIZE];

typedef struct Challenge_s {
    uint32_t userId;
    bool verified;
    ChallengeNonce_t serverNonce;
    ChallengeNonce_t clientNonce;
    ChallengeNonce_t wsNonce;
    uint8_t ecdhServerPublicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t ecdhServerPrivateKey[P256_PRIVATE_KEY_SIZE];
    uint8_t ecdhClientPublicKey[P256_PUBLIC_KEY_SIZE];
} Challenge_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

esp_err_t challengesInit(size_t maxChallengesCount, uint32_t windowSizeInMs);
void challengesDone();

void challengesAdd(const ChallengeCookie_t cookie, const IPAddress_t *addr, Challenge_t *challenge);
void challengesRemove(const ChallengeCookie_t cookie);
void challengesRemoveAll();

Challenge_t* challengesFind(const ChallengeCookie_t cookie, const IPAddress_t *addr);

#ifdef __cplusplus
}
#endif // __cplusplus
