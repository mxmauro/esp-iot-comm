#include <unity.h>
#include <iot_comm/iot_comm.h>
#include "../../private_include/http_helpers.h"

// -----------------------------------------------------------------------------

TEST_CASE("iotCommDefaultConfig returns expected defaults", "[iot_comm]")
{
    IotCommConfig_t cfg = iotCommDefaultConfig();

    TEST_ASSERT_EQUAL_UINT32(IOTCOMM_DEFAULT_MAX_USERS_COUNT, cfg.maxUsersCount);

    TEST_ASSERT_EQUAL_UINT32(IOTCOMM_DEFAULT_MAX_RATE_LIMIT_SLOTS, cfg.rateLimit.maxSlots);
    TEST_ASSERT_EQUAL_UINT32(IOTCOMM_DEFAULT_RATE_LIMIT_WINDOW_TIME_MS, cfg.rateLimit.windowSizeInMs);
    TEST_ASSERT_EQUAL_UINT8(IOTCOMM_DEFAULT_MAX_RATE_LIMIT_REQUESTS_COUNT, cfg.rateLimit.maxRequestsPerWindow);
    TEST_ASSERT_EQUAL_UINT8(IOTCOMM_DEFAULT_MAX_RATE_LIMIT_CONSECUTIVE_FAILURES, cfg.rateLimit.maxConsecutiveAuthFailures);

    TEST_ASSERT_EQUAL_UINT32(IOTCOMM_DEFAULT_MAX_CHALLENGES_SLOTS, cfg.challenge.maxSlots);
    TEST_ASSERT_EQUAL_UINT32(IOTCOMM_DEFAULT_CHALLENGE_WINDOW_TIME_MS, cfg.challenge.windowSizeInMs);

    TEST_ASSERT_NULL(cfg.rootKey.cb);
    TEST_ASSERT_NULL(cfg.rootKey.ctx);
    TEST_ASSERT_NULL(cfg.storage.load);
    TEST_ASSERT_NULL(cfg.storage.save);
    TEST_ASSERT_NULL(cfg.storage.ctx);
    TEST_ASSERT_NULL(cfg.handler);
    TEST_ASSERT_NULL(cfg.handlerCtx);
    TEST_ASSERT_NULL(cfg.proxy.trustedProxies);
    TEST_ASSERT_EQUAL_UINT32(0, cfg.proxy.trustedProxiesCount);

    TEST_ASSERT_EQUAL_INT(IotCommStorageItemTypeUsers, 1);
    TEST_ASSERT_EQUAL_INT(IotCommStorageItemTypeDeviceIdentityKeyPair, 2);
}

TEST_CASE("trusted proxy rules validate CIDRs and resolve X-Forwarded-For", "[iot_comm]")
{
    IotCommTrustedProxy_t trustedProxy = {};
    IPAddress_t trustedAddress = {};
    IPAddress_t untrustedAddress = {};
    IPAddress_t clientAddress = {};

    TEST_ASSERT_TRUE(parseIP(&trustedProxy.network, "10.0.0.0"));
    trustedProxy.prefixLength = 8;
    TEST_ASSERT_TRUE(httpValidateTrustedProxy(&trustedProxy));
    TEST_ASSERT_TRUE(parseIP(&trustedAddress, "10.1.2.3"));
    TEST_ASSERT_TRUE(httpIsTrustedProxy(&trustedAddress, &trustedProxy, 1));
    TEST_ASSERT_TRUE(parseIP(&untrustedAddress, "192.0.2.1"));
    TEST_ASSERT_FALSE(httpIsTrustedProxy(&untrustedAddress, &trustedProxy, 1));

    TEST_ASSERT_TRUE(httpSelectClientIpFromXForwardedFor("198.51.100.4, 10.1.2.3", &trustedProxy, 1, &clientAddress));
    TEST_ASSERT_TRUE(parseIP(&untrustedAddress, "198.51.100.4"));
    TEST_ASSERT_TRUE(ipAddressEqual(&clientAddress, &untrustedAddress));
    TEST_ASSERT_FALSE(httpSelectClientIpFromXForwardedFor("198.51.100.4, invalid", &trustedProxy, 1, &clientAddress));

    TEST_ASSERT_TRUE(parseIP(&trustedProxy.network, "10.0.0.1"));
    TEST_ASSERT_FALSE(httpValidateTrustedProxy(&trustedProxy));
}

TEST_CASE("iotCommDefaultServerConfig returns expected defaults", "[iot_comm]")
{
    IotCommServerConfig_t cfg = iotCommDefaultServerConfig();

    TEST_ASSERT_EQUAL_UINT16(80, cfg.listenPort);
    TEST_ASSERT_EQUAL_UINT16(0, cfg.udpListenPort);
    TEST_ASSERT_EQUAL_UINT16(IOTCOMM_DEFAULT_MAX_USERS_COUNT + 2, cfg.maxConnections);
}

TEST_CASE("iotCommGetDeviceIdentityPublicKey requires initialized runtime", "[iot_comm]")
{
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, iotCommGetDeviceIdentityPublicKey(publicKey));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, iotCommGetDeviceIdentityPublicKey(nullptr));
}
