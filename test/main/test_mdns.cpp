#include <unity.h>
#include <iot_comm/mDNS/mDNS.h>

// -----------------------------------------------------------------------------

TEST_CASE("mDnsIsValidHostname accepts valid hostnames", "[mdns]")
{
    TEST_ASSERT_TRUE(mDnsIsValidHostname("device"));
    TEST_ASSERT_TRUE(mDnsIsValidHostname("device-01"));
    TEST_ASSERT_TRUE(mDnsIsValidHostname("sensor.hallway"));
    TEST_ASSERT_TRUE(mDnsIsValidHostname("sensor.hallway.local."));
    TEST_ASSERT_TRUE(mDnsIsValidHostname("a"));
}

TEST_CASE("mDnsIsValidHostname rejects invalid hostnames", "[mdns]")
{
    TEST_ASSERT_FALSE(mDnsIsValidHostname(nullptr));
    TEST_ASSERT_FALSE(mDnsIsValidHostname(""));
    TEST_ASSERT_FALSE(mDnsIsValidHostname("-device"));
    TEST_ASSERT_FALSE(mDnsIsValidHostname("device-"));
    TEST_ASSERT_FALSE(mDnsIsValidHostname("device..local"));
    TEST_ASSERT_FALSE(mDnsIsValidHostname("device_.local"));
    TEST_ASSERT_FALSE(mDnsIsValidHostname(".device"));
}
