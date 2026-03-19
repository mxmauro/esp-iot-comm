#include <unity.h>
#include <iot_comm/utils/network.h>
#include <lwip/inet.h>

// -----------------------------------------------------------------------------

static void assertIPv4(const IPAddress_t *addr, uint8_t a, uint8_t b, uint8_t c, uint8_t d);
static void assertIPv6Bytes(const IPAddress_t *addr, const uint8_t expected[16]);

// -----------------------------------------------------------------------------

TEST_CASE("parseIPv4 extracts IPv4 octets", "[network]")
{
    struct sockaddr_in in = {};
    IPAddress_t        addr = {};

    TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET, "203.0.113.7", &in.sin_addr));

    parseIPv4(&addr, &in);

    assertIPv4(&addr, 203, 0, 113, 7);
}

TEST_CASE("parseIPv6 extracts IPv6 bytes", "[network]")
{
    struct sockaddr_in6 in = {};
    IPAddress_t         addr = {};
    const uint8_t       expected[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef
    };

    TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET6, "2001:db8::dead:beef", &in.sin6_addr));

    parseIPv6(&addr, &in);

    assertIPv6Bytes(&addr, expected);
}

TEST_CASE("parseIP accepts supported IPv4 and IPv6 formats", "[network]")
{
    IPAddress_t addr = {};
    const uint8_t ipv6Expected[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef
    };

    TEST_ASSERT_TRUE(parseIP(&addr, " 203.0.113.9 "));
    assertIPv4(&addr, 203, 0, 113, 9);

    TEST_ASSERT_TRUE(parseIP(&addr, "\"203.0.113.10:8080\""));
    assertIPv4(&addr, 203, 0, 113, 10);

    TEST_ASSERT_TRUE(parseIP(&addr, "[2001:db8::dead:beef]:443"));
    assertIPv6Bytes(&addr, ipv6Expected);

    TEST_ASSERT_TRUE(parseIP(&addr, "\"2001:db8::dead:beef\""));
    assertIPv6Bytes(&addr, ipv6Expected);
}

TEST_CASE("parseIP rejects invalid address candidates", "[network]")
{
    IPAddress_t addr = {};

    TEST_ASSERT_FALSE(parseIP(&addr, nullptr));
    TEST_ASSERT_FALSE(parseIP(&addr, ""));
    TEST_ASSERT_FALSE(parseIP(&addr, "unknown"));
    TEST_ASSERT_FALSE(parseIP(&addr, "\"  \""));
    TEST_ASSERT_FALSE(parseIP(&addr, "203.0.113.999"));
    TEST_ASSERT_FALSE(parseIP(&addr, "[2001:db8::1"));
}

TEST_CASE("isValidHostname accepts valid hostnames", "[mdns]")
{
    TEST_ASSERT_TRUE(isValidHostname("device"));
    TEST_ASSERT_TRUE(isValidHostname("device-01"));
    TEST_ASSERT_TRUE(isValidHostname("sensor.hallway"));
    TEST_ASSERT_TRUE(isValidHostname("sensor.hallway.local."));
    TEST_ASSERT_TRUE(isValidHostname("a"));
}

TEST_CASE("isValidHostname rejects invalid hostnames", "[mdns]")
{
    TEST_ASSERT_FALSE(isValidHostname(nullptr));
    TEST_ASSERT_FALSE(isValidHostname(""));
    TEST_ASSERT_FALSE(isValidHostname("-device"));
    TEST_ASSERT_FALSE(isValidHostname("device-"));
    TEST_ASSERT_FALSE(isValidHostname("device..local"));
    TEST_ASSERT_FALSE(isValidHostname("device_.local"));
    TEST_ASSERT_FALSE(isValidHostname(".device"));
}

// -----------------------------------------------------------------------------

static void assertIPv4(const IPAddress_t *addr, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    TEST_ASSERT_FALSE(addr->isIPv6);
    TEST_ASSERT_EQUAL_UINT8(a, addr->ip[0]);
    TEST_ASSERT_EQUAL_UINT8(b, addr->ip[1]);
    TEST_ASSERT_EQUAL_UINT8(c, addr->ip[2]);
    TEST_ASSERT_EQUAL_UINT8(d, addr->ip[3]);
}

static void assertIPv6Bytes(const IPAddress_t *addr, const uint8_t expected[16])
{
    TEST_ASSERT_TRUE(addr->isIPv6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, addr->ip, 16);
}
