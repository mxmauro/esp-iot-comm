#include <unity.h>
#include <iot_comm/provisioning/wifi.h>

// -----------------------------------------------------------------------------

TEST_CASE("mDNS service APIs require initialized Wi-Fi manager", "[wifi][mdns]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, wifiMgrMdnsServiceAdd(nullptr, "_http", "_tcp", 80, nullptr, 0));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, wifiMgrMdnsServiceRemove("_http", "_tcp"));
}

TEST_CASE("provisioning is inactive before Wi-Fi initialization", "[wifi][provisioning]")
{
    TEST_ASSERT_FALSE(wifiMgrIsProvisioningActive());
}
