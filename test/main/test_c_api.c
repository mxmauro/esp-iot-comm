#include <unity.h>
#include <iot_comm/captive_portal/captive_portal.h>
#include <iot_comm/crypto/aes.h>
#include <iot_comm/crypto/hkdf.h>
#include <iot_comm/crypto/ecc.h>
#include <iot_comm/crypto/sha.h>
#include <iot_comm/crypto/utils.h>
#include <iot_comm/http/helpers.h>
#include <iot_comm/iot_comm.h>
#include <iot_comm/ota/ota.h>
#include <iot_comm/provisioning/wifi.h>
#include <iot_comm/utils/binary.h>
#include <iot_comm/utils/network.h>

// -----------------------------------------------------------------------------

TEST_CASE("Public C headers compile as C", "[c api]")
{
    TEST_ASSERT_EQUAL_INT(0, 0);
}
