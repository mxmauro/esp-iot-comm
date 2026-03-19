#include <unity.h>
#include <iot_comm/utils/binary.h>

// -----------------------------------------------------------------------------

TEST_CASE("binary reader reads mixed values sequentially", "[binary]")
{
    const uint8_t buffer[] = {
        'o', 'k', 0x00,
        0xaa, 0xbb, 0xcc,
        0x7f,
        0x12, 0x34,
        0xde, 0xad, 0xbe, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    binary_reader_t br = br_init(buffer, sizeof(buffer));
    const char      *text;
    size_t          textLen;
    const uint8_t   *blob;
    uint8_t         byteValue;
    uint16_t        be16Value;
    uint32_t        be32Value;
    uint64_t        be64Value;

    TEST_ASSERT_TRUE(br_read_str(&br, &text, &textLen));
    TEST_ASSERT_EQUAL_UINT32(2, textLen);
    TEST_ASSERT_EQUAL_STRING_LEN("ok", text, textLen);

    TEST_ASSERT_TRUE(br_read_blob(&br, 3, &blob));
    TEST_ASSERT_EQUAL_HEX8(0xaa, blob[0]);
    TEST_ASSERT_EQUAL_HEX8(0xbb, blob[1]);
    TEST_ASSERT_EQUAL_HEX8(0xcc, blob[2]);

    TEST_ASSERT_TRUE(br_read_byte(&br, &byteValue));
    TEST_ASSERT_EQUAL_HEX8(0x7f, byteValue);

    TEST_ASSERT_TRUE(br_read_be16(&br, &be16Value));
    TEST_ASSERT_EQUAL_HEX16(0x1234, be16Value);

    TEST_ASSERT_TRUE(br_read_be32(&br, &be32Value));
    TEST_ASSERT_EQUAL_HEX32(0xdeadbeef, be32Value);

    TEST_ASSERT_TRUE(br_read_be64(&br, &be64Value));
    TEST_ASSERT_EQUAL_HEX32(0x01234567, (uint32_t)(be64Value >> 32));
    TEST_ASSERT_EQUAL_HEX32(0x89abcdef, (uint32_t)be64Value);
    TEST_ASSERT_EQUAL_UINT32(0, br.len);
}

TEST_CASE("binary reader reports failure on short buffers", "[binary]")
{
    const uint8_t   buffer[] = { 0x12 };
    binary_reader_t br = br_init(buffer, sizeof(buffer));
    uint16_t        be16Value = 0xffff;

    TEST_ASSERT_FALSE(br_read_be16(&br, &be16Value));
    TEST_ASSERT_EQUAL_HEX16(0x0000, be16Value);
    TEST_ASSERT_EQUAL_UINT32(sizeof(buffer), br.len);
}

TEST_CASE("binary writer writes mixed values sequentially", "[binary]")
{
    uint8_t         buffer[32] = {};
    binary_writer_t bw = bw_init(buffer, sizeof(buffer));
    const uint8_t   blob[] = { 0xaa, 0xbb, 0xcc };
    const uint8_t   expected[] = {
        'o', 'k', 0x00,
        0xaa, 0xbb, 0xcc,
        0x7f,
        0x12, 0x34,
        0xde, 0xad, 0xbe, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    TEST_ASSERT_TRUE(bw_write_str(&bw, "ok"));
    TEST_ASSERT_TRUE(bw_write_blob(&bw, blob, sizeof(blob)));
    TEST_ASSERT_TRUE(bw_write_byte(&bw, 0x7f));
    TEST_ASSERT_TRUE(bw_write_be16(&bw, 0x1234));
    TEST_ASSERT_TRUE(bw_write_be32(&bw, 0xdeadbeef));
    TEST_ASSERT_TRUE(bw_write_be64(&bw, 0x0123456789abcdefULL));

    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), bw.written);
    TEST_ASSERT_EQUAL_UINT32(sizeof(buffer), bw.len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, sizeof(expected));
}

TEST_CASE("binary writer rejects writes that exceed capacity", "[binary]")
{
    uint8_t         buffer[4] = {};
    binary_writer_t bw = bw_init(buffer, sizeof(buffer));

    TEST_ASSERT_TRUE(bw_write_be32(&bw, 0x11223344));
    TEST_ASSERT_FALSE(bw_write_byte(&bw, 0x55));
    TEST_ASSERT_EQUAL_UINT32(4, bw.written);
    TEST_ASSERT_EQUAL_UINT32(sizeof(buffer), bw.len);
    TEST_ASSERT_EQUAL_HEX8(0x11, buffer[0]);
    TEST_ASSERT_EQUAL_HEX8(0x22, buffer[1]);
    TEST_ASSERT_EQUAL_HEX8(0x33, buffer[2]);
    TEST_ASSERT_EQUAL_HEX8(0x44, buffer[3]);
}
