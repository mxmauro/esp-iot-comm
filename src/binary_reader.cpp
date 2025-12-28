#include "iot_comm/binary_reader.h"
#include <endian.h>

// -----------------------------------------------------------------------------

binary_reader_t br_init(const uint8_t *data, size_t dataLen)
{
    binary_reader_t br;
    br.ptr = data;
    br.len = dataLen;
    return br;
}

bool br_read_str(binary_reader_t *br, const char **value, size_t *valueLen)
{
    for (size_t len = 0; len < br->len; len++) {
        if (br->ptr[len] == 0) {
            *value = (const char *)(br->ptr);
            *valueLen = len;
            // Advance
            br->ptr += len + 1;
            br->len -= len + 1;
            // Done
            return true;
        }
    }
    *value = nullptr;
    *valueLen = 0;
    return false;
}

bool br_read_blob(binary_reader_t *br, size_t size, const uint8_t **value)
{
    if (br->len < size) {
        *value = nullptr;
        return false;
    }
    // Extract
    *value = br->ptr;
    // Advance
    br->ptr += size;
    br->len -= size;
    // Done
    return true;
}

bool br_read_byte(binary_reader_t *br, uint8_t *value)
{
    if (br->len < 1) {
        *value = false;
        return false;
    }
    // Extract
    *value = *(br->ptr);
    // Advance
    br->ptr += 1;
    br->len -= 1;
    // Done
    return true;
}

bool br_read_be16(binary_reader_t *br, uint16_t *value)
{
    if (br->len < 2) {
        *value = 0;
        return false;
    }
    // Extract
    *value = be16dec(br->ptr);
    // Advance
    br->ptr += 2;
    br->len -= 2;
    // Done
    return true;
}

bool br_read_be32(binary_reader_t *br, uint32_t *value)
{
    if (br->len < 4) {
        *value = 0;
        return false;
    }
    // Extract
    *value = be32dec(br->ptr);
    // Advance
    br->ptr += 4;
    br->len -= 4;
    // Done
    return true;
}

bool br_read_be64(binary_reader_t *br, uint64_t *value)
{
    if (br->len < 8) {
        *value = 0;
        return false;
    }
    // Extract
    *value = be64dec(br->ptr);
    // Advance
    br->ptr += 8;
    br->len -= 8;
    // Done
    return true;
}
