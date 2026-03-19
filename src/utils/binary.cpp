#include "iot_comm/utils/binary.h"
#include <endian.h>
#include <string.h>

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

    // Unable to complete
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

binary_writer_t bw_init(uint8_t *data, size_t maxDataLen)
{
    binary_writer_t bw;

    bw.ptr = data;
    bw.len = maxDataLen;
    bw.written = 0;
    return bw;
}

bool bw_write_str(binary_writer_t *bw, const char *value, size_t valueLen)
{
    if (value) {
        if (valueLen == (size_t)-1) {
            valueLen = strlen(value);
        }
    }
    else {
        if (valueLen != 0 && valueLen != (size_t)-1) {
            return false;
        }
        valueLen = 0;
    }

    if (bw->len - bw->written <= valueLen) {
        return false;
    }

    // Store
    memcpy(bw->ptr, value, valueLen);
    bw->ptr[valueLen] = 0;

    // Advance
    bw->ptr += valueLen + 1;
    bw->written += valueLen + 1;

    // Done
    return true;
}

bool bw_write_blob(binary_writer_t *bw, const uint8_t *value, size_t size)
{
    if (size > 0 && value == nullptr) {
        return false;
    }
    if (bw->len - bw->written < size) {
        return false;
    }

    // Store
    memcpy(bw->ptr, value, size);

    // Advance
    bw->ptr += size;
    bw->written += size;

    // Done
    return true;
}

bool bw_write_byte(binary_writer_t *bw, uint8_t value)
{
    if (bw->len - bw->written < 1) {
        return false;
    }

    // Store
    *(bw->ptr) = value;

    // Advance
    bw->ptr += 1;
    bw->written += 1;

    // Done
    return true;
}

bool bw_write_be16(binary_writer_t *bw, uint16_t value)
{
    if (bw->len - bw->written < 2) {
        return false;
    }

    // Store
    be16enc(bw->ptr, value);

    // Advance
    bw->ptr += 2;
    bw->written += 2;

    // Done
    return true;
}

bool bw_write_be32(binary_writer_t *bw, uint32_t value)
{
    if (bw->len - bw->written < 4) {
        return false;
    }

    // Store
    be32enc(bw->ptr, value);

    // Advance
    bw->ptr += 4;
    bw->written += 4;

    // Done
    return true;
}

bool bw_write_be64(binary_writer_t *bw, uint64_t value)
{
    if (bw->len - bw->written < 8) {
        return false;
    }

    // Store
    be64enc(bw->ptr, value);

    // Advance
    bw->ptr += 8;
    bw->written += 8;

    // Done
    return true;
}
