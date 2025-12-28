#pragma once

#include <stdlib.h>

// -----------------------------------------------------------------------------

typedef struct binary_reader_s {
    const uint8_t *ptr;
    size_t        len;
} binary_reader_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

binary_reader_t br_init(const uint8_t *data, size_t dataLen);

bool br_read_str(binary_reader_t *br, const char **value, size_t *valueLen);
bool br_read_blob(binary_reader_t *br, size_t size, const uint8_t **value);
bool br_read_byte(binary_reader_t *br, uint8_t *value);
bool br_read_be16(binary_reader_t *br, uint16_t *value);
bool br_read_be32(binary_reader_t *br, uint32_t *value);
bool br_read_be64(binary_reader_t *br, uint64_t *value);

#ifdef __cplusplus
}
#endif // __cplusplus
