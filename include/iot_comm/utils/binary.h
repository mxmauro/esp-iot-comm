#pragma once

#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

// Tracks read progress while decoding binary data from a buffer.
typedef struct binary_reader_s {
    const uint8_t *ptr;
    size_t        len;
} binary_reader_t;

// Tracks write progress while encoding binary data into a buffer.
typedef struct binary_writer_s {
    uint8_t *ptr;
    size_t  len;
    size_t  written;
} binary_writer_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Creates a binary reader over an existing memory buffer.
binary_reader_t br_init(const uint8_t *data, size_t dataLen);

// Reads a length-prefixed string from the input buffer.
bool br_read_str(binary_reader_t *br, const char **value, size_t *valueLen);
// Reads a fixed-size blob from the input buffer.
bool br_read_blob(binary_reader_t *br, size_t size, const uint8_t **value);
// Reads a single byte from the input buffer.
bool br_read_byte(binary_reader_t *br, uint8_t *value);
// Reads a 16-bit big-endian integer from the input buffer.
bool br_read_be16(binary_reader_t *br, uint16_t *value);
// Reads a 32-bit big-endian integer from the input buffer.
bool br_read_be32(binary_reader_t *br, uint32_t *value);
// Reads a 64-bit big-endian integer from the input buffer.
bool br_read_be64(binary_reader_t *br, uint64_t *value);

// Creates a binary writer over an existing memory buffer.
binary_writer_t bw_init(uint8_t *data, size_t maxDataLen);

// Writes a length-prefixed string to the output buffer.
bool bw_write_str(binary_writer_t *bw, const char *value, size_t valueLen = (size_t)-1);
// Writes a fixed-size blob to the output buffer.
bool bw_write_blob(binary_writer_t *bw, const uint8_t *value, size_t size);
// Writes a single byte to the output buffer.
bool bw_write_byte(binary_writer_t *bw, uint8_t value);
// Writes a 16-bit big-endian integer to the output buffer.
bool bw_write_be16(binary_writer_t *bw, uint16_t value);
// Writes a 32-bit big-endian integer to the output buffer.
bool bw_write_be32(binary_writer_t *bw, uint32_t value);
// Writes a 64-bit big-endian integer to the output buffer.
bool bw_write_be64(binary_writer_t *bw, uint64_t value);

#ifdef __cplusplus
}
#endif // __cplusplus
