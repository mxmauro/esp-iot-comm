#pragma once

#include <lwip/sockets.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_HOSTNAME_LEN 64

// -----------------------------------------------------------------------------

// Stores either an IPv4 or IPv6 address in normalized form.
typedef struct IPAddress_s {
    uint8_t ip[16];
    bool    isIPv6;
} IPAddress_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Converts a native IPv4 socket address into the library representation.
void parseIPv4(IPAddress_t *addr, const struct sockaddr_in *in);
// Converts a native IPv6 socket address into the library representation.
void parseIPv6(IPAddress_t *addr, const struct sockaddr_in6 *in);

// Accepts candidates like:
//  - "203.0.113.1"
//  - " 203.0.113.1 "
//  - "\"203.0.113.1\""
//  - "[2001:db8::1]"
//  - "\"[2001:db8::1]\""
//  - "2001:db8::1"
//  - "203.0.113.1:1234"  (we'll strip :port for IPv4)
//  - "[2001:db8::1]:1234" (strip brackets + port)
// Parses an IPv4 or IPv6 address string into the library representation.
bool parseIP(IPAddress_t *addr, const char *s, size_t len = (size_t)-1);

// Compares two IP addresses for exact equality.
bool ipAddressEqual(const IPAddress_t *addr1, const IPAddress_t *addr2);

// Validates whether a string can be used as a device hostname.
bool isValidHostname(const char *hostname);

#ifdef __cplusplus
}
#endif // __cplusplus
