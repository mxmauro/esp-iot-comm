#pragma once

#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------

typedef struct IPAddress_s {
    uint8_t ip[16];
    bool    isIPv6;
} IPAddress_t;

// -----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void parseIPv4(IPAddress_t *addr, const struct sockaddr_in *in);
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
bool parseIP(IPAddress_t *addr, const char *s, size_t len = (size_t)-1);

bool ipAddressEqual(const IPAddress_t *addr1, const IPAddress_t *addr2);

#ifdef __cplusplus
}
#endif // __cplusplus
