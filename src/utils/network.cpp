#include "iot_comm/utils/network.h"
#include <ctype.h>
#include <memory.h>
#include <stdint.h>
#include <string.h>

// -----------------------------------------------------------------------------

static void trim(const char **lpsStart, const char **lpsEnd);
static const char *findChar(const char *s, const char *sEnd, char c);

// -----------------------------------------------------------------------------

void parseIPv4(IPAddress_t *addr, const struct sockaddr_in *in)
{
    addr->ip[0] = (uint8_t) in->sin_addr.s_addr        & 0xFF;
    addr->ip[1] = (uint8_t)(in->sin_addr.s_addr >>  8) & 0xFF;
    addr->ip[2] = (uint8_t)(in->sin_addr.s_addr >> 16) & 0xFF;
    addr->ip[3] = (uint8_t)(in->sin_addr.s_addr >> 24) & 0xFF;
    addr->isIPv6 = false;
}

void parseIPv6(IPAddress_t *addr, const struct sockaddr_in6 *in)
{
    memcpy(addr->ip, &in->sin6_addr.s6_addr, 16);
    addr->isIPv6 = true;
    toIPv4(addr);
}

bool toIPv4(IPAddress_t *addr)
{
    if (!addr->isIPv6) {
        return true;
    }

    // Fast shared check for:
    // ::ffff:a.b.c.d   - IPv4-mapped
    // ::a.b.c.d        - IPv4-compatible, deprecated
    // 64:ff9b::a.b.c.d - NAT64 well-known prefix
    if ((addr->ip[4] | addr->ip[5] | addr->ip[6] | addr->ip[7] | addr->ip[8] | addr->ip[9]) == 0x00) {
        // ::ffff:a.b.c.d - IPv4-mapped
        // ::a.b.c.d      - IPv4-compatible, deprecated
        if ((addr->ip[0] | addr->ip[1] | addr->ip[2] | addr->ip[3]) == 0) {
            if ((addr->ip[10] == 0xff && addr->ip[11] == 0xff) || (addr->ip[10] == 0x00 && addr->ip[11] == 0x00)) {
                addr->ip[0] = addr->ip[12];
                addr->ip[1] = addr->ip[13];
                addr->ip[2] = addr->ip[14];
                addr->ip[3] = addr->ip[15];
                addr->isIPv6 = false;
                return true;
            }
        }
        else if ((addr->ip[0] | addr->ip[10] | addr->ip[11]) == 0x00 && addr->ip[1] == 0x64 && addr->ip[2] == 0xff && addr->ip[3] == 0x9b) {
            // 64:ff9b::a.b.c.d - NAT64 well-known prefix
            addr->ip[0] = addr->ip[12];
            addr->ip[1] = addr->ip[13];
            addr->ip[2] = addr->ip[14];
            addr->ip[3] = addr->ip[15];
            addr->isIPv6 = false;
            return true;
        }
    }

    // 2002:aabb:ccdd:: - 6to4
    if (addr->ip[0] == 0x20 && addr->ip[1] == 0x02) {
        addr->ip[0] = addr->ip[2];
        addr->ip[1] = addr->ip[3];
        addr->ip[2] = addr->ip[4];
        addr->ip[3] = addr->ip[5];
        addr->isIPv6 = false;
        return true;
    }

    // Teredo: 2001:0000::/32, the client IPv4 is at offset 12, but bytes are XORed with 0xff.
    if (addr->ip[0] == 0x20 && addr->ip[1] == 0x01 && addr->ip[2] == 0x00 && addr->ip[3] == 0x00) {
        addr->ip[0] = addr->ip[12] ^ 0xFF;
        addr->ip[1] = addr->ip[13] ^ 0xFF;
        addr->ip[2] = addr->ip[14] ^ 0xFF;
        addr->ip[3] = addr->ip[15] ^ 0xFF;
        addr->isIPv6 = false;
        return true;
    }

    // Not an IPv4 address
    return false;
}

bool parseIP(IPAddress_t *addr, const char *s, size_t len)
{
    const char *sEnd;
    const char *pos;
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    char buf[128];

    if (s == nullptr) {
        return false;
    }
    if (len != (size_t)-1) {
        sEnd = s + len;
    } else {
        sEnd = s + strlen(s);
    }

    // Trim
    trim(&s, &sEnd);
    if (s >= sEnd) {
        return false;
    }

    // Remove surrounding quotes, if any
    if (*s == '"' && *(sEnd - 1) == '"' && sEnd - s >= 2) {
        s++;
        sEnd--;
        trim(&s, &sEnd);
        if (s >= sEnd) {
            return false;
        }
    }

    // If it's "unknown" (Forwarded can have for=unknown)
    if (sEnd - s == 7 && strncasecmp(s, "unknown", 7) == 0) {
        return false;
    }

    // Handle bracketed IPv6: [....] or [....]:port
    if (*s == '[') {
        pos = findChar(s, sEnd, ']');
        if ((!pos) || pos - s - 1 >= (int)sizeof(buf)) {
            return false;
        }
        strncpy(buf, s + 1, pos - s - 1);
        buf[pos - s - 1] = '\0';

        if (inet_pton(AF_INET6, buf, &a6.sin6_addr) == 1) {
            parseIPv6(addr, &a6);
            return true;
        }
        return false;
    }

    // Try raw IPv4 first (possibly with :port)
    // Heuristic: if there is a single ':' and also dots, treat as IPv4:port
    pos = findChar(s, sEnd, ':');
    if (pos && findChar(s, sEnd, '.') && (!findChar(pos + 1, sEnd, ':'))) {
        sEnd = pos;
        trim(&s, &sEnd);
        if (s >= sEnd) {
            return false;
        }
    }

    if (sEnd - s - 1 >= (int)sizeof(buf)) {
        return false;
    }
    strncpy(buf, s, sEnd - s);
    buf[sEnd - s] = '\0';

    // Try IPv4
    if (inet_pton(AF_INET, buf, &a4.sin_addr) == 1) {
        parseIPv4(addr, &a4);
        return true;
    }

    // Try raw IPv6 (no brackets)
    if (inet_pton(AF_INET6, buf, &a6.sin6_addr) == 1) {
        parseIPv6(addr, &a6);
        return true;
    }

    // No match
    return false;
}

bool ipAddressEqual(const IPAddress_t *addr1, const IPAddress_t *addr2)
{
    if (addr1->isIPv6) {
        if (addr2->isIPv6) {
            // Both are IPv6
            return !!(memcmp(addr1->ip, addr2->ip, 16) == 0);
        }
    }
    else if (!addr2->isIPv6) {
        // Both are IPv4
        return !!(memcmp(addr1->ip, addr2->ip, 4) == 0);
    }

    // No match
    return false;
}

bool isValidHostname(const char *hostname)
{
    size_t i;
    size_t len;
    char ch;

    if ((!hostname) || *hostname == 0) {
        return false;
    }
    len = strlen(hostname);
    if (len > 63) {
        return false;
    }
    if (!isalnum((unsigned char)hostname[0])) {
        return false;
    }
    if (!isalnum((unsigned char)hostname[len - 1])) {
        return false;
    }

    for (i = 0; i < len; i++) {
        ch = hostname[i];
        if (!isalnum((unsigned char)ch) && ch != '-') {
            return false;
        }
    }

    return true;
}

// -----------------------------------------------------------------------------

static void trim(const char **lpsStart, const char **lpsEnd)
{
    const char *s = *lpsStart;
    const char *sEnd = *lpsEnd;

    while (s < sEnd && isspace((unsigned char)*s)) {
        s++;
    }
    while (sEnd > s && isspace((unsigned char)*(sEnd - 1))) {
        sEnd--;
    }
    *lpsStart = s;
    *lpsEnd = sEnd;
}

static const char *findChar(const char *s, const char *sEnd, char c)
{
    while (s < sEnd && *s != c) {
        s++;
    }
    return (s < sEnd) ? s : nullptr;
}
