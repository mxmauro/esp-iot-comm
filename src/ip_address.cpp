#include "ip_address.h"
#include <lwip/sockets.h>
#include <memory.h>

// -----------------------------------------------------------------------------

static void trim(const char **lpS, const char **lpsEnd);
static const char *findChar(const char *s, const char *sEnd, char c);

// -----------------------------------------------------------------------------

void parseIPv4(IPAddress_t *addr, const struct sockaddr_in *in)
{
    addr->ip[0] = (uint8_t)in->sin_addr.s_addr & 0xFF;
    addr->ip[1] = (uint8_t)(in->sin_addr.s_addr >> 8) & 0xFF;
    addr->ip[2] = (uint8_t)(in->sin_addr.s_addr >> 16) & 0xFF;
    addr->ip[3] = (uint8_t)(in->sin_addr.s_addr >> 24) & 0xFF;
    addr->isIPv6 = false;
}

void parseIPv6(IPAddress_t *addr, const struct sockaddr_in6 *in)
{
    memcpy(addr->ip, in->sin6_addr.s6_addr, 16);
    addr->isIPv6 = true;
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
    // Check if both addresses are the same type
    if (addr1->isIPv6 == addr2->isIPv6) {
        return !!(memcmp(addr1->ip, addr2->ip, 16) == 0);
    }

    // If addr1 is IPv6 and addr2 is IPv4 then switch both
    // addresses so addr1 is always IPv4 and addr2 is IPv6
    if (addr1->isIPv6) {
        const IPAddress_t *temp = addr1;
        addr1 = addr2;
        addr2 = temp;
    }

    // Compare the IPv4 part
    if (memcmp(addr1->ip, addr2->ip, 4) != 0) {
        return false;
    }

    // Check in the IPv6 address for the v4 wrapper
    if (addr2->ip[4] != 0xFF || addr2->ip[5] != 0xFF) {
        return false;
    }
    for (int i = 6; i < 16; i++) {
        if (addr2->ip[i] != 0) {
            return false;
        }
    }

    // They match
    return true;
}

// -----------------------------------------------------------------------------

static void trim(const char **lpS, const char **lpsEnd)
{
    const char *s = *lpS;
    const char *sEnd = *lpsEnd;

    while (s < sEnd && isspace((unsigned char)*s)) {
        s++;
    }
    while (sEnd > s && isspace((unsigned char)*(sEnd - 1))) {
        sEnd--;
    }
    *lpS = s;
    *lpsEnd = sEnd;
}

static const char *findChar(const char *s, const char *sEnd, char c)
{
    while (s < sEnd && *s != c) {
        s++;
    }
    return (s < sEnd) ? s : nullptr;
}
