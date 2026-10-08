/* userspace/net/dns.c - RFC 1035 query builder + first-A parser.
 * Pure C, host-testable, libc-free (byte loops only, no string.h) so the
 * freestanding net ELF can share it. See dns.h for the contract. */
#include "dns.h"

/* Skip one NAME field at *off (labels and/or one trailing 0xC0 pointer).
 * A pointer terminates the name; its target must lie inside the message
 * and must itself be a plain label sequence (no second pointer level,
 * which keeps parsing bounded and pointer chains rejected). */
static int dns_skip_name(const uint8_t *m, unsigned long len, unsigned long *off)
{
    unsigned long o = *off;
    unsigned steps = 0;
    for (;;)
    {
        uint8_t b;
        unsigned long ptr, p;
        unsigned psteps = 0;
        if (o >= len)
            return -1;
        b = m[o];
        if ((b & 0xC0u) == 0xC0u)
        {
            if (o + 1u >= len)
                return -1;
            ptr = (((unsigned long)(b & 0x3Fu)) << 8) | (unsigned long)m[o + 1u];
            if (ptr >= len)
                return -1;
            /* Validate the one allowed level: plain labels to a root. */
            p = ptr;
            for (;;)
            {
                uint8_t pb;
                if (p >= len)
                    return -1;
                pb = m[p];
                if ((pb & 0xC0u) == 0xC0u)
                    return -1;
                if (pb & 0xC0u)
                    return -1;
                if (pb == 0u)
                    break;
                if (pb > NET_DNS_LABEL_MAX)
                    return -1;
                if (p + 1u + (unsigned long)pb >= len + 1u)
                    return -1;
                p += 1u + (unsigned long)pb;
                if (++psteps > 128u)
                    return -1;
            }
            *off = o + 2u;
            return 0;
        }
        if (b & 0xC0u)
            return -1;
        if (b == 0u)
        {
            *off = o + 1u;
            return 0;
        }
        if (b > NET_DNS_LABEL_MAX)
            return -1;
        if (o + 1u + (unsigned long)b >= len + 1u)
            return -1;
        o += 1u + (unsigned long)b;
        if (++steps > 128u)
            return -1;
    }
}

int net_dns_build_query(const char *name, uint16_t txid, uint8_t *out, unsigned long *out_len)
{
    unsigned long n = 0;
    unsigned long m;
    unsigned long qname;
    unsigned long o;
    unsigned long lab_start;
    unsigned long i;
    unsigned long lab_len;
    if (!name || !out || !out_len)
        return -1;
    while (name[n] != '\0')
        n++;
    if (n == 0u || n > NET_DNS_NAME_MAX)
        return -1;
    /* Strip one trailing dot; a lone "." queries the root. */
    m = n;
    if (name[n - 1u] == '.')
        m = n - 1u;
    if (m == 0u)
    {
        out[0] = (uint8_t)(txid >> 8);
        out[1] = (uint8_t)(txid & 0xFFu);
        out[2] = 0x01;
        out[3] = 0x00;
        out[4] = 0x00;
        out[5] = 0x01;
        out[6] = 0x00;
        out[7] = 0x00;
        out[8] = 0x00;
        out[9] = 0x00;
        out[10] = 0x00;
        out[11] = 0x00;
        out[12] = 0x00;
        out[13] = 0x00;
        out[14] = 0x01;
        out[15] = 0x00;
        out[16] = 0x01;
        *out_len = 17u;
        return 0;
    }
    /* Validate label structure: 1..63 bytes per label, no empties. */
    lab_len = 0;
    for (i = 0; i < m; i++)
    {
        if (name[i] == '.')
        {
            if (lab_len == 0u || lab_len > NET_DNS_LABEL_MAX)
                return -1;
            lab_len = 0;
        }
        else
        {
            lab_len++;
            if (lab_len > NET_DNS_LABEL_MAX)
                return -1;
        }
    }
    if (lab_len == 0u || lab_len > NET_DNS_LABEL_MAX)
        return -1;
    /* Wire QNAME length is m chars + 1 leading length byte + 1 root. */
    qname = m + 2u;
    if (qname > NET_DNS_NAME_MAX)
        return -1;
    out[0] = (uint8_t)(txid >> 8);
    out[1] = (uint8_t)(txid & 0xFFu);
    out[2] = 0x01;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x01;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0x00;
    out[9] = 0x00;
    out[10] = 0x00;
    out[11] = 0x00;
    o = 12u;
    lab_start = 0;
    for (i = 0; i <= m; i++)
    {
        unsigned long k;
        if (i < m && name[i] != '.')
            continue;
        lab_len = i - lab_start;
        out[o] = (uint8_t)lab_len;
        o++;
        for (k = 0; k < lab_len; k++)
        {
            out[o] = (uint8_t)name[lab_start + k];
            o++;
        }
        lab_start = i + 1u;
    }
    out[o] = 0x00;
    o++;
    out[o] = 0x00;
    out[o + 1u] = (uint8_t)NET_DNS_QTYPE_A;
    out[o + 2u] = 0x00;
    out[o + 3u] = (uint8_t)NET_DNS_QCLASS_IN;
    o += 4u;
    *out_len = o;
    return 0;
}

int net_dns_parse_a(const uint8_t *resp, unsigned long len, uint32_t *out_ip)
{
    unsigned long o;
    unsigned qd, an, i;
    uint16_t flags;
    if (!resp || !out_ip)
        return -(NET_ERR_TRUNC);
    if (len < 12u)
        return -(NET_ERR_TRUNC);
    flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    if (flags & 0x0200u)
        return -(NET_ERR_TRUNC);
    qd = (unsigned)(((unsigned)resp[4] << 8) | (unsigned)resp[5]);
    an = (unsigned)(((unsigned)resp[6] << 8) | (unsigned)resp[7]);
    o = 12u;
    for (i = 0; i < qd; i++)
    {
        if (dns_skip_name(resp, len, &o) != 0)
            return -(NET_ERR_TRUNC);
        if (o + 4u > len)
            return -(NET_ERR_TRUNC);
        o += 4u;
    }
    for (i = 0; i < an; i++)
    {
        uint16_t type, class, rdlen;
        if (dns_skip_name(resp, len, &o) != 0)
            return -(NET_ERR_TRUNC);
        if (o + 10u > len)
            return -(NET_ERR_TRUNC);
        type = (uint16_t)(((uint16_t)resp[o] << 8) | (uint16_t)resp[o + 1u]);
        class = (uint16_t)(((uint16_t)resp[o + 2u] << 8) | (uint16_t)resp[o + 3u]);
        rdlen = (uint16_t)(((uint16_t)resp[o + 8u] << 8) | (uint16_t)resp[o + 9u]);
        o += 10u;
        if (o + (unsigned long)rdlen > len)
            return -(NET_ERR_TRUNC);
        if (type == (uint16_t)NET_DNS_QTYPE_A && class == (uint16_t)NET_DNS_QCLASS_IN &&
            rdlen == 4u)
        {
            *out_ip = ((uint32_t)resp[o] << 24) | ((uint32_t)resp[o + 1u] << 16) |
                      ((uint32_t)resp[o + 2u] << 8) | (uint32_t)resp[o + 3u];
            return 0;
        }
        o += (unsigned long)rdlen;
    }
    return -(NET_ERR_EMPTY);
}
