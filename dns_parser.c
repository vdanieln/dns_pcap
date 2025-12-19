#include "dns_parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DNS_FLAG_QR_RESPONSE 0x8000
#define DNS_POINTER_FLAG_MASK 0xC0 // 6-7 bits set -> pointer
#define DNS_HEADER_LEN 12
#define DNS_NAME_DECODE_MAX_STEPS 255
#define DNS_CLASS_IN 1
#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_HTTPS 65

static int decode_name(const u_char *dns, size_t dns_len,
                       size_t *offset, char *buffer, size_t buffer_len) {
    size_t pos = *offset, buffer_pos = 0, jump_end = 0;
    int jumped = 0, loops = 0, saw_terminator = 0;

    while (pos < dns_len) {
        if (++loops > DNS_NAME_DECODE_MAX_STEPS) return -1; // prevents infinite loops
        uint8_t len = dns[pos];

        if ((len & DNS_POINTER_FLAG_MASK) == DNS_POINTER_FLAG_MASK) { // Pointer case
            if (pos + 1 >= dns_len) return -1;
            uint16_t ptr = (uint16_t)(((len & 0x3F) << 8) | dns[pos + 1]); // 14-bit pointer
            if (ptr >= dns_len) return -1;
            if (!jumped) jump_end = pos + 2; // first time - we save cursor after the pointer
            pos = ptr; 
            jumped = 1;
            continue;
        }

        if (len == 0) { // end of name
            pos++;
            *offset = jumped ? jump_end : pos;
            saw_terminator = 1;
            break;
        }

        pos++;
        if (pos + len > dns_len || buffer_pos + len + 1 >= buffer_len) return -1;
        memcpy(buffer + buffer_pos, dns + pos, len);
        buffer_pos += len;
        buffer[buffer_pos++] = '.';
        pos += len;
        if (!jumped) *offset = pos;
    }

    if (!saw_terminator) return -1;

    if (buffer_pos == 0) { snprintf(buffer, buffer_len, "."); }
    else { buffer[buffer_pos - 1] = '\0'; }
    return 0;
}

void process_dns_response(const u_char *dns, size_t dns_len, const packet_info_t *info) {
    (void)info;
    if (dns_len < DNS_HEADER_LEN) return;

    uint16_t flags   = (uint16_t)((dns[2] << 8) | dns[3]);
    if ((flags & DNS_FLAG_QR_RESPONSE) == 0) return; // Not a DNS response

    uint16_t qdcount = (uint16_t)((dns[4] << 8) | dns[5]);
    uint16_t ancount = (uint16_t)((dns[6] << 8) | dns[7]);

    size_t offset = DNS_HEADER_LEN;

    char domain[256] = "<unknown>";
    for (uint16_t q = 0; q < qdcount; ++q) {
        char tmp[256];
        if (decode_name(dns, dns_len, &offset, tmp, sizeof(tmp)) != 0) return;
        if (offset + 4 > dns_len) return; /* type + class */
        if (q == 0) snprintf(domain, sizeof(domain), "%s", tmp);
        offset += 4;
    }

    int started_print = 0;
    int first = 1;

    for (uint16_t i = 0; i < ancount; i++) {
        char owner[256];
        if (decode_name(dns, dns_len, &offset, owner, sizeof(owner)) != 0) return;
        if (offset + 10 > dns_len) return;

        uint16_t type    = (uint16_t)((dns[offset]     << 8) | dns[offset + 1]);
        uint16_t class   = (uint16_t)((dns[offset + 2] << 8) | dns[offset + 3]);
        uint16_t rdlen   = (uint16_t)((dns[offset + 8] << 8) | dns[offset + 9]);
        offset += 10;
        if (offset + rdlen > dns_len) return;

        if (class == DNS_CLASS_IN) {
            if (type == DNS_TYPE_A && rdlen == 4) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, dns + offset, ip, sizeof(ip));
                if (!started_print) {
                    printf("Domain: %s -> ", domain);
                    started_print = 1;
                }
                printf("%s%s", first ? "" : ", ", ip); first = 0;
            } else if (type == DNS_TYPE_AAAA && rdlen == 16) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, dns + offset, ip6, sizeof(ip6));
                if (!started_print) {
                    printf("Domain: %s -> ", domain);
                    started_print = 1;
                }
                printf("%s%s", first ? "" : ", ", ip6); first = 0;
            } else if (type == DNS_TYPE_CNAME) {
                size_t cname_off = offset; char cname[256];
                if (decode_name(dns, dns_len, &cname_off, cname, sizeof(cname)) == 0) {
                    if (!started_print) {
                        printf("Domain: %s -> ", domain);
                        started_print = 1;
                    }
                    printf("%sCNAME %s", first ? "" : ", ", cname); first = 0;
                }
            }
        }
        offset += rdlen;
    }

    if (!started_print) {
        return;
    }
    printf("\n");
}
