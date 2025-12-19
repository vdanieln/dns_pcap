#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stddef.h>
#include "capture.h"

/* dns points to the start of the DNS message (DNS header at offset 0). */
void process_dns_response(const u_char *dns, size_t dns_len, const packet_info_t *info);

#endif /* DNS_PARSER_H */
