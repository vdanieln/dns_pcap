#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>

typedef struct {
    const char *iface;      /* interface for live capture */
    const char *pcap_file;  /* offline pcap file to read */
    int packet_count;       /* 0 = infinite */
} capture_config_t;

typedef struct {
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t ip_proto; /* e.g. IPPROTO_UDP */
    int is_ipv6;
} packet_info_t;

typedef void (*payload_handler_t)(const u_char *payload, size_t len, const packet_info_t *info);

int start_capture(const capture_config_t *cfg, payload_handler_t handler);

#endif /* CAPTURE_H */
