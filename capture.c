#include "capture.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* EtherType values */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD

/* UDP header is fixed-size (RFC 768). */
#define UDP_HEADER_LEN 8

/* Capture only DNS responses over UDP. */
#define DEFAULT_DNS_RESPONSE_FILTER "udp port 53 and (udp[10] & 0x80 != 0)"

static int datalink_type = DLT_EN10MB;

static int parse_link_layer(const u_char **data, uint32_t *remaining_len, uint16_t *eth_type) {
    switch (datalink_type) {
    case DLT_EN10MB: { /* Ethernet */
        if (*remaining_len < 14) {
            return -1;
        }
        const u_char *ptr = *data;
        uint16_t type = (uint16_t)(ptr[12] << 8 | ptr[13]);
        *eth_type = type;
        *data += 14;
        *remaining_len -= 14;
        return 0;
    }
    case DLT_LINUX_SLL: { /* Linux cooked capture */
        if (*remaining_len < 16) {
            return -1;
        }
        const u_char *ptr = *data;
        uint16_t type = (uint16_t)(ptr[14] << 8 | ptr[15]);
        *eth_type = type;
        *data += 16;
        *remaining_len -= 16;
        return 0;
    }
    case DLT_RAW: { /* No link header, treat as IP */
        *eth_type = 0;
        return 0;
    }
    case DLT_NULL: { /* BSD loopback */
        if (*remaining_len < 4) {
            return -1;
        }
        uint32_t af = 0;
        memcpy(&af, *data, sizeof(uint32_t));
        *data += 4;
        *remaining_len -= 4;
        if (af == AF_INET) {
            *eth_type = ETHERTYPE_IPV4;
        } else if (af == AF_INET6) {
            *eth_type = ETHERTYPE_IPV6;
        } else {
            return -1;
        }
        return 0;
    }
    default:
        return -1;
    }
}

static void handle_ipv4(const u_char *data, uint32_t ipv4_packet_len, payload_handler_t handler) {
    if (ipv4_packet_len < 20) { // smallest IPv4 header size
        return;
    }
    uint8_t ipv4_header_len = (data[0] & 0x0F) * 4;
    if (ipv4_header_len < 20 || ipv4_packet_len < ipv4_header_len) {
        return;
    }
    if (data[9] != IPPROTO_UDP) {
        return;
    }
    uint16_t total_len = (uint16_t)(data[2] << 8 | data[3]); // Network byte order - big endian
    if (total_len < ipv4_header_len + UDP_HEADER_LEN) {
        return;
    }
    if (ipv4_packet_len < total_len) {
        return;
    }

    const u_char *udp = data + ipv4_header_len;
    uint16_t sport = (uint16_t)(udp[0] << 8 | udp[1]);
    uint16_t dport = (uint16_t)(udp[2] << 8 | udp[3]);
    uint16_t udp_len = (uint16_t)(udp[4] << 8 | udp[5]);
    if (udp_len < UDP_HEADER_LEN || (size_t)udp_len > ipv4_packet_len - ipv4_header_len) {
        return;
    }
    const u_char *payload = udp + UDP_HEADER_LEN;
    size_t payload_len = udp_len - UDP_HEADER_LEN;

    packet_info_t info = {0};
    inet_ntop(AF_INET, data + 12, info.src_addr, sizeof(info.src_addr));
    inet_ntop(AF_INET, data + 16, info.dst_addr, sizeof(info.dst_addr));
    info.src_port = sport;
    info.dst_port = dport;
    info.ip_proto = IPPROTO_UDP;
    info.is_ipv6 = 0;

    handler(payload, payload_len, &info);
}

static void handle_ipv6(const u_char *data, uint32_t ipv6_packet_len, payload_handler_t handler) {
    if (ipv6_packet_len < 40) {
        return;
    }
    uint8_t next_hdr = data[6];
    if (next_hdr != IPPROTO_UDP) {
        return;
    }
    uint16_t ipv6_payload_len = (uint16_t)(data[4] << 8 | data[5]);
    if ((uint32_t)ipv6_payload_len + 40U > ipv6_packet_len) {
        return;
    }
    const u_char *udp = data + 40;
    if (ipv6_payload_len < UDP_HEADER_LEN) {
        return;
    }
    uint16_t sport = (uint16_t)(udp[0] << 8 | udp[1]);
    uint16_t dport = (uint16_t)(udp[2] << 8 | udp[3]);
    uint16_t udp_len = (uint16_t)(udp[4] << 8 | udp[5]);
    if (udp_len < UDP_HEADER_LEN || udp_len > ipv6_payload_len) {
        return;
    }
    const u_char *payload = udp + UDP_HEADER_LEN;
    size_t payload_sz = udp_len - UDP_HEADER_LEN;

    packet_info_t info = {0};
    inet_ntop(AF_INET6, data + 8, info.src_addr, sizeof(info.src_addr));
    inet_ntop(AF_INET6, data + 24, info.dst_addr, sizeof(info.dst_addr));
    info.src_port = sport;
    info.dst_port = dport;
    info.ip_proto = IPPROTO_UDP;
    info.is_ipv6 = 1;

    handler(payload, payload_sz, &info);
}

typedef struct {
    payload_handler_t handler;
} payload_handler_ctx_t;

static void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    payload_handler_ctx_t *payload_handler = (payload_handler_ctx_t *)user;
    if (!payload_handler || !payload_handler->handler) {
        return;
    }
    payload_handler_t payload_handler_fn = payload_handler->handler;
    const u_char *data = packet;
    uint32_t remaining_len = pkthdr->caplen;
    uint16_t eth_type = 0;

    if (parse_link_layer(&data, &remaining_len, &eth_type) != 0) {
        return;
    }

    if (datalink_type == DLT_RAW) {
        /* Assume raw IP */
        if ((data[0] >> 4) == 4) {
            handle_ipv4(data, remaining_len, payload_handler_fn);
        } else if ((data[0] >> 4) == 6) {
            handle_ipv6(data, remaining_len, payload_handler_fn);
        }
        return;
    }

    switch (eth_type) {
    case ETHERTYPE_IPV4:
        handle_ipv4(data, remaining_len, payload_handler_fn);
        break;
    case ETHERTYPE_IPV6:
        handle_ipv6(data, remaining_len, payload_handler_fn);
        break;
    default:
        break;
    }
}

int start_capture(const capture_config_t *cfg, payload_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;

    if (cfg->pcap_file) {
        pcap = pcap_open_offline(cfg->pcap_file, errbuf);
    } else {
        if (!cfg->iface) {
            fprintf(stderr, "No interface specified for live capture\n");
            return -1;
        }
        pcap = pcap_open_live(cfg->iface, BUFSIZ, 1, 1000, errbuf);
    }

    if (!pcap) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return -1;
    }

    datalink_type = pcap_datalink(pcap);

    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, DEFAULT_DNS_RESPONSE_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return -1;
    }
    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap));
        pcap_freecode(&fp);
        pcap_close(pcap);
        return -1;
    }
    pcap_freecode(&fp);

    payload_handler_ctx_t payload_handler = {.handler = handler};
    int rc = pcap_loop(pcap, cfg->packet_count, packet_callback, (u_char *)&payload_handler);
    if (rc == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(pcap));
    }

    pcap_close(pcap);
    return rc;
}
