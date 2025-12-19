#include "capture.h"
#include "dns_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-i interface] [-r pcap_file] [-c count]\n", prog);
    fprintf(stderr, "  -i interface   Capture on interface (live capture)\n");
    fprintf(stderr, "  -r file        Read from pcap/pcapng file instead of live capture\n");
    fprintf(stderr, "  -c count       Number of packets to process (0 = infinite, default)\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s -i wlp1s0\n", prog);
    fprintf(stderr, "  %s -r sample.pcapng\n", prog);
}

int main(int argc, char **argv) {
    capture_config_t cfg = {0};
    int opt;

    while ((opt = getopt(argc, argv, "i:r:c:h")) != -1) {
        switch (opt) {
        case 'i':
            cfg.iface = optarg;
            break;
        case 'r':
            cfg.pcap_file = optarg;
            break;
        case 'c':
            cfg.packet_count = atoi(optarg);
            if (cfg.packet_count < 0) {
                fprintf(stderr, "Invalid packet count: %s\n", optarg);
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!cfg.iface && !cfg.pcap_file) {
        usage(argv[0]);
        return 1;
    }

    if (start_capture(&cfg, process_dns_response) != 0) {
        return 1;
    }
    return 0;
}
