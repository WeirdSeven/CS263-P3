#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "sniffer.h"
#include "analyzer.h"
#include "logger.h"

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];

	char *dev_name;
	if (argc == 1) {
		dev_name = "eth0";
	} else if (argc == 2) {
		dev_name = argv[1];
		if (!device_exists(dev_name)) {
			printf("Device does not exist.\n");
			exit(1);
		}
	} else {
		printf("Usage: sniffer [dev_name]\n");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}

	if (pcap_datalink(phandle) != DLT_EN10MB) {
		printf("%s is not an Ethernet.\n", dev_name);
		exit(1);
	}

	apply_filter(phandle, "not port 22");

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	// Retrieve the packets 
	int res;
    while((res = pcap_next_ex(phandle, &header, &pkt_data)) >= 0){
        
        // 0 means that libpcap's read timeout expired
        if(res == 0)
            continue;

        //printf("Packet cap length:%d\n", header->caplen);
        //printf("Packet length:%d\n", header->len);

        //printf("Dump packet...");
        //print_hex_memory((const void *)pkt_data, header->len);

        struct hdrs *headers = analyze_packet(pkt_data);
        log_headers(headers);
    }

    if (res == -1) {
        printf("An error occurred while reading the packet.\n");
        exit(1);
    } else if (res == -2) {
        // TODO
    }

	return 0;
}