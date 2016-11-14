#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "sniffer.h"
#include "analyzer.h"
#include "logger.h"


int device_exists(char *target) {
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		pcap_freealldevs(alldevsp);
		return 0;
	}

	pcap_if_t *dev = alldevsp;
	while(dev) {
		if (strcmp(dev->name, target) == 0) {
			pcap_freealldevs(alldevsp);
			return 1;
		}		
		dev = dev->next;
	}
	pcap_freealldevs(alldevsp);
	return 0;
}

pcap_t *open_phandle(char *dev_name, char *errbuf) {
	pcap_t *phandle = pcap_create(dev_name, errbuf);
	if (phandle == NULL)
		return NULL;

	pcap_set_promisc(phandle, 1);
	pcap_set_snaplen(phandle, 65535);
	pcap_activate(phandle);

	const char *filter_rule = "dst port 22"
	struct bpf_program fp;
	if (pcap_compile(phandle, &fp, filter_rule, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		printf("Filter compile error: %s.\n", pcap_geterr(phandle));
		exit(1);
	}
	if (pcap_setfilter(phandle, &fp) == -1) {
		printf("Filter set error: %s.\n", pcap_geterr(phandle));
		exit(1);
	}

	return phandle;
}


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

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	// Retrieve the packets 
	int res;
    while((res = pcap_next_ex(phandle, &header, &pkt_data)) >= 0){
        
        // 0 means that libpcap's read timeout expired
        if(res == 0)
            continue;
        
        printf("Packet length:%d\n", header->len);
    }

    if (res == -1) {
        printf("An error occurred while reading the packet.\n");
        exit(1);
    } else if (res == -2) {
        // TODO
    }

	return 0;
}