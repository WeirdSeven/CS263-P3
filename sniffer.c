#include #include <pcap/pcap.h>

#include "sniffer.h"
#include "analyzer.h"
#include "logger.h"


int main() {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp;

	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	pcap_if_t *dev = alldevsp;
	while(dev) {
		printf("Device found: [%s].\n", dev->name);
		if (dev->description) {
			printf("\tDescription: [%s].\n", dev->description);
		} else {
			printf("No description.\n");
		}
	}


	pcap_t phandle;



	return 0;
}