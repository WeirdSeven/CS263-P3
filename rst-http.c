#include <pcap/pcap.h>
#include <libnet.h>
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
		printf("Usage: rst-http [dev_name]\n");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}

	apply_filter(phandle, "tcp src port 8181 and tcp[tcpflags] & tcp-ack != 0")



	return 0;
}