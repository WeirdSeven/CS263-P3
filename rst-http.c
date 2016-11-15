#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "sniffer.h"
#include "analyzer.h"
#include "logger.h"

char *get_ip_address(char *interface) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	 /* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	 /* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		perrno();
		exit(1);
	}

	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
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
		printf("Usage: rst-http [dev_name]\n");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}

	char *ip_address = get_ip_address(dev_name);
	printf("IP: [%s].\n", ip_address);
	char *filter_expr = "tcp src port 8181 and tcp[tcpflags] & tcp-ack != 0 and dst host ";
	strcat(filter_expr, ip_address);
	apply_filter(phandle, filter_expr);



	return 0;
}