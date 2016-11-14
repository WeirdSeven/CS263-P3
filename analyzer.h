#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include <pcap/pcap.h>
#include <string.h>
#include "sniffer.h"

struct hdrs *analyze_packet(const u_char *packet) {
	struct hdrs *ret = (struct hdrs *)malloc(sizeof(struct hdrs));
	ret->ethernet_header = (struct ethernet_hdr *)packet;
	ret->ip_header = (struct ip_hdr *)(packet + ETHER_HDR_LEN);
	int ip_header_length = (ret->ip_header->ip_hlen) * 4;
	if (ip_header_length < 20) {
		printf("Invalid IP header length: %d bytes.\n", ip_header_length);
		exit(1);
	}

	int protocol = ret->ip_header->ip_protocol;
	if (protocol == IP_ICMP) {
		printf("ICMP packet!\n");
		ret->icmp_header = (struct icmp_hdr *)(packet + ETHER_HDR_LEN + ip_header_length);
		ret->tcp_header = NULL;
		ret->payload = NULL;
		strcpy(ret->protocol, "ICMP");
	} else if (protocol == IP_TCP) {
		printf("TCP packet!\n");
		ret->icmp_header = NULL;
		ret->tcp_header = (struct tcp_hdr *)(packet + ETHER_HDR_LEN + ip_header_length);
		int tcp_header_length = (ret->tcp_header->tcp_off) * 4;
		if (tcp_header_length < 20) {
			printf("Invalid TCP header length: %d bytes.\n", tcp_header_length);
			exit(1);
		}
		ret->payload = (char *)(packet + ETHER_HDR_LEN + ip_header_length + tcp_header_length);
		strcpy(ret->protocol, "TCP");
	} else if (protocol == IP_UDP) {
		printf("UDP packet!\n");
		ret->icmp_header = NULL;
		ret->tcp_header = NULL;
		ret->payload = NULL;
		strcpy(ret->protocol, "UDP");
	} else {
		printf("Other packet!\n");
		ret->icmp_header = NULL;
		ret->tcp_header = NULL;
		ret->payload = NULL;
		strcpy(ret->protocol, "Other");
	}
	return ret;
}

#endif
