#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sniffer.h"

void print_hex_memory(const void *mem, int len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i = 0;i < len; i++) {
    printf("0x%02x ", p[i]);
    if (i % 16 == 0)
      printf("\n");
  }
  printf("\n");
}


void log_headers(struct hdrs *headers) {
	struct ethernet_hdr *ethernet_header = headers->ethernet_header;
	printf("ETHERNET: src[%s] dst[%s]\n", ether_ntoa((struct ether_addr*)&ethernet_header[6]), 
										ether_ntoa((struct ether_addr*)&ethernet_header[0]));

	struct ip_hdr *ip_header = headers->ip_header;
	printf("IP: src[%s] dst[%s]\n", inet_ntoa(ip_header->ip_src_addr),
		                          inet_ntoa(ip_header->ip_dst_addr));
	printf("    ip_hdr_len[%u] ip_data_len[%u] Protocol: %s\n", (ip_header->ip_hlen) * 4, 
															    ntohs(ip_header->ip_len) - (ip_header->ip_hlen) * 4, 
															    headers->protocol);

	if (ip_header->ip_protocol == IP_ICMP) {
		struct icmp_hdr *icmp_header = headers->icmp_header;
		if (icmp_header->type == ICMP_ECHOREPLY) {
			printf("ICMP: type[ICMP_ECHOREPLAY] id[%u] seq[%u]", ntohs(icmp_header->un.echo.id), ntohs(icmp_header->un.echo.seq));
		} else if (icmp_header->type == ICMP_ECHO) {
			printf("ICMP: type[ICMP_ECHO] id[%u] seq[%u]", ntohs(icmp_header->un.echo.id), ntohs(icmp_header->un.echo.seq));
		}
	} else if (ip_header->ip_protocol == IP_TCP) {
		struct tcp_hdr *tcp_header = headers->tcp_header;
		printf("TCP: src_port[%u] dst_port[%u]\n", ntohs(tcp_header->tcp_src_port), ntohs(tcp_header->tcp_dst_port));
		printf("     seq_num[%u] ack_num[%u]\n", ntohl(tcp_header->tcp_seq), ntohl(tcp_header->tcp_ack));
		printf("     tcp_hdr_len[%u] tcp_data_len[%u]\n", (tcp_header->tcp_off) * 4, 
			                                              ntohs(ip_header->ip_len) - (ip_header->ip_hlen + tcp_header->tcp_off) * 4);
	}
}



#endif
