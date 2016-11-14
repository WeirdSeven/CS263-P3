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
	printf("IP: src[%s] dst[%s]", inet_ntoa(ip_header->ip_src_addr),
		                          inet_ntoa(ip_header->ip_dst_addr));
	printf("   ip_hdr_len[%d] ip_data_len[%d] Protocol: %s\n", ip_header->ip_hlen, ((ip_header->len) - (ip_header->hlen)), headers->protocol);
	//printf("ETHERNET: src[0c:df:27:16:b8:30] dst[50:5a:00:12:35:02]");
}



#endif
