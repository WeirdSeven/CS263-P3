#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <pcap/pcap.h>
#include <netinet/ether.h>
#include "sniffer.h"

void log_headers(struct hdrs *headers) {
	struct ethernet_hdr *ethernet_header = headers->ethernet_header;
	//struct ether_addr ether_src_addr;
	//struct ether_addr ether_dst_addr;
	//ether_src_addr.ether_addr_octet = (u_int8_t[6])ethernet_header->ether_src_addr;
	//ether_dst_addr.ether_addr_octet = (u_int8_t[6])ethernet_header->ether_dst_addr;
	printf("ETHERNET: src[%s] dst[%s]", ether_ntoa((struct ether_addr*)&ethernet_header[6]), ether_ntoa((struct addr*)&ethernet_header[0]));
	//printf("ETHERNET: src[0c:df:27:16:b8:30] dst[50:5a:00:12:35:02]");
}



#endif
