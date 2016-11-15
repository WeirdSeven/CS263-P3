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

pcap_t *global_phandle;

void SIGINT_handler(int num) {
	printf("Before\n");
	pcap_breakloop(global_phandle);
	pcap_close(global_phandle);
	printf("After\n");
}

char *get_ip_address(char *interface) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		perror("Getting IP address: ");
		exit(1);
	}

	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int send_rst_packet(struct hdrs *headers, libnet_t *l, libnet_ptag_t *tcp_tag, libnet_ptag_t *ipv4_tag) {
	struct tcp_hdr *tcp_header = headers->tcp_header;
	struct ip_hdr *ip_header = headers->ip_header;	

	*tcp_tag = libnet_build_tcp(ntohs(tcp_header->tcp_dst_port), //source port
				              ntohs(tcp_header->tcp_src_port), //destination port
				              ntohl(tcp_header->tcp_ack) + 1, //sequence number
				              ntohl(tcp_header->tcp_seq), //acknowledgement number
				              TCP_RST, //flags
				              1024, //window size
				              0, //checksum
				              0, //urgent pointer
				              20, //TCP packet length
				              NULL, //payload pointer
				              0, //payload length
				              l,
				              *tcp_tag);
	if (*tcp_tag == -1) {
		printf("Can't build TCP header: %s\n", libnet_geterror(l));
		exit(1);
	}

	*ipv4_tag = libnet_build_ipv4(40, //IP packet length
								 0, //type of service
								 0, //id
								 0, //fragmentation bits 
								 64, //time to live
								 IPPROTO_TCP, //protocol
								 0, //checksum
								 *(uint32_t *)&(ip_header->ip_dst_addr), //source IP address
								 *(uint32_t *)&(ip_header->ip_src_addr), //destination IP address
								 NULL, //payload poitner
								 0, //payload length
								 l,
								 *ipv4_tag);
	if (*ipv4_tag == -1) {
		printf("Can't build IPv4 header: %s\n", libnet_geterror(l));
		exit(1);
	}

    if (libnet_write(l) == -1) {
    	printf("Error writing packet: %s\n", libnet_geterror(l));
    	exit(1);
    }

    printf("RST Packet sent!\n");
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

	struct sigaction action;
	action.sa_handler = SIGINT_handler;
	if (sigaction(SIGINT, &action, NULL) < 0) {
		perror("SIGINT sigaction");
		exit(1);
	}
	if (sigaction(SIGQUIT, &action, NULL) < 0) {
		perror("SIGINT sigaction");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}
	global_phandle = phandle;

	char *temp = get_ip_address(dev_name);
	char *ip_address = (char *)malloc(strlen(temp) + 1);
	strcpy(ip_address, temp);
	char filter_expr[200];
	strcpy(filter_expr, "tcp src port 8181 and tcp[tcpflags] & tcp-ack != 0 and dst host ");
	strcat(filter_expr, ip_address);
	printf("Filter expression: %s\n", filter_expr);
	apply_filter(phandle, filter_expr);

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	
	char errbuf2[LIBNET_ERRBUF_SIZE]; 
	libnet_t *l = libnet_init(LIBNET_RAW4, dev_name, errbuf2);
	if (l == NULL) {
		printf("libnet_init(): %s\n", errbuf2);
		exit(1);
	} 

	libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
	libnet_ptag_t ipv4_tag = LIBNET_PTAG_INITIALIZER;

	int res;
	struct hdrs *headers;
    while((res = pcap_next_ex(phandle, &header, &pkt_data)) >= 0){ 
    	printf("1\n");
        // 0 means that libpcap's read timeout expired
        if(res == 0)
            continue;
        printf("2\n");

        printf("Packet captured!\n");

        headers = analyze_packet(pkt_data);

        log_headers(headers);

		send_rst_packet(headers, l, &tcp_tag, &ipv4_tag);

        printf("---------------------------------------------\n");
    }
    printf("3\n");

    if (res == -1) {
        printf("An error occurred while reading the packet.\n");
        exit(1);
    } else if (res == -2) {
    	printf("In handler\n");
    	free(ip_address);
    	free(headers);
    	libnet_destroy(l);
        
        printf("All resources deallocated.\n");
    }

	return 0;
}