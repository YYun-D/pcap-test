#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//Ethernet Header
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet;
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

		//IP Header
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ethernet_hdr));
		if (ip_hdr->ip_p != IPPROTO_TCP) continue;

		// TCP Header
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

		//Ethernet Header의 source mac
		printf("Ethernet Header src mac : ");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

		//Ethernet Header의 destination mac
		printf("Ethernet Header dst mac : ");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		
		//IP Header의 source ip
		printf("IP Header src ip : %s\n", inet_ntoa(ip_hdr->ip_src)); //inet_ntoa() 함수는 주어진 struct in_addr에서 IP 주소를 포함하는 정적 문자열을 반환
		//IP Header의 destination ip
		printf("IP Header dst ip : %s\n\n", inet_ntoa(ip_hdr->ip_dst));

		// TCP Header의 source port
		printf("TCP Header src port: %d\n", ntohs(tcp_hdr->th_sport));
		// TCP Header의 destination port
		printf("TCP Header dst port: %d\n\n", ntohs(tcp_hdr->th_dport));

		// Payload(Data)의 hexadecimal value(최대 10바이트까지만)
		int payload_offset = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr->th_off * 4;
		int payload_len = header->len - payload_offset;

		if (payload_len > 0) {
			printf("Payload (Data) hexadecimal value : ");
			for (int i = 0; i < payload_len && i < 10; i++) {
				printf("%02x ", packet[payload_offset + i]);
			}
			printf("\n");
		}

		printf("-----------------------------------------------\n");
	}

	pcap_close(pcap);
}
