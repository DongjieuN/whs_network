#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

void print_mac_address(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // check if it's an IP packet
        printf("Ethernet Header - Source MAC: ");
        print_mac_address(eth->ether_shost);
        printf("Ethernet Header - Destination MAC: ");
        print_mac_address(eth->ether_dhost);
        printf("\n");

        struct ip *iph = (struct ip *)(packet + sizeof(struct ethheader));
        printf("IP Header - Source IP: %s\n", inet_ntoa(iph->ip_src));
        printf("IP Header - Destination IP: %s\n", inet_ntoa(iph->ip_dst));

        if (iph->ip_p == IPPROTO_TCP) { // check if it's TCP
            int ip_header_len = iph->ip_hl << 2; // get the TCP header length
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            printf("TCP Header - Source Port: %d\n", ntohs(tcph->source));
            printf("TCP Header - Destination Port: %d\n", ntohs(tcph->dest));

            int tcp_header_len = tcph -> doff << 2; // get the payload length

	    int payload_length = ntohs(iph->ip_len) - (iph->ip_hl<<2) - tcp_header_len;

	    char* payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

	    int print_length = payload_length >10 ? 10 : payload_length;

	    for(int i=0;i<print_length;i++) {
		putchar(payload[i]);
	    }
	    putchar('\n');
            
       }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
	fprintf(stderr,"Couldn't open device ens33: %s\n",errbuf);
	return 2;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle

    return EXIT_SUCCESS;
}
