#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct tcpheader{
	unsigned short int tcp_sport;
	unsigned short int tcp_dport;
	unsigned int seq_number;
	unsigned int ack_number;
	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flags;
	unsigned short int tcp_window;
	unsigned short int tcp_check;
	unsigned short int tcp_urgent;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));
    struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip-> iph_ihl*4);
    //const char *data = (const char *)(packet + sizeof(struct ethheader) + ip ->iph_ihl * 4 + tcp->tcp_offset * 4);
    int ip_header_len = ip->iph_ihl * 4;
    int tcp_header_len = tcp->tcp_offset * 4;
    int total_len = ntohs(ip->iph_len);
    int payload_len = total_len - ip_header_len - tcp_header_len;
    char *dest_host = eth->ether_dhost;
    char *src_host = eth->ether_shost;
    const char *data = (const char *)(packet + sizeof(struct ethheader) + ip_header_len+ tcp_header_len);
    printf("Destination mac: ");
    for(int i = 0; i < 6; i++){
	printf("%02x", dest_host[i]);
	if (i != 5) printf(":");
    }
    printf("\n");

    printf("Source mac: ");
    for(int i = 0; i < 6; i++){
	printf("%02x", src_host[i]);
	if (i != 5) printf(":");
    }
    printf("\n");
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
    printf("Source port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination port: %d\n", ntohs(tcp->tcp_dport));

    if(payload_len > 0){
	    printf("Http Message\n");
	    printf("%d\n", payload_len);

	    fwrite(data, 1, payload_len, stdout);
	    printf("\n--------------------\n");
    }
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", 65535, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

