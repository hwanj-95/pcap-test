#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> //ipv4 ip_addr
#include "net.h"
#include <arpa/inet.h> // inet_ntoa > net add change
//#include <netinet/tcp.h>
#include <net/ethernet.h> //Use ETHERTYPE_IP
#include <linux/in.h> //Use IPPROTO_TCP#
#include <algorithm>
using namespace std;

//#define iplen 16

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        usage();
        return -1;
    }

    struct libnet_ethernet_hdr* eth;
    struct libnet_ipv4_hdr* ip;
    struct libnet_tcp_hdr* tcp;

    int iphl; // IP header len
    int totl; // IP total len
    int tcphl; // tcp header len
    int payload;// payload len


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet; //packet start point
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        eth = (struct libnet_ethernet_hdr* )packet;
        if(ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

        packet = packet+14;
        ip = (struct libnet_ipv4_hdr* )packet;
        iphl = (ip->ip_hl)*4; // ip header len
        totl = ntohs(ip->ip_len); // total len
        packet = packet + iphl;

        if(ip->ip_p != IPPROTO_TCP) continue;

        tcp = (struct libnet_tcp_hdr* )packet;
        tcphl = (tcp->th_off)*4;

        payload = totl - iphl - tcphl;

        printf("       Ethernet Header\n");
        printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0],eth->ether_shost[1],
                eth->ether_shost[2],eth->ether_shost[3],
                eth->ether_shost[4],eth->ether_shost[5]);
        printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0],eth->ether_dhost[1],
                eth->ether_dhost[2],eth->ether_dhost[3],
                eth->ether_dhost[4],eth->ether_dhost[5]);
        printf("---------------------------");
        printf("\n\n");
        /////////////////////////////////////////////////////
        printf("       IP Header\n");
        char sorce_src[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&ip->ip_src, sorce_src, INET_ADDRSTRLEN);
        char sorce_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&ip->ip_dst, sorce_dst, INET_ADDRSTRLEN);
        printf("src IP : %s\n", sorce_src); //net byte order > host byte order
        printf("dst IP : %s\n", sorce_dst);
        printf("---------------------------");
        printf("\n\n");
        ///////////////////////////////////////////////////////
        printf("       TCP Header\n");
        printf("src port : %d\n", ntohs(tcp->th_sport)); //ntohs 2byte ntohl 4byte
        printf("dst port : %d\n", ntohs(tcp->th_dport));
        printf("---------------------------");
        printf("\n\n");
        printf("       Data\n");

        packet = packet+tcphl;

        int write_len = min(16, payload);
        for(int i = 0; i<write_len; i++){
            printf("%02x ", *packet++);
        }
        printf("\n");
        printf("---------------------------");
        printf("\n\n");
    }
    printf("\n\n");

    pcap_close(handle);
}

