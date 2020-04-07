#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> //ipv4 ip_addr
#include "net.h"
#include <arpa/inet.h> // inet_ntoa > net add change
#include <netinet/tcp.h>

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
    //int totl; // IP total len
    int tcphl; // tcp header len
    //int payload;


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

                packet = packet+14;
                ip = (struct libnet_ipv4_hdr* )packet;
                iphl = (ip->ip_hl)*4; // ip header len
                //totl = ntohs(ip->ip_len); // total len


                packet = packet + iphl;
                tcp = (struct libnet_tcp_hdr* )packet;
                tcphl = (tcp->th_off)*4;
                //payload = totl - iphl - tcphl;


                if(ip->ip_p == 0x06){

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
                printf("src IP : %s\n", inet_ntoa(ip ->ip_src)); //net byte order > host byte order
                printf("dst IP : %s\n", inet_ntoa(ip ->ip_dst));
                printf("---------------------------");
                printf("\n\n");
                ///////////////////////////////////////////////////////
                printf("       TCP Header\n");
                printf("src port : %d\n", ntohs(tcp->th_sport)); //ntohs 2byte ntohl 4byte
                printf("dst port : %d\n", ntohs(tcp->th_dport));
                printf("---------------------------");
                printf("\n");
                printf("       Data\n");

                for(int i = 0; i<16; i++){
                     printf("%02x ", packet[14+iphl+tcphl]+i);
                    }
                printf("---------------------------");
                }
                printf("\n\n");

                //////////////////////////////////////////////////////
            }
    pcap_close(handle);
}

