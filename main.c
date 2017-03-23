#include "main.h"

int main(void) {
  int master_sock;
  int packet_size;
  unsigned int slen;
  int one = 1;
  uint8_t src_mac[6];
  const int *val = &one;
  /* datagram to represent the packet */
  char datagram[4096], source_ip[32], interface[40], *data;
  struct ether_header *eth;
  struct iphdr *iph;
  struct udphdr *udph;
  struct sockaddr_in sin;
  struct sockaddr_ll device;
  struct ifreq ifr;

  /* create a raw socket */
  master_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

  if (master_sock == -1) {
    /* socket creation failed, may be because of non-root privileges */
    perror("Failed to create raw socket");
    exit(1);
  }

  strcpy(interface, "lo");

  /* use ioctl() to look up interface name and get its MAC address */
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (master_sock, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (master_sock);

  /* copy source MAC address */
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));


  /* find interface index from interface name and store index in
   * struct sockaddr_ll device, which will be used as an argument of sendto()
   */
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }

  /* fill out sockaddr_ll */
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  eth = (struct ether_header *) datagram;
  iph = (struct iphdr *) (datagram + sizeof(struct ether_header));
  udph = (struct udphdr *) (datagram + sizeof(struct iphdr) + sizeof(struct ether_header));

  /* zero out the packet buffer */
  memset(datagram, 0, 4096);

  /* data part */
  data = datagram + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(data, "Hello, world!");

  strcpy(source_ip, "127.0.0.1");

  sin.sin_family = AF_INET;
  sin.sin_port = htons(8888);
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* fill in the ethernet Header */
  eth->ether_type = htons(ETH_P_IP);
  memcpy(eth->ether_shost, src_mac, 6);
  memcpy(eth->ether_dhost, src_mac, 6);

  /* fill in the IP Header */
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data));
  iph->id = htons(54321); /* id of this packet */
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0; /* Set to 0 before calculating checksum */
  iph->saddr = inet_addr(source_ip); /* spoof the source ip address */
  iph->daddr = sin.sin_addr.s_addr;

  /* IP checksum */
  iph->check = CalcIPChecksum((unsigned short*) iph, iph->ihl << 2);

  /* UDP header */
  udph->source = htons(8822);
  udph->dest = htons(8888);
  udph->len = htons(8 + strlen(data)); /* udp header size */
  udph->check = 0; /* leave checksum 0 now, filled later by pseudo header */

  udph->check = CalcUDPChecksum(iph, (unsigned short *) udph);

  /* create a raw socket */
  master_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (master_sock == -1) {
    /* socket creation failed, may be because of non-root privileges */
    perror("Failed to create raw socket");
    exit(1);
  }

  slen = sizeof(device);
  packet_size = strlen(data) + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (sendto(master_sock, datagram, packet_size, 0, (struct sockaddr *) &device,
             slen) == -1) {
    perror("sendto failed");
  } else {
    printf("Packet Send. Length : %d \n", iph->tot_len);
  }
  /* zero out the packet buffer */
  memset(datagram, 0, 4096);
  slen = sizeof(sin);
  /* try to receive some data, this is a blocking call */
  if (recvfrom(master_sock, datagram, 512, 0, (struct sockaddr *) &sin,
             &slen) == -1) {
    perror("recvfrom");
    return EXIT_FAILURE;
  }

  printf("Echo: %s", datagram + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ether_header));

  return 0;
}
