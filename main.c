#include "main.h"

int main(void) {
  int master_sock;
  int slen;
  int one = 1;
  int i;
  const int *val = &one;
  /* datagram to represent the packet */
  char datagram[4096], source_ip[32], *data;
  struct iphdr *iph;
  struct udphdr *udph;
  struct sockaddr_in sin;
  struct sockaddr_in client;

  /* create a raw socket of type IPPROTO */
  master_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

  if (master_sock == -1) {
    /* socket creation failed, may be because of non-root privileges */
    perror("Failed to create raw socket");
    exit(1);
  }
  /* inform the kernel do not fill up the packet structure. we will build our own...*/
  if (setsockopt(master_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    perror("setsockopt() error");
    exit(-1);
  } else
    printf("setsockopt() is OK.\n");

  iph = (struct iphdr *) datagram;
  udph = (struct udphdr *) (datagram + sizeof(struct iphdr));

  /* zero out the packet buffer */
  memset(datagram, 0, 4096);

  /* data part */
  data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(data, "Hello, world!");

  strcpy(source_ip, "127.0.0.1");

  sin.sin_family = AF_INET;
  sin.sin_port = htons(8888);
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  client.sin_family = AF_INET;
  client.sin_port = htons(8822);
  client.sin_addr.s_addr = INADDR_ANY;

  /* fill in the IP Header */
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
  iph->id = htonl(54321); /* id of this packet */
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
  slen = sizeof(sin);
  if (sendto(master_sock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin,
             slen) == -1) {
    perror("sendto failed");
  } else {
    printf("Packet Send. Length : %d \n", iph->tot_len);
  }
  /* zero out the packet buffer */
  memset(datagram, 0, 4096);
  /* try to receive some data, this is a blocking call */
  if (recvfrom(master_sock, datagram, 512, 0, (struct sockaddr *) &sin,
             &slen) == -1) {
    perror("recvfrom");
    return EXIT_FAILURE;
  }

  printf("Echo: %s", datagram + sizeof(struct iphdr) + sizeof(struct udphdr));

  return 0;
}
