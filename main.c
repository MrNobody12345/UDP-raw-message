#include "main.h"

int main(void) {
  int master_sock;
  int psize;
  /* datagram to represent the packet */
  char datagram[4096], source_ip[32], *data, *pseudogram;
  struct iphdr *iph;
  struct udphdr *udph;
  struct sockaddr_in sin;

  struct pseudo_header psh;
  /* create a raw socket of type IPPROTO */
  master_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if (master_sock == -1) {
    /* socket creation failed, may be because of non-root privileges */
    perror("Failed to create raw socket");
    exit(1);
  }

  iph = (struct iphdr *) datagram;
  udph = (struct udphdr *) (datagram + sizeof(struct iphdr));

  /* zero out the packet buffer */
  memset(datagram, 0, 4096);

  /* data part */
  data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
  strcpy(data, "Hello, world!");

  strcpy(source_ip, "192.168.0.104");

  sin.sin_family = AF_INET;
  sin.sin_port = htons(8888);
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");

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
  udph->source = htons(6666);
  udph->dest = htons(8888);
  udph->len = htons(8 + strlen(data)); /* udp header size */
  udph->check = 0; /* leave checksum 0 now, filled later by pseudo header */

  /* now the UDP checksum using the pseudo header */
  psh.source_address = inet_addr(source_ip);
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_UDP;
  psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

  psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);

  pseudogram = (char *) malloc(sizeof(char) * psize);
  memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), udph,
         sizeof(struct udphdr) + strlen(data));

  udph->check = CalcUDPChecksum(iph, (unsigned short *) udph);

  if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin,
             sizeof(sin)) < 0) {
    perror("sendto failed");
  } else {
    printf("Packet Send. Length : %d \n", iph->tot_len);
  }
  free(pseudogram);
  return 0;
}
