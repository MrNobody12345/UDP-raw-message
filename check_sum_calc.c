#include "main.h"

/*
 * calculate ip checksum (first 20 bytes)
 */
unsigned short CalcIPChecksum(unsigned short *addr, unsigned int count) {
  unsigned long sum = 0;

  while (count > 1) {
    sum += *addr++;
    count -= 2;
  }

  /* if any bytes left, pad the bytes and add */

  if(count > 0) {
    sum += ((*addr) & htons(0xFF00));
  }

  /* fold sum to 16 bits: add carrier to result */
  while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  /* one's complement */
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set udp checksum: given IP header and UDP datagram */

unsigned short CalcUDPChecksum(struct iphdr *ip, unsigned short *ip_payload) {
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ip_payload);
    unsigned short udpLen = htons(udphdrp->len);

    /* the source ip */
    sum += (ip->saddr>>16)&0xFFFF;
    sum += (ip->saddr)&0xFFFF;
    /* the dest ip */
    sum += (ip->daddr>>16)&0xFFFF;
    sum += (ip->daddr)&0xFFFF;
    /* protocol and reserved: 17 */
    sum += htons(IPPROTO_UDP);
    /* the length */
    sum += udphdrp->len;

    /* initialize checksum to 0 */
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ip_payload++;
        udpLen -= 2;
    }

    /* if any bytes left, pad the bytes and add */
    if(udpLen > 0) {
        sum += ((*ip_payload)&htons(0xFF00));
    }

    /* fold sum to 16 bits: add carrier to result */
    while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    /* set computation result */
    return ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}
