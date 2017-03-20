#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

/*
 * 96 bit (12 bytes) pseudo header needed for udp header checksum calculation
 */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};


/* calculate checksum routine */
unsigned short CalcIPChecksum(unsigned short *addr, unsigned int count);
unsigned short CalcTCPChecksum(struct iphdr *ip, unsigned short *ip_payload);
unsigned short CalcUDPChecksum(struct iphdr *ip, unsigned short *ip_payload);
unsigned short CalcICMPChecksum(unsigned short *ptr, int nbytes);

#endif
