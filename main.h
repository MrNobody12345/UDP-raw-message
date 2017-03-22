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

#define SERVER "127.0.0.1"

/* calculate checksum routine */
unsigned short CalcIPChecksum(unsigned short *addr, unsigned int count);
unsigned short CalcTCPChecksum(struct iphdr *ip, unsigned short *ip_payload);
unsigned short CalcUDPChecksum(struct iphdr *ip, unsigned short *ip_payload);
unsigned short CalcICMPChecksum(unsigned short *ptr, int nbytes);

#endif
