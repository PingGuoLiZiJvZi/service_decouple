#ifndef __COMMON_H__
#define __COMMON_H__
#define REASON_FLOODING 0x01
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
struct event_data
{
	unsigned int reason;
	unsigned int packet_len;
	unsigned int ingress_ifc;
	unsigned int metadata[3];
};
struct eth_hdr
{
	unsigned long long dst : 48;
	unsigned long long src : 48;
	unsigned short proto;
} __attribute__((packed));
#endif