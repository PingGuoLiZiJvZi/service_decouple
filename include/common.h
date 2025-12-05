#ifndef __COMMON_H__
#define __COMMON_H__
#define REASON_FLOODING 0x01
#define XDP_FLAGS_SKB_MODE 1U << 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define MAX_SECONDARY_ADDRESSES 5 // also defined in bridge_ports.h
#define CHECK_MAC_DST
#define ROUTING_TABLE_DIM 256
#define ROUTER_PORT_N 32
#define ARP_TABLE_DIM 1024

#define TYPE_NOLOCALINTERFACE 0 // used to compare the 'type' field in the rt_v
#define TYPE_LOCALINTERFACE 1
#define IP_CSUM_OFFSET (sizeof(struct eth_hdr) + offsetof(struct iphdr, check))
#define ICMP_CSUM_OFFSET                             \
	(sizeof(struct eth_hdr) + sizeof(struct iphdr) + \
	 offsetof(struct icmphdr, checksum))
#define MAC_MULTICAST_MASK 0x1ULL // network byte order
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
struct rt_k
{
	unsigned int netmask_len;
	unsigned int network;
};
/* Routing Table Value
the type field is used to know if the destination is one interface of the router
*/
struct rt_v
{
	unsigned int port;
	unsigned int nexthop;
	unsigned char type;
};
/* Router Port, also defined in bridge_ports.h */
struct r_port
{
	unsigned int ip;
	unsigned int netmask;
	unsigned int secondary_ip[MAX_SECONDARY_ADDRESSES];
	unsigned int secondary_netmask[MAX_SECONDARY_ADDRESSES];
	unsigned long long mac : 48;
};
struct arp_hdr
{
	unsigned short ar_hrd;			/* format of hardware address	*/
	unsigned short ar_pro;			/* format of protocol address	*/
	unsigned char ar_hln;			/* length of hardware address	*/
	unsigned char ar_pln;			/* length of protocol address	*/
	unsigned short ar_op;			/* ARP opcode (command)		*/
	unsigned long long ar_sha : 48; /* sender hardware address	*/
	unsigned int ar_sip;			/* sender IP address		*/
	unsigned long long ar_tha : 48; /* target hardware address	*/
	unsigned int ar_tip;			/* target IP address		*/
}
__attribute__((packed));
enum
{
	SLOWPATH_ARP_REPLY = 1,
	SLOWPATH_ARP_LOOKUP_MISS,
	SLOWPATH_TTL_EXCEEDED,
	SLOWPATH_PKT_FOR_ROUTER
};
#endif