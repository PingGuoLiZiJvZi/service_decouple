#ifndef __SIMPLEBRIDGE_H__
#define __SIMPLEBRIDGE_H__
#define REASON_FLOODING 0x01
struct event_data
{
	unsigned int reason;
	unsigned int packet_len;
	unsigned int ingress_ifc;
};
struct eth_hdr
{
	unsigned long long dst : 48;
	unsigned long long src : 48;

	unsigned short proto;
} __attribute__((packed));

#endif // __SIMPLEBRIDGE_COMMON_DEF_H__