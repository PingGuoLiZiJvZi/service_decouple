/*
 * Copyright 2017 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../include/pcn.bpf.h"
#include <bpf/bpf_helpers.h>

/*
Router Port table provides a way to simulate the physical interface of the
router
The ip address is used to answer to the arp request (TO IMPLEMENT)
The mac address is used as mac_src for the outcoming packet on that interface,
and as mac address contained in the arp reply
*/
// Converted from BPF_TABLE('hash', u16, struct r_port, router_port, ROUTER_PORT_N)
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ROUTER_PORT_N);
	__type(key, u16);
	__type(value, struct r_port);
} router_port SEC(".maps");

struct arp_entry
{
	__be64 mac;
	u32 port;
} __attribute__((packed));
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ARP_TABLE_DIM);
	__type(key, u32);
	__type(value, struct arp_entry);
} arp_table SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, ROUTING_TABLE_DIM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct rt_k);
	__type(value, struct rt_v);
} routing_table SEC(".maps");
/*the function checks if the packet is an ICMP ECHO REQUEST and source mac is
 * not equal to in_port mac, if it is true sends the
 * packet to the slowpath. The slowpath searchs if the destination ip is one of
 * ip in the router and generates an echo reply
 */
static inline int send_packet_for_router_to_slowpath(struct xdp_md *ctx,
													 struct eth_hdr *eth,
													 struct iphdr *ip)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end)
		return XDP_DROP;
	// u32 mdata[3];
	// mdata[0] = ip->saddr;
	// mdata[1] = ip->daddr;
	// mdata[2] = ip->protocol;
	pcn_pkt_controller_with_metadata(ctx, SLOWPATH_PKT_FOR_ROUTER, ip->saddr, ip->daddr, ip->protocol);
	return XDP_DROP;
}
static inline int send_icmp_ttl_time_exceeded(struct xdp_md *ctx,

											  __be32 ip_port)
{
	// pcn_log(ctx, LOG_DEBUG, "packet DROP (ttl = 0)");
	LOG("packet DROP (ttl = 0)");
	// u32 mdata[3];
	// mdata[0] = ip_port;
	pcn_pkt_controller_with_metadata(ctx, SLOWPATH_TTL_EXCEEDED, ip_port, 0, 0);
	return XDP_DROP;
}
static inline int arp_lookup_miss(struct xdp_md *ctx,
								  __be32 dst_ip, u16 out_port, __be32 ip_port)
{
	// pcn_log(ctx, LOG_DEBUG, "arp lookup failed. Send to controller");
	LOG("arp lookup failed. Send to controller");

	// Set metadata and send packet to slowpath
	// u32 mdata[3];
	// mdata[0] = dst_ip;
	// mdata[1] = out_port;
	// mdata[2] = ip_port;
	pcn_pkt_controller_with_metadata(ctx, SLOWPATH_ARP_LOOKUP_MISS, dst_ip, out_port, ip_port);
	return XDP_DROP;
}
static inline __u16 checksum(unsigned short *buf, int bufsz)
{
	unsigned long sum = 0;

	while (bufsz > 1)
	{
		sum += *buf;
		buf++;
		bufsz -= 2;
	}
	if (bufsz == 1)
	{
		sum += *(unsigned char *)buf;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	// sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static __always_inline int send_packet_to_output_interface(
	struct xdp_md *ctx, struct eth_hdr *eth,
	struct iphdr *ip, __be32 nexthop, u16 out_port, __be32 ip_port,
	__be64 mac_port)
{
	__be32 dst_ip = 0;
	if (nexthop == 0)
		// Next Hop is local, directly lookup in arp table for the destination ip.
		dst_ip = ip->daddr;
	else
		// Next Hop not local, lookup in arp table for the next hop ip address.
		dst_ip = nexthop;
	// struct arp_entry *entry = arp_table.lookup(&dst_ip);
	struct arp_entry *entry = bpf_map_lookup_elem(&arp_table, &dst_ip);
	if (!entry)
		return arp_lookup_miss(ctx, dst_ip, out_port, ip_port);

	// pcn_log(ctx, LOG_TRACE, "in: %d out: %d REDIRECT", md->in_port, out_port);
	LOG("in: %d out: %d REDIRECT", ctx->ingress_ifindex, out_port);

	__be32 l3sum = 0;
	// eth->dst = *mac_entry;
	eth->dst = entry->mac;
	eth->src = mac_port;
	/* Decrement TTL and update checksum */
	__u32 new_ttl = ip->ttl - 1;

	ip->check = 0;
	ip->ttl = (__u8)new_ttl;
	ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

	return pcn_pkt_redirect(ctx, out_port);
}
static inline int search_secondary_address(__be32 *arr, __be32 ip)
{
	int i, size = MAX_SECONDARY_ADDRESSES;
	for (i = 0; i < size; i++)
	{
		if (arr[i] == ip)
			return i; /* found */
	}
	return (-1); /* if it was not found */
}
/*when an arp request is received, the router controls if the target if is one
 * of its interfaces,
 * if it is true, it sends an arp reply to the ingress port
 */
static inline int send_arp_reply(struct xdp_md *ctx,
								 struct eth_hdr *eth, struct arp_hdr *arp,
								 struct r_port *in_port)
{
	__be32 target_ip = arp->ar_tip;
	__be32 sender = 0;
	LOG("target_ip: %x,in_port_ip: %x", target_ip, in_port->ip);
	if (target_ip == in_port->ip)
		sender = in_port->ip;
	else
	{
		__be32 *arr = in_port->secondary_ip;
		int pos = search_secondary_address(arr, target_ip);
		if (pos > -1)
			sender = arr[pos];

		else
		{
			LOG("target_ip %x is not for me,drop packet", target_ip);
			return XDP_DROP;
		}
	}

	// pcn_log(ctx, LOG_DEBUG, "somebody is asking for my address");
	LOG("somebody is asking for my address");

	__be64 remotemac = arp->ar_sha;
	__be32 remoteip = arp->ar_sip;
	arp->ar_op = htons(ARPOP_REPLY);
	arp->ar_tha = remotemac;
	arp->ar_sha = in_port->mac;
	arp->ar_sip = sender;
	arp->ar_tip = remoteip;
	eth->dst = remotemac;
	eth->src = in_port->mac;
	/* register the requesting mac and ip */
	struct arp_entry entry;
	entry.mac = remotemac;
	entry.port = ctx->ingress_ifindex;
	// arp_table.update(&remoteip, &entry);
	bpf_map_update_elem(&arp_table, &remoteip, &entry, BPF_ANY);
	return pcn_pkt_redirect(ctx, ctx->ingress_ifindex);
}
static inline int notify_arp_reply_to_slowpath(struct xdp_md *ctx,

											   struct arp_hdr *arp)
{
	// pcn_log(ctx, LOG_DEBUG, "packet is arp reply");
	LOG("packet is arp reply");

	__be64 mac_ = arp->ar_sha;
	__be32 ip_ = arp->ar_sip;
	struct arp_entry entry;
	entry.mac = mac_;
	entry.port = ctx->ingress_ifindex;
	// arp_table.update(&ip_, &entry);
	// notify the slowpath. New arp reply received.
	// u32 mdata[3];
	// mdata[0] = ip_;
	pcn_pkt_controller_with_metadata(ctx, SLOWPATH_ARP_REPLY, ip_, 0, 0);
	return XDP_DROP;
}
static inline int is_ether_mcast(__be64 mac_address)
{
	return (mac_address & (__be64)MAC_MULTICAST_MASK);
}

SEC("xdp")
int xdp_router_rx(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		goto DROP;

	// pcn_log(ctx, LOG_TRACE, "in_port: %d, proto: 0x%x, mac_src: %M mac_dst: %M",
	// 		md->in_port, htons(eth->proto), eth->src, eth->dst);
	LOG("in_port: %d, proto: 0x%x", ctx->ingress_ifindex, htons(eth->proto));
	LOG("mac_src: %x mac_dst: %x", eth->src, eth->dst);

	u16 in_port_index = ctx->ingress_ifindex;
	// struct r_port *in_port = router_port.lookup(&in_port_index);
	struct r_port *in_port = bpf_map_lookup_elem(&router_port, &in_port_index);
	if (!in_port)
	{
		// pcn_log(ctx, LOG_ERR, "received packet from non valid port: %d",
		// 		md->in_port);
		LOG("received packet from non valid port: %d",
			ctx->ingress_ifindex);
		goto DROP;
	}
/*
Check if the mac destination of the packet is multicast, broadcast, or the
unicast address of the router port.  If not, drop the packet.
*/
#ifdef CHECK_MAC_DST
	if (eth->dst != in_port->mac && !is_ether_mcast(eth->dst))
	{
		LOG("mac destination %x MISMATCH %x", eth->dst,
			in_port->mac);
		goto DROP;
	}
#endif
	switch (htons(eth->proto))
	{
	case ETH_P_IP:
		goto IP; // ipv4 packet
	case ETH_P_ARP:
		goto ARP; // arp packet
	default:
	{
		LOG("unsupported ethertype 0x%x", htons(eth->proto));
		goto DROP;
	}
	}
IP:; // ipv4 packet
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		goto DROP;

	LOG("ttl: %u", ip->ttl);

	// find entry in routing table
	struct rt_k k = {32, ip->daddr};
	// struct rt_v *rt_entry_p = routing_table.lookup(&k);
	struct rt_v *rt_entry_p = bpf_map_lookup_elem(&routing_table, &k);
	if (!rt_entry_p)
	{
		// pcn_log(ctx, LOG_TRACE, "no routing table match for %I", ip->daddr);
		LOG("no routing table match for %x", ip->daddr);
		goto DROP;
	}
	/* Check if the pkt destination is one local interface of the router */
	if (rt_entry_p->type == TYPE_LOCALINTERFACE)
	{
		return send_packet_for_router_to_slowpath(ctx, eth, ip);
	}
	if (ip->ttl == 1)
	{
		return send_icmp_ttl_time_exceeded(ctx, in_port->ip);
	}
	// Select out interface
	u16 out_port = rt_entry_p->port;
	// struct r_port *r_port_p = router_port.lookup(&out_port);
	struct r_port *r_port_p = bpf_map_lookup_elem(&router_port, &out_port);
	if (!r_port_p)
	{
		// pcn_log(ctx, LOG_ERR, "out port '%d' not found", out_port);
		LOG("out port '%d' not found", out_port);
		goto DROP;
	}
	// redirect packet to out interface
	return send_packet_to_output_interface(ctx, eth, ip, rt_entry_p->nexthop,
										   out_port, r_port_p->ip, r_port_p->mac);
ARP:; // arp packet
	struct arp_hdr *arp = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*arp) > data_end)
		goto DROP;
	LOG("arp op: %u", htons(arp->ar_op));
	if (arp->ar_op == htons(ARPOP_REQUEST))
	{ // arp request?
		return send_arp_reply(ctx, eth, arp, in_port);
	}
	else if (arp->ar_op == htons(ARPOP_REPLY)) // arp reply
		return notify_arp_reply_to_slowpath(ctx, arp);
	return XDP_DROP;
DROP:
	LOG("in: %d out: -- DROP", ctx->ingress_ifindex);
	return XDP_DROP;
}
char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
