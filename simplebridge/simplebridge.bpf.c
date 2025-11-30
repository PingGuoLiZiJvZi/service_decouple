#ifndef FDB_TIMEOUT
#define FDB_TIMEOUT 300
#endif

#include "../include/pcn.bpf.h"

struct fwd_entry
{
	__u32 timestamp;
	__u32 port;
} __attribute__((packed, aligned(8)));

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be64);
	__type(value, struct fwd_entry);
} fwdtable SEC(".maps");

static __always_inline __u32 time_get_sec()
{
	return bpf_ktime_get_ns() >> 30;
}
SEC("xdp")
int xdp_simplebridge_rx(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth = data;

	if (data + sizeof(*eth) > data_end)
		return XDP_DROP;

	__u32 in_ifc = ctx->ingress_ifindex;

	LOG("Received a new packet from port %d mac src:%x dst:%x", in_ifc, eth->src, eth->dst);

	__be64 src_key = eth->src;
	__u32 now = time_get_sec();

	struct fwd_entry *entry = bpf_map_lookup_elem(&fwdtable, &src_key);
	if (!entry)
	{
		struct fwd_entry e;

		e.timestamp = now;
		e.port = in_ifc;

		bpf_map_update_elem(&fwdtable, &src_key, &e, BPF_ANY);
		LOG("MAC: %x learned", src_key);
	}
	else
	{
		entry->port = in_ifc;
		entry->timestamp = now;
		LOG("MAC: %x updated", src_key);
	}

	__be64 dst_mac = eth->dst;

	entry = bpf_map_lookup_elem(&fwdtable, &dst_mac);
	if (!entry)
	{
		LOG("Entry not found for dst-mac: %x", dst_mac);
		goto DO_FLOODING;
	}

	__u64 timestamp = entry->timestamp;

	if ((now - timestamp) > FDB_TIMEOUT)
	{
		LOG("Entry is too old. FLOODING");
		bpf_map_delete_elem(&fwdtable, &dst_mac);
		goto DO_FLOODING;
	}
	LOG("Entry is valid. FORWARDING");

FORWARD:;
	__u32 dst_interface = entry->port;

	if (dst_interface == in_ifc)
	{
		LOG("Destination interface is equals to the input interface. DROP packet");

		return XDP_DROP;
	}
	LOG("Redirect packet to port %d", dst_interface);

	return pcn_pkt_redirect(ctx, dst_interface);

DO_FLOODING:
	LOG("Flooding required: sending packet to controller");
	pcn_pkt_controller(ctx, REASON_FLOODING);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
