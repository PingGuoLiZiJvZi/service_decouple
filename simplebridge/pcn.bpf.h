#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "simplebridge.h"
// #include <linux/bpf.h>
// #include <linux/filter.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/in.h>
// #include <linux/ip.h>
// #include <linux/pkt_cls.h>
// #include <linux/types.h>

#define ENABLE_LOGGING 1
#ifdef ENABLE_LOGGING
#define LOG(fmt, ...) bpf_printk("[LOG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ;
#endif

//------------------------通过 perf map 通知用户态------------------------
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int pcn_pkt_controller(struct xdp_md *pkt,
											  u16 reason)
{
	struct event_data event;
	event.reason = reason;
	event.packet_len = pkt->data_end - pkt->data;
	event.ingress_ifc = pkt->ingress_ifindex;
	u64 flags = BPF_F_CURRENT_CPU;
	flags |= (u64)event.packet_len << 32;
	bpf_perf_event_output(pkt, &events, flags, &event, sizeof(event));
	return XDP_DROP;
}
static __always_inline int pcn_pkt_redirect(struct xdp_md *pkt, u32 out_port)
{
	return bpf_redirect(out_port, 0);
}