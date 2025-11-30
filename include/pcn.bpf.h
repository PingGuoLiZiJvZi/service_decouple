#ifndef __PCN_BPF_H__
#define __PCN_BPF_H__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#define ENABLE_LOGGING 1
#ifdef ENABLE_LOGGING
#define LOG(fmt, ...) bpf_printk("[LOG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ;
#endif
static __always_inline __u16 htons(__u16 val)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(val);
#else
	return val;
#endif
}
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
	event.metadata[0] = 0;
	event.metadata[1] = 0;
	event.metadata[2] = 0;
	bpf_perf_event_output(pkt, &events, flags, &event, sizeof(event));
	return XDP_DROP;
}
static __always_inline int pcn_pkt_controller_with_metadata(struct xdp_md *pkt,
															u16 reason,
															u32 mdata0, u32 mdata1, u32 mdata2)
{
	struct event_data event;
	event.reason = reason;
	event.packet_len = pkt->data_end - pkt->data;
	event.ingress_ifc = pkt->ingress_ifindex;
	u64 flags = BPF_F_CURRENT_CPU;
	flags |= (u64)event.packet_len << 32;
	event.metadata[0] = mdata0;
	event.metadata[1] = mdata1;
	event.metadata[2] = mdata2;
	bpf_perf_event_output(pkt, &events, flags, &event, sizeof(event));
	return XDP_DROP;
}
static __always_inline int pcn_pkt_redirect(struct xdp_md *pkt, u32 out_port)
{
	return bpf_redirect(out_port, 0);
}
#endif // __PCN_BPF_H__