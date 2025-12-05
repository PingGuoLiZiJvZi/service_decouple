#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

SEC("tp_btf/xdp_redirect_err")
int BPF_PROG(tp_xdp_redirect_err, const struct net_device *dev,
			 const struct bpf_prog *xdp, const void *tgt, int err,
			 const struct bpf_map *map, u32 index)
{
	bpf_printk("xdp_redirect_err called: index=%u, err=%d\n", index, err);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
// 506155  506155  simplebridge    xdp_redirect_err map=2147483647 err=-22
//         xdp_do_generic_redirect+0x274 [kernel]
//         xdp_do_generic_redirect+0x274 [kernel]
//         do_xdp_generic.part.0+0x12f [kernel]
//         __netif_receive_skb_core.constprop.0+0x288 [kernel]
//         __netif_receive_skb_one_core+0x3f [kernel]
//         __netif_receive_skb+0x15 [kernel]
//         process_backlog+0x9e [kernel]
//         __napi_poll+0x33 [kernel]
//         net_rx_action+0x126 [kernel]
//         handle_softirqs+0xdd [kernel]
//         __softirqentry_text_start+0x10 [kernel]
//         do_softirq+0x7d [kernel]
//         __local_bh_enable_ip+0x54 [kernel]
//         __dev_queue_xmit+0x2af [kernel]
//         dev_queue_xmit+0x10 [kernel]
//         packet_snd+0x473 [kernel]
//         packet_sendmsg+0x2a [kernel]
//         __sock_sendmsg+0x69 [kernel]
//         __sys_sendto+0x113 [kernel]
//         __x64_sys_sendto+0x24 [kernel]
//         x64_sys_call+0x1bcb [kernel]
//         do_syscall_64+0x56 [kernel]
//         entry_SYSCALL_64_after_hwframe+0x6c [kernel]