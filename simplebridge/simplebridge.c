#include "simplebridge.skel.h"
#include "../include/common.h"
#include "../include/port.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
static volatile sig_atomic_t exiting = 0;
static int libbpf_print_fn(enum libbpf_print_level level,
						   const char *format,
						   va_list args)
{
	return vfprintf(stderr, format, args);
	// return 0;
}
static void sig_int(int signo)
{
	exiting = 1;
}
void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}
void do_flooding(struct event_data *e, char *packet_data)
{
	if (!e || e->packet_len < sizeof(struct eth_hdr))
	{
		fprintf(stderr, "Invalid flood event data\n");
		return;
	}
	int packets_sent = 0;
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
	{
		if (bridge_ports[i].index == e->ingress_ifc)
		{
			continue;
		}
		// 发送包数据
		ssize_t sent = send(bridge_ports[i].socket, packet_data, e->packet_len, 0);
		if (sent < 0)
		{
			fprintf(stderr, "Send failed on %s: %s\n",
					bridge_ports[i].name, strerror(errno));
		}
		else if (sent != e->packet_len)
		{
			fprintf(stderr, "Partial send on %s: %zd/%u bytes\n",
					bridge_ports[i].name, sent, e->packet_len);
		}
		else
		{
			printf("Forwarded packet to %s (ifc=%d)\n", bridge_ports[i].name, bridge_ports[i].index);
			packets_sent++;
		}
	}

	printf("FLOODING complete: sent to %d interfaces\n", packets_sent);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event_data *e = data;

	data += sizeof(*e);
	char *packet_data = data;

	switch (e->reason)
	{
	case REASON_FLOODING:
		printf("FLOODING packet of length %u received on interface %u\n",
			   e->packet_len, e->ingress_ifc);
		do_flooding(e, packet_data);
		break;
	default:
		printf("Unknown reason %u for packet of length %u received on interface %u\n", e->reason, e->packet_len, e->ingress_ifc);
		break;
	}
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct simplebridge_bpf *obj;
	int err;
	if (init_bridge_ports())
	{
		fprintf(stderr, "Failed to initialize port\n");
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);
	obj = simplebridge_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	printf("成功打开 BPF 对象\n");
	err = simplebridge_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = simplebridge_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
	{
		const char *ifname = bridge_ports[i].name;
		int ifindex = bridge_ports[i].index;
		err = bpf_xdp_attach(ifindex, bpf_program__fd(obj->progs.xdp_simplebridge_rx), XDP_FLAGS_SKB_MODE, NULL);
		if (err)
		{
			fprintf(stderr, "Failed to attach XDP program to interface %s: %s\n", ifname, strerror(-err));
			goto cleanup;
		}
		printf("成功将 XDP 程序附加到接口 %s\n", ifname);
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
						  handle_event, handle_lost_events, NULL, NULL);
	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting)
	{
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR)
		{
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	simplebridge_bpf__destroy(obj);
	return -err;
}
