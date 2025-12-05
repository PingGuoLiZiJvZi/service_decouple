#include "router.skel.h"
#include "slowpaths.h"
#include "json_map.h"
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
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event_data *e = data;

	data += sizeof(*e);
	char *packet_data = data;

	switch (e->reason)
	{
	case SLOWPATH_TTL_EXCEEDED:
		printf("TTL_EXCEEDED packet of length %u received on interface %u\n",
			   e->packet_len, e->ingress_ifc);
		generate_icmp_ttl_exceed(e, packet_data);
		break;
	case SLOWPATH_ARP_LOOKUP_MISS:
		printf("ARP_LOOKUP_MISS packet of length %u received on interface %u\n",
			   e->packet_len, e->ingress_ifc);
		generate_arp_request(e, packet_data);
		break;
	case SLOWPATH_ARP_REPLY:
		printf("ARP_REPLY packet of length %u received on interface %u\n",
			   e->packet_len, e->ingress_ifc);
		generate_arp_reply(e, packet_data);
		break;
	case SLOWPATH_PKT_FOR_ROUTER:
		printf("PKT_FOR_ROUTER packet of length %u received on interface %u\n",
			   e->packet_len, e->ingress_ifc);
		handle_router_pkt(e, packet_data);
		break;
	default:
		printf("Unknown reason %u for packet of length %u received on interface %u\n", e->reason, e->packet_len, e->ingress_ifc);
		break;
	}
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct router_bpf *obj;
	int err;
	init_packet_map();
	if (init_json_data("/mnt/disk1/zhouchenxi/service_decouple/router/map_json_1_3"))
	{
		fprintf(stderr, "Failed to initialize JSON data\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	obj = router_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	if (init_router_ports())
	{
		fprintf(stderr, "Failed to initialize router ports\n");
		return 1;
	}
	printf("成功打开 BPF 对象\n");
	err = router_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = router_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	for (int i = 0; i < port_config_count; i++)
	{
		struct r_port rp = {};
		rp.ip = port_configs[i].ip;
		rp.netmask = port_configs[i].netmask;
		for (int j = 0; j < 5; j++)
		{
			rp.secondary_ip[j] = port_configs[i].secondary_ip[j];
			rp.secondary_netmask[j] = port_configs[i].secondary_netmask[j];
		}
		rp.mac = get_router_port_mac_by_index(port_configs[i].key);
		if (rp.mac == 0)
		{
			fprintf(stderr, "Failed to get MAC address for port index %d\n", port_configs[i].key);
			goto cleanup;
		}

		bpf_map_update_elem(bpf_map__fd(obj->maps.router_port),
							&port_configs[i].key,
							&rp,
							BPF_ANY);
	}

	// 填充路由映射表
	for (int i = 0; i < routing_entry_count; i++)
	{
		bpf_map_update_elem(bpf_map__fd(obj->maps.routing_table),
							&routing_entries[i].key,
							&routing_entries[i].value,
							BPF_ANY);
	}
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		const char *ifname = router_ports[i].name;
		int ifindex = router_ports[i].index;
		err = bpf_xdp_attach(ifindex, bpf_program__fd(obj->progs.xdp_router_rx), XDP_FLAGS_SKB_MODE, NULL);
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
	cleanup_json_data();
	router_bpf__destroy(obj);
	return -err;
}
