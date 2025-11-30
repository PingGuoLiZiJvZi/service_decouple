#ifndef __SLOWPATHS_H__
#define __SLOWPATHS_H__

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
static void generate_icmp_ttl_exceed(struct event_data *event, char *packet_data)
{
	return;
}
static void generate_arp_reply(struct event_data *event, char *packet_data)
{
	return;
}
static void generate_arp_request(struct event_data *event, char *packet_data)
{
	return;
}
static void handle_router_pkt(struct event_data *event, char *packet_data)
{
	return;
}
#endif