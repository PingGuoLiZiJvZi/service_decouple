#ifndef __PORT_H__
#define __PORT_H__
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define BRIDGE_PORT_COUNT 4
#define ROUTER_PORT_COUNT 3
struct port
{
	char name[16];
	int index;
	int socket;
};
struct port bridge_ports[BRIDGE_PORT_COUNT] = {
	{"veth0_bridge", 0, -1},
	{"veth1_bridge", 0, -1},
	{"veth2_bridge", 0, -1},
	{"veth3_bridge", 0, -1},
};
struct port router_ports[ROUTER_PORT_COUNT] = {
	{"veth1_router", 0, -1},
	{"veth2_router", 0, -1},
	{"veth3_router", 0, -1},
};
int init_bridge_ports_indexes()
{
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
	{
		bridge_ports[i].index = if_nametoindex(bridge_ports[i].name);
		if (bridge_ports[i].index == 0)
		{
			fprintf(stderr, "Invalid interface name %s\n", bridge_ports[i].name);
			return -1;
		}
	}
	return 0;
}
int init_bridge_ports_sockets()
{
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
	{
		int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock < 0)
		{
			fprintf(stderr, "Failed to create socket for %s: %s\n",
					bridge_ports[i].name, strerror(errno));
			return -1;
		}

		struct sockaddr_ll sll;
		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = bridge_ports[i].index;
		sll.sll_protocol = htons(ETH_P_ALL);

		if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		{
			fprintf(stderr, "Failed to bind to %s: %s\n",
					bridge_ports[i].name, strerror(errno));
			close(sock);
			return -1;
		}
		bridge_ports[i].socket = sock;
	}
	return 0;
}

int init_bridge_ports()
{
	if (init_bridge_ports_indexes())
	{
		return -1;
	}
	if (init_bridge_ports_sockets())
	{
		return -1;
	}
	return 0;
}

int is_in_bridge_ports_indexes(int ifindex)
{
	for (int i = 0; i < 16; i++)
	{
		if (bridge_ports[i].index == ifindex)
		{
			return 1;
		}
	}
	return 0;
}
int init_router_ports_indexes()
{
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		router_ports[i].index = if_nametoindex(router_ports[i].name);
		if (router_ports[i].index == 0)
		{
			fprintf(stderr, "Invalid interface name %s\n", router_ports[i].name);
			return -1;
		}
	}
	return 0;
}
int init_router_ports_sockets()
{
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sock < 0)
		{
			fprintf(stderr, "Failed to create socket for %s: %s\n",
					router_ports[i].name, strerror(errno));
			return -1;
		}

		struct sockaddr_ll sll;
		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = router_ports[i].index;
		sll.sll_protocol = htons(ETH_P_ALL);

		if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		{
			fprintf(stderr, "Failed to bind to %s: %s\n",
					router_ports[i].name, strerror(errno));
			close(sock);
			return -1;
		}
		router_ports[i].socket = sock;
	}
	return 0;
}
int init_router_ports()
{
	if (init_router_ports_indexes())
	{
		return -1;
	}
	if (init_router_ports_sockets())
	{
		return -1;
	}
	return 0;
}
#endif