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
#include <sys/ioctl.h>
#include <linux/if.h>


struct port
{
	char name[16];
	int index;
	int socket;
	unsigned long long mac;
};
struct port bridge_ports[] = {
	{"veth0_bridge", 0, -1, 0},
	{"veth1_bridge", 0, -1, 0},
	{"veth2_bridge", 0, -1, 0},
	{"veth3_bridge", 0, -1, 0},
};
struct port router_ports[] = {
	{"veth1_router", 0, -1, 0},
	{"veth2_router", 0, -1, 0},
	{"veth3_router", 0, -1, 0},
};

#define BRIDGE_PORT_COUNT sizeof(bridge_ports) / sizeof(bridge_ports[0])
#define ROUTER_PORT_COUNT sizeof(router_ports) / sizeof(router_ports[0])

unsigned long long get_interface_mac(const char *interface_name)
{
	int sock;
	struct ifreq ifr;
	unsigned long long mac = 0;

	// 创建临时socket用于ioctl调用
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		fprintf(stderr, "Failed to create socket for MAC retrieval: %s\n", strerror(errno));
		return 0;
	}

	// 设置接口名称
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	// 获取MAC地址
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		fprintf(stderr, "Failed to get MAC address for %s: %s\n",
				interface_name, strerror(errno));
		close(sock);
		return 0;
	}

	close(sock);

	// 将6字节的MAC地址转换为64位整数
	// MAC地址格式: XX:XX:XX:XX:XX:XX
	mac = ((unsigned long long)ifr.ifr_hwaddr.sa_data[0] << 40) |
		  ((unsigned long long)ifr.ifr_hwaddr.sa_data[1] << 32) |
		  ((unsigned long long)ifr.ifr_hwaddr.sa_data[2] << 24) |
		  ((unsigned long long)ifr.ifr_hwaddr.sa_data[3] << 16) |
		  ((unsigned long long)ifr.ifr_hwaddr.sa_data[4] << 8) |
		  ((unsigned long long)ifr.ifr_hwaddr.sa_data[5]);

	printf("MAC address for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   interface_name,
		   (unsigned char)ifr.ifr_hwaddr.sa_data[0],
		   (unsigned char)ifr.ifr_hwaddr.sa_data[1],
		   (unsigned char)ifr.ifr_hwaddr.sa_data[2],
		   (unsigned char)ifr.ifr_hwaddr.sa_data[3],
		   (unsigned char)ifr.ifr_hwaddr.sa_data[4],
		   (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	return mac;
}

int init_bridge_ports_macs()
{
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
	{
		bridge_ports[i].mac = get_interface_mac(bridge_ports[i].name);
		if (bridge_ports[i].mac == 0)
		{
			fprintf(stderr, "Failed to get MAC address for %s\n", bridge_ports[i].name);
			return -1;
		}
	}
	return 0;
}

int init_router_ports_macs()
{
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		router_ports[i].mac = get_interface_mac(router_ports[i].name);
		if (router_ports[i].mac == 0)
		{
			fprintf(stderr, "Failed to get MAC address for %s\n", router_ports[i].name);
			return -1;
		}
	}
	return 0;
}
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
	if (init_bridge_ports_macs())
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
	for (int i = 0; i < BRIDGE_PORT_COUNT; i++)
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
	if (init_router_ports_macs())
	{
		return -1;
	}
	if (init_router_ports_sockets())
	{
		return -1;
	}
	return 0;
}
unsigned long long get_router_port_mac_by_index(int ifindex)
{
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		if (router_ports[i].index == ifindex)
		{
			return router_ports[i].mac;
		}
	}
	return 0;
}
#endif