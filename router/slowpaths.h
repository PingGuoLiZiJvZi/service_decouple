#ifndef __SLOWPATHS_H__
#define __SLOWPATHS_H__
#include "packet_map.h"
#include "../include/common.h"
#include "../include/port.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <assert.h>
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
#include <linux/ip.h>
#include <linux/icmp.h>
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
static unsigned short checksum(unsigned short *buf, int bufsz)
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
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}
static void generate_icmp_ttl_exceed(struct event_data *event, char *packet_data)
{
	if (event->packet_len < sizeof(struct eth_hdr) + sizeof(struct iphdr))
	{
		printf("Packet too small for ICMP TTL exceeded generation\n");
		return;
	}

	struct eth_hdr *orig_eth = (struct eth_hdr *)packet_data;
	struct iphdr *orig_ip = (struct iphdr *)(packet_data + sizeof(struct eth_hdr));

	// Extract source and destination IPs from original packet
	unsigned int dst_ip = orig_ip->saddr;
	unsigned int src_ip = event->metadata[0]; // Router IP from metadata

	printf("Generating ICMP TTL Exceeded to host %08x\n", dst_ip);

	size_t icmp_packet_size = sizeof(struct eth_hdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

	// Allocate buffer for ICMP packet
	char *icmp_packet = malloc(icmp_packet_size);
	if (!icmp_packet)
	{
		printf("Failed to allocate memory for ICMP packet\n");
		return;
	}

	memset(icmp_packet, 0, icmp_packet_size);

	// Set up Ethernet header
	struct eth_hdr *icmp_eth = (struct eth_hdr *)icmp_packet;
	icmp_eth->dst = orig_eth->src; // Original sender becomes destination
	icmp_eth->src = orig_eth->dst; // Router's MAC becomes source
	icmp_eth->proto = htons(ETH_P_IP);

	struct iphdr *icmp_ip = (struct iphdr *)(icmp_packet + sizeof(struct eth_hdr));
	icmp_ip->version = 4;
	icmp_ip->ihl = 5; // No options
	icmp_ip->tos = 0;
	icmp_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	icmp_ip->id = 0; // Let kernel set if needed
	icmp_ip->frag_off = 0;
	icmp_ip->ttl = 64; // Default TTL
	icmp_ip->protocol = IPPROTO_ICMP;
	icmp_ip->check = 0; // Will calculate later
	icmp_ip->saddr = src_ip;
	icmp_ip->daddr = dst_ip;

	// Calculate IP header checksum
	icmp_ip->check = checksum((unsigned short *)icmp_ip, sizeof(struct iphdr));

	// Set up ICMP header
	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct eth_hdr) + sizeof(struct iphdr));
	icmp_hdr->type = ICMP_TIME_EXCEEDED; // Type 11 - Time Exceeded
	icmp_hdr->code = ICMP_EXC_TTL;		 // Code 0 - TTL exceeded in transit
	icmp_hdr->checksum = 0;
	icmp_hdr->un.gateway = 0; // Unused

	// Copy original IP header + first 8 bytes of payload into ICMP message
	char *icmp_payload = (char *)(icmp_hdr + 1);
	memcpy(icmp_payload, orig_ip, sizeof(struct iphdr) + 8);

	// Calculate ICMP checksum (includes ICMP header + payload)
	icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

	// Send the ICMP packet out through the ingress interface
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		if (router_ports[i].index == event->ingress_ifc)
		{
			ssize_t sent = send(router_ports[i].socket, icmp_packet, icmp_packet_size, 0);
			if (sent < 0)
			{
				fprintf(stderr, "Failed to send ICMP TTL exceeded packet on %s: %s\n",
						router_ports[i].name, strerror(errno));
			}
			else if (sent != icmp_packet_size)
			{
				fprintf(stderr, "Partial send of ICMP TTL exceeded packet on %s: %zd/%zu bytes\n",
						router_ports[i].name, sent, icmp_packet_size);
			}
			else
			{
				printf("Sent ICMP TTL exceeded packet to %08x on port %s (ifc=%d)\n",
					   dst_ip, router_ports[i].name, event->ingress_ifc);
			}
			break;
		}
	}

	free(icmp_packet);
}

static void generate_arp_reply(struct event_data *event, char *packet_data)
{
	if (event->packet_len < sizeof(struct eth_hdr) + sizeof(struct arp_hdr))
	{
		printf("ARP reply packet too small\n");
		return;
	}

	struct eth_hdr *eth = (struct eth_hdr *)packet_data;
	struct arp_hdr *arp = (struct arp_hdr *)(packet_data + sizeof(struct eth_hdr));

	if (ntohs(eth->proto) != ETH_P_ARP || ntohs(arp->ar_op) != ARPOP_REPLY)
	{
		printf("Not an ARP reply packet\n");
		return;
	}

	unsigned int src_ip = arp->ar_sip;
	uint64_t src_mac = arp->ar_sha;

	printf("ARP reply '%08x is at %02x:%02x:%02x:%02x:%02x:%02x'\n",
		   src_ip,
		   (unsigned char)(src_mac >> 40),
		   (unsigned char)(src_mac >> 32),
		   (unsigned char)(src_mac >> 24),
		   (unsigned char)(src_mac >> 16),
		   (unsigned char)(src_mac >> 8),
		   (unsigned char)(src_mac));
	// 处理等待该ARP回复的packet,全部发送出去
	while (1)
	{
		struct packet waiting_packet = dequeue_packet_from_ip(src_ip);

		if (waiting_packet.data == NULL)
		{
			printf("No packet found for ARP reply to IP %08x\n", src_ip);
			return;
		}

		struct eth_hdr *waiting_eth = (struct eth_hdr *)waiting_packet.data;

		waiting_eth->dst = src_mac;
		waiting_eth->src = get_router_port_mac_by_index(event->ingress_ifc);

		for (int i = 0; i < ROUTER_PORT_COUNT; i++)
		{
			if (router_ports[i].index == event->ingress_ifc)
			{
				ssize_t sent = send(router_ports[i].socket, waiting_packet.data, waiting_packet.size, 0);
				if (sent < 0)
				{
					fprintf(stderr, "Failed to send waiting packet on %s: %s\n",
							router_ports[i].name, strerror(errno));
				}
				else if (sent != waiting_packet.size)
				{
					fprintf(stderr, "Partial send of waiting packet on %s: %zd/%d bytes\n",
							router_ports[i].name, sent, waiting_packet.size);
				}
				else
				{
					printf("Sent waiting packet to IP %08x on port %s (ifc=%d)\n",
						   src_ip, router_ports[i].name, event->ingress_ifc);
				}
				break;
			}
		}

		free(waiting_packet.data);
	}
}
static void generate_arp_request(struct event_data *event, char *packet_data)
{
	// printf("Generating ARP Request not implemented yet.\n");
	unsigned int target_ip = event->metadata[0];
	int port_out = event->metadata[1];
	unsigned int src_ip = event->metadata[2];
	uint64_t src_mac = get_router_port_mac_by_index(port_out);
	assert(src_mac != 0);
	if (add_ip_to_packet_map(target_ip) != 0)
	{
		printf("Failed to add IP to packet map\n");
		return;
	}
	if (add_packet_to_ip(target_ip, packet_data, event->packet_len) != 0)
	{
		printf("Failed to add packet to ip in packet map\n");
		return;
	}

	// 构建ARP请求包
	unsigned char arp_packet[sizeof(struct eth_hdr) + sizeof(struct arp_hdr)];
	memset(arp_packet, 0, sizeof(arp_packet));

	// 设置以太网头部
	struct eth_hdr *eth = (struct eth_hdr *)arp_packet;
	eth->dst = 0xffffffffffffULL; // 广播MAC地址
	eth->src = src_mac;
	eth->proto = htons(ETH_P_ARP);

	// 设置ARP头部
	struct arp_hdr *arp = (struct arp_hdr *)(arp_packet + sizeof(struct eth_hdr));
	arp->ar_hrd = htons(1);			   // 硬件类型：以太网
	arp->ar_pro = htons(ETH_P_IP);	   // 协议类型：IP
	arp->ar_hln = 6;				   // 硬件地址长度：6字节
	arp->ar_pln = 4;				   // 协议地址长度：4字节
	arp->ar_op = htons(ARPOP_REQUEST); // ARP操作：请求
	arp->ar_sha = src_mac;			   // 发送者MAC地址
	arp->ar_sip = src_ip;			   // 发送者IP地址
	arp->ar_tha = 0;				   // 目标MAC地址（未知，设为0）
	arp->ar_tip = target_ip;		   // 目标IP地址

	// 发送ARP请求包
	for (int i = 0; i < ROUTER_PORT_COUNT; i++)
	{
		if (router_ports[i].index == port_out)
		{
			ssize_t sent = send(router_ports[i].socket, arp_packet, sizeof(arp_packet), 0);
			if (sent < 0)
			{
				fprintf(stderr, "Failed to send ARP request on %s: %s\n",
						router_ports[i].name, strerror(errno));
			}
			else if (sent != sizeof(arp_packet))
			{
				fprintf(stderr, "Partial ARP request send on %s: %zd/%zu bytes\n",
						router_ports[i].name, sent, sizeof(arp_packet));
			}
			else
			{
				printf("Sent ARP request for IP %08x on port %s (ifc=%d)\n",
					   target_ip, router_ports[i].name, port_out);
			}
			break;
		}
	}
	printf("ARP Request generation completed.\n");
	return;
}
static void handle_router_pkt(struct event_data *event, char *packet_data)
{
	printf("Handling router packet not implemented yet.\n");
	// 似乎没有必要实现该函数，原框架中的实现也不完整
	return;
}

#endif