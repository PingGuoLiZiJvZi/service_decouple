#ifndef __JSON_MAP_H__
#define __JSON_MAP_H__

#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/common.h"
struct port_config
{
	int key;
	uint32_t ip;
	uint32_t netmask;
	uint32_t secondary_ip[5];
	uint32_t secondary_netmask[5];
	uint64_t mac;
};

struct routing_entry
{
	struct rt_k key;
	struct rt_v value;
};

extern struct port_config *port_configs;
extern int port_config_count;
extern struct routing_entry *routing_entries;
extern int routing_entry_count;

struct port_config *load_port_configs(const char *filepath, int *count);
struct routing_entry *load_routing_table(const char *filepath, int *count);
void free_port_configs(struct port_config *configs);
void free_routing_table(struct routing_entry *entries);
int init_json_data(const char *json_dir);
void cleanup_json_data();

#endif