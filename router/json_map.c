#include "json_map.h"
#include <string.h>
#include <errno.h>

struct port_config *port_configs = NULL;
int port_config_count = 0;
struct routing_entry *routing_entries = NULL;
int routing_entry_count = 0;

struct port_config *load_port_configs(const char *filepath, int *count)
{
	if (!filepath || !count)
	{
		fprintf(stderr, "Invalid parameters for load_port_configs\n");
		return NULL;
	}

	FILE *fp = fopen(filepath, "r");
	if (!fp)
	{
		fprintf(stderr, "Failed to open file %s: %s\n", filepath, strerror(errno));
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *json_data = malloc(file_size + 1);
	if (!json_data)
	{
		fprintf(stderr, "Failed to allocate memory for JSON data\n");
		fclose(fp);
		return NULL;
	}

	fread(json_data, 1, file_size, fp);
	json_data[file_size] = '\0';
	fclose(fp);

	json_object *root = json_tokener_parse(json_data);
	free(json_data);

	if (!root)
	{
		fprintf(stderr, "Failed to parse JSON from %s\n", filepath);
		return NULL;
	}

	if (json_object_get_type(root) != json_type_array)
	{
		fprintf(stderr, "JSON root is not an array in %s\n", filepath);
		json_object_put(root);
		return NULL;
	}

	int array_len = json_object_array_length(root);
	struct port_config *configs = malloc(array_len * sizeof(struct port_config));
	if (!configs)
	{
		fprintf(stderr, "Failed to allocate memory for port configs\n");
		json_object_put(root);
		return NULL;
	}

	*count = 0;
	for (int i = 0; i < array_len; i++)
	{
		json_object *entry_obj = json_object_array_get_idx(root, i);
		if (!entry_obj)
			continue;

		json_object *key_obj, *value_obj;
		if (!json_object_object_get_ex(entry_obj, "key", &key_obj) ||
			!json_object_object_get_ex(entry_obj, "value", &value_obj))
		{
			fprintf(stderr, "Missing key or value in entry %d\n", i);
			continue;
		}

		configs[*count].key = json_object_get_int(key_obj);

		json_object *ip_obj, *netmask_obj, *mac_obj;
		json_object *secondary_ip_obj, *secondary_netmask_obj;

		if (json_object_object_get_ex(value_obj, "ip", &ip_obj))
			configs[*count].ip = json_object_get_int64(ip_obj);

		if (json_object_object_get_ex(value_obj, "netmask", &netmask_obj))
			configs[*count].netmask = json_object_get_int64(netmask_obj);

		if (json_object_object_get_ex(value_obj, "mac", &mac_obj))
		{
			printf("Parsing MAC address for port %d = %s\n", configs[*count].key, json_object_get_string(mac_obj));
			sscanf(json_object_get_string(mac_obj), "%lx", &configs[*count].mac);
			printf("Parsed MAC address: %lx\n", configs[*count].mac);
		}

		if (json_object_object_get_ex(value_obj, "secondary_ip", &secondary_ip_obj))
		{
			int sec_ip_len = json_object_array_length(secondary_ip_obj);
			for (int j = 0; j < 5 && j < sec_ip_len; j++)
			{
				json_object *sec_ip_val = json_object_array_get_idx(secondary_ip_obj, j);
				if (sec_ip_val)
				{
					configs[*count].secondary_ip[j] = json_object_get_int64(sec_ip_val);
				}
			}
		}

		if (json_object_object_get_ex(value_obj, "secondary_netmask", &secondary_netmask_obj))
		{
			int sec_mask_len = json_object_array_length(secondary_netmask_obj);
			for (int j = 0; j < 5 && j < sec_mask_len; j++)
			{
				json_object *sec_mask_val = json_object_array_get_idx(secondary_netmask_obj, j);
				if (sec_mask_val)
				{
					configs[*count].secondary_netmask[j] = json_object_get_int64(sec_mask_val);
				}
			}
		}

		(*count)++;
	}

	json_object_put(root);
	return configs;
}

struct routing_entry *load_routing_table(const char *filepath, int *count)
{
	if (!filepath || !count)
	{
		fprintf(stderr, "Invalid parameters for load_routing_table\n");
		return NULL;
	}

	FILE *fp = fopen(filepath, "r");
	if (!fp)
	{
		fprintf(stderr, "Failed to open file %s: %s\n", filepath, strerror(errno));
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *json_data = malloc(file_size + 1);
	if (!json_data)
	{
		fprintf(stderr, "Failed to allocate memory for JSON data\n");
		fclose(fp);
		return NULL;
	}

	fread(json_data, 1, file_size, fp);
	json_data[file_size] = '\0';
	fclose(fp);

	json_object *root = json_tokener_parse(json_data);
	free(json_data);

	if (!root)
	{
		fprintf(stderr, "Failed to parse JSON from %s\n", filepath);
		return NULL;
	}

	if (json_object_get_type(root) != json_type_array)
	{
		fprintf(stderr, "JSON root is not an array in %s\n", filepath);
		json_object_put(root);
		return NULL;
	}

	int array_len = json_object_array_length(root);
	struct routing_entry *entries = malloc(array_len * sizeof(struct routing_entry));
	if (!entries)
	{
		fprintf(stderr, "Failed to allocate memory for routing entries\n");
		json_object_put(root);
		return NULL;
	}

	*count = 0;
	for (int i = 0; i < array_len; i++)
	{
		json_object *entry_obj = json_object_array_get_idx(root, i);
		if (!entry_obj)
			continue;

		json_object *key_obj, *value_obj;
		if (!json_object_object_get_ex(entry_obj, "key", &key_obj) ||
			!json_object_object_get_ex(entry_obj, "value", &value_obj))
		{
			fprintf(stderr, "Missing key or value in entry %d\n", i);
			continue;
		}

		json_object *netmask_len_obj, *network_obj;
		if (json_object_object_get_ex(key_obj, "netmask_len", &netmask_len_obj))
			entries[*count].key.netmask_len = json_object_get_int(netmask_len_obj);

		if (json_object_object_get_ex(key_obj, "network", &network_obj))
			entries[*count].key.network = json_object_get_int64(network_obj);

		json_object *port_obj, *nexthop_obj, *type_obj;
		if (json_object_object_get_ex(value_obj, "port", &port_obj))
			entries[*count].value.port = json_object_get_int(port_obj);

		if (json_object_object_get_ex(value_obj, "nexthop", &nexthop_obj))
			entries[*count].value.nexthop = json_object_get_int(nexthop_obj);

		if (json_object_object_get_ex(value_obj, "type", &type_obj))
			entries[*count].value.type = json_object_get_int(type_obj);

		(*count)++;
	}

	json_object_put(root);
	return entries;
}

void free_port_configs(struct port_config *configs)
{
	if (configs)
	{
		free(configs);
	}
}

void free_routing_table(struct routing_entry *entries)
{
	if (entries)
	{
		free(entries);
	}
}

int init_json_data(const char *json_dir)
{
	char router_port_path[512];
	char routing_table_path[512];

	if (!json_dir)
	{
		fprintf(stderr, "JSON directory path is NULL\n");
		return -1;
	}

	snprintf(router_port_path, sizeof(router_port_path), "%s/router_port.json", json_dir);
	snprintf(routing_table_path, sizeof(routing_table_path), "%s/routing_table.json", json_dir);

	printf("Loading JSON data from: %s\n", json_dir);

	port_configs = load_port_configs(router_port_path, &port_config_count);
	if (!port_configs)
	{
		fprintf(stderr, "Failed to load port configs from %s\n", router_port_path);
		return -1;
	}
	printf("Loaded %d port configurations\n", port_config_count);

	routing_entries = load_routing_table(routing_table_path, &routing_entry_count);
	if (!routing_entries)
	{
		fprintf(stderr, "Failed to load routing table from %s\n", routing_table_path);
		cleanup_json_data();
		return -1;
	}
	printf("Loaded %d routing entries\n", routing_entry_count);

	for (int i = 0; i < port_config_count; i++)
	{
		printf("Port %d: IP=0x%x, Netmask=0x%x, MAC=%lx\n",
			   port_configs[i].key,
			   port_configs[i].ip,
			   port_configs[i].netmask,
			   port_configs[i].mac);
	}

	for (int i = 0; i < routing_entry_count; i++)
	{
		printf("Route %d: Network=0x%x/%d, Port=%d, Type=%d\n",
			   i,
			   routing_entries[i].key.network,
			   routing_entries[i].key.netmask_len,
			   routing_entries[i].value.port,
			   routing_entries[i].value.type);
	}

	return 0;
}

void cleanup_json_data(void)
{
	if (port_configs)
	{
		free_port_configs(port_configs);
		port_configs = NULL;
		port_config_count = 0;
	}

	if (routing_entries)
	{
		free_routing_table(routing_entries);
		routing_entries = NULL;
		routing_entry_count = 0;
	}
}