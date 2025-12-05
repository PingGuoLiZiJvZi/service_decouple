#ifndef __PACKET_MAP_H__
#define __PACKET_MAP_H__
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
struct packet
{
	char *data;
	int size;
};
struct packets
{
	int ip;
	struct packet packets[1024];
	int count;
};
struct packet_map
{
	pthread_mutex_t pm_lock;
	struct packets p_list[1024];
	int p_list_count;
} pm;

void init_packet_map()
{
	memset(&pm, 0, sizeof(pm));
	pthread_mutex_init(&pm.pm_lock, NULL);
}
// 一个函数，如果ip已经在map中，则什么都不做，返回0；如果ip不在map中，则添加ip，并初始化对应的packet list，返回0；如果出错，返回-1
int add_ip_to_packet_map(int ip)
{
	pthread_mutex_lock(&pm.pm_lock);
	// 搜索ip是否在map中
	for (int i = 0; i < pm.p_list_count; i++)
	{
		if (pm.p_list[i].ip == ip)
		{
			pthread_mutex_unlock(&pm.pm_lock);
			return 0; // 已经存在
		}
	}
	// 如果不在map中，添加ip
	if (pm.p_list_count >= 1024)
	{
		pthread_mutex_unlock(&pm.pm_lock);
		return -1; // map已满
	}
	pm.p_list[pm.p_list_count].ip = ip;
	pm.p_list_count++;
	pthread_mutex_unlock(&pm.pm_lock);
	return 0;
}
int add_packet_to_ip(int ip, char *packet, int size)
{
	pthread_mutex_lock(&pm.pm_lock);
	// 搜索ip对应的packet list
	for (int i = 0; i < pm.p_list_count; i++)
	{
		if (pm.p_list[i].ip == ip)
		{
			// 找到对应的packet list，添加packet
			if (pm.p_list[i].count >= 1024)
			{
				pthread_mutex_unlock(&pm.pm_lock);
				return -1; // packet list已满
			}
			pm.p_list[i].packets[pm.p_list[i].count].data = (char *)malloc(size);
			if (!pm.p_list[i].packets[pm.p_list[i].count].data)
			{
				pthread_mutex_unlock(&pm.pm_lock);
				return -1; // 内存分配失败
			}
			memcpy(pm.p_list[i].packets[pm.p_list[i].count].data, packet, size);
			pm.p_list[i].packets[pm.p_list[i].count].size = size;
			pm.p_list[i].count++;
			pthread_mutex_unlock(&pm.pm_lock);
			return 0; // 成功添加
		}
	}
	pthread_mutex_unlock(&pm.pm_lock);
	return -1; // ip未找到
}
// 写一个函数，将某IP出队一个packet，返回packet数据和大小，如果没有packet，返回NULL和0
// 拿出来的包使用后需要free
struct packet dequeue_packet_from_ip(int ip)
{
	struct packet result = {NULL, 0};
	pthread_mutex_lock(&pm.pm_lock);
	// 搜索ip对应的packet list
	for (int i = 0; i < pm.p_list_count; i++)
	{
		if (pm.p_list[i].ip == ip)
		{
			// 找到对应的packet list，出队一个packet
			if (pm.p_list[i].count == 0)
			{
				pthread_mutex_unlock(&pm.pm_lock);
				return result; // 没有packet
			}
			result.data = pm.p_list[i].packets[0].data;
			result.size = pm.p_list[i].packets[0].size;
			// 将后面的packet前移
			for (int j = 1; j < pm.p_list[i].count; j++)
			{
				pm.p_list[i].packets[j - 1] = pm.p_list[i].packets[j];
			}
			pm.p_list[i].count--;
			pthread_mutex_unlock(&pm.pm_lock);
			return result; // 成功出队
		}
	}
	pthread_mutex_unlock(&pm.pm_lock);
	return result; // ip未找到
}

#endif