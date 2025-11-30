# 独立 NF 分析
## 简单网桥 (simplebridge)
### 逻辑解析
网桥在链路层（第二层）根据 MAC 地址实现不同网段/冲突域之间的转发和隔离，从而减少冲突、扩大网络并提高性能，总的来说，其在程序中的表现为维护一个 mac 地址和网络接口之间的映射表
### bpf 函数
#### 入口函数
- 当挂载在网卡上的 xdp 程序接收到网络包时，首先从包中解析出以太网头
- 从以太网头中获取源 mac 地址和目标 mac 地址，从转发表中记载有没有已经记录的源 mac 到输入网络接口之间的映射
- 如果没有，则带着目前的时间戳新增，如果有，则更新已有的表项
- 随后，处理发送端口，首先，查表，没查到，泛洪 (转接用户态处理,通过 perf_buffer 通知用户态处理)
- 查到了，检查是否已老化，已老化，删除，泛洪
- 随后才是有效转发，若发生回环，丢包
#### 出口函数
- 与入口函数通用
#### 其余函数
- 无
### bpf_maps
- 转发表:维护 mac 地址到网络接口的映射
- 时间戳存储表:通过查表获取当前时间

## 防火墙 (firewall)
### 逻辑解析
- polycube 框架中的防火墙是一个包过滤防火墙，支持以下的过滤指标
```c
  struct packetHeaders {
    uint32_t srcIp;           // 源IP地址过滤
    uint32_t dstIp;           // 目的IP地址过滤  
    uint8_t l4proto;          // 协议类型过滤 (TCP/UDP/ICMP)
    uint16_t srcPort;         // 源端口过滤
    uint16_t dstPort;         // 目的端口过滤
    uint8_t flags;            // TCP标志位过滤
    uint8_t connStatus;       // 连接状态过滤 (有状态)
  } __attribute__((packed));
```
### bpf 函数
#### 入口函数
- 防火墙服务的实现较为复杂，一个数据包需要经过多个模块之间的连续尾调用才能完成处理
- 首先是数据解析模块，Firewall_Parser_dp.c 中的 handle_rx 函数完成了对于包的初步校验和解析，将解析到的数据存入共享的 packet map 中，key 为 0，同时根据规则数学，初始化线性位搜索算法的 bits 值
- 随后是两个可配置的功能，Conntrack 提供完整有状态防火墙功能，Horus 提供高效的性能匹配优化
- Horus 模块新增了 horusTable map，用从包中构造出来的五元组 key 去查表，观察是否能找到对应规则
- 没找到或者 ruleID (标识原始防火墙规则)越界 ，走标准流程进入 Conntrack 处理
- 里面维护了一个命中计数器，不知道干什么用的
- 随后 0 丢包，1 通过，如果启用了 conntrack,需要跳转至状态跟踪
- 在 Firewall_ConntrackLabel_dp.c 函数中，先拿包，初始化跟踪键(有规范化和反向标记)，确保同一连接的正向和反向数据包使用相同的哈希键，只需要用 ipRev 和 portRev 来区分方向
- 随后查找现有连接，维护在 connections map 里，如何查到了，与查到的值做比较，会有正向流量，反向流量和异常三种情况
- 在不同情况中，根据 pkt->flags 和 value->state 中的不同数据，给 pkt->connStatus 打上不同标识，交给 action 代码块处理
- 在 action 中，_CONNTRACK_MODE 有两种选择
- 手动模式(1)下，如果 horus 说能放就放，没说能放就走正常防火墙规则检查
- 而在自动模式(2)下,对于可以方向的包的要求大大放宽， ESTABLISHED 连接都不需要进行规则检查，只需要更新 tracktable 就行
- 随后，进入 Firewall_ChainForwarder_dp.c 下的 handle_rx,进行一系列的规则链检查，有规则走规则，没规则全放或全丢，其中涉及 _NEXT_HOP_1 动态加载代码机制
- ConntrackTableUpdate 负责连接表的更新
#### 出口函数
- 与入口函数通用
#### 其余函数
- 懒得写
### bpf_maps
- packet map(放包的共享内存)
- sharedEle map(位向量的存储位置)
- horusTable map
- connections map
## 路由器 (router)
### 逻辑解析
在 polycube 框架中的路由器主要负责 IPv4 包和 ARP 包的路由，这个路由器的实现较为简单，主要功能为获取 dest ip 到网络接口的映射(敢问路在何方belike)
### bpf 函数
#### 入口函数
- 在入口处，首先进行网络接口的校验(通过 router_port 由接口id查接口所在)，也可以进行 mac 地址校验，接下来，根据不同的协议族(IP/ARP)进行转交处理
- 在 IP 协议处理段，首先解析出 ip 头，随后进行边界检查和 ttl 检查，随后，从 routing table 中进行路由查找(LPM 查找逻辑)，没找到就丢包，如何是回环则转交慢速路径处理，若 ttl 为 1 则回复超时响应，随后选择出接口并进行接口验证，随后转发数据包
- ARP 拿头，校验，如果收到的是对于自己的请求，则回复自己的 ip 与 mac，如果是自己发起的请求，则正常发送 arp 请求
#### 出口函数
- 与入口通用
#### 其余函数
- send_packet_for_router_to_slowpath 将发往路由器自身的IPv4数据包发送到慢路径处理
- send_icmp_ttl_time_exceeded  当 TTL 超时时，发送ICMP超时消息给发送者
- arp_lookup_miss 当ARP表中找不到下一跳的MAC地址时，发送ARP请求
- send_packet_to_output_interface 将数据包转发到输出接口，这是最核心的转发函数 ARP解析 更新二层头部 更新IP头部 转发数据包
- search_secondary_address 在辅助IP地址中搜索指定的IP地址
- send_arp_reply 构造并发送ARP回复，响应ARP请求(内核态构建)
- notify_arp_reply_to_slowpath 处理收到的ARP回复，学习新的IP-MAC映射
### bpf_maps
- router_port portid->port
- arp_table ip->mac
- routing_table rt_k -> rt_v