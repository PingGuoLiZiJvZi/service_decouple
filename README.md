# 这是从 polycube 中抽离出的两个服务,目前仅实现了网桥和路由器
# 使用说明
(代码的自动化程度较差(逃))
## 配置
### 网桥
需要在 include/port.h 中修改
```c
struct port bridge_ports[] = {
	{"veth0_bridge", 0, -1, 0},
	{"veth1_bridge", 0, -1, 0},
	{"veth2_bridge", 0, -1, 0},
	{"veth3_bridge", 0, -1, 0},
};
```
中的字符串为想要接入该网桥的网口名称即可
### 路由器
将
```c
struct port router_ports[] = {
	{"veth1_router", 0, -1, 0},
	{"veth2_router", 0, -1, 0},
	{"veth3_router", 0, -1, 0},
};
```
中的字符串修改为接入路由器中的网口名
同时，由于规则较少，可以直接修改json完成路由表的配置，router/map_json_1_3/router_port.json 中，key 修改为网口对应的 ifindex,ip(网关),netmask 都可以手动修改(小端序)，mac 地址不用修改，在程序中会自己去获取
#### 注意，arp表是由慢路径发送arp请求填充的，在对端无法回应arp包时，可能需要修改为手动填充json,否则所有的包都会在用户态被暂存
## 使用
使用 libbpf-bootstrap 编译运行，在服务目录下 make 后挂载即可，env.sh 是简单的测试脚本