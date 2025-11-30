#!/bin/bash
setup(){
	sudo ip netns add ns1
	sudo ip netns add ns2
	sudo ip netns add ns3

	sudo ip link add veth1_router type veth peer name veth1
	sudo ip link add veth2_router type veth peer name veth2
	sudo ip link add veth3_router type veth peer name veth3

	sudo ip link set veth1 netns ns1
	sudo ip link set veth2 netns ns2
	sudo ip link set veth3 netns ns3

	sudo ip -n ns1 addr add 10.0.1.1/24 dev veth1
	sudo ip -n ns1 link set veth1 up
	sudo ip -n ns2 addr add 10.0.2.1/24 dev veth2
	sudo ip -n ns2 link set veth2 up
	sudo ip -n ns3 addr add 10.0.3.1/24 dev veth3
	sudo ip -n ns3 link set veth3 up

	sudo ip link set veth1_router up
	sudo ip link set veth2_router up
	sudo ip link set veth3_router up

	sudo ip netns exec ns1 route add default gw 10.0.1.254 veth1
	sudo ip netns exec ns2 route add default gw 10.0.2.254 veth2
	sudo ip netns exec ns3 route add default gw 10.0.3.254 veth3
}

cleanup(){
	sudo ip netns delete ns1
	sudo ip netns delete ns2
	sudo ip netns delete ns3
}

test(){
	sudo ip netns exec ns1 ping -c3 10.0.0.2
	sudo ip netns exec ns2 ping -c3 10.0.0.3
	sudo ip netns exec ns3 ping -c3 10.0.0.1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    "$@"          # 把第一个参数当函数名，其余当参数
fi