#!/bin/bash

BRIDGE="virbr-shikra"
VM_NETWORK="192.168.100.0/24"
HOST_INTERFACE=$(ip route | grep default | awk '{print $5}')

echo "Setting up network isolation for $BRIDGE"

# Remove any existing rules
iptables -D FORWARD -i $BRIDGE -j LOG --log-prefix "SHIKRA-BLOCKED: " 2>/dev/null || true
iptables -D FORWARD -i $BRIDGE -d $VM_NETWORK -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o $BRIDGE -s $VM_NETWORK -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $BRIDGE -o $HOST_INTERFACE -j REJECT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $VM_NETWORK -j MASQUERADE 2>/dev/null || true

# Block all outbound traffic from VMs to real internet
iptables -I FORWARD 1 -i $BRIDGE -o $HOST_INTERFACE -j REJECT --reject-with icmp-net-prohibited

# Allow traffic within the isolated network
iptables -I FORWARD 1 -i $BRIDGE -d $VM_NETWORK -j ACCEPT
iptables -I FORWARD 1 -o $BRIDGE -s $VM_NETWORK -j ACCEPT

# Log blocked packets for monitoring
iptables -I FORWARD 1 -i $BRIDGE -j LOG --log-prefix "SHIKRA-BLOCKED: "

echo "Network isolation configured successfully"
