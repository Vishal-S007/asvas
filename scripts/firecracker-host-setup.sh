#!/usr/bin/env bash
# One-time host networking for Firecracker job VMs (run as root on the KVM host). For each slot: a network
# namespace asvas-fc-<slot> holding tap asvastap<slot> (172.31.<slot>.1/30, guest .2) with NAT to the host uplink.
# Egress filtering per job is done by the executor (table inet asvas_fc, forward hook). Idempotent.
#   scripts/firecracker-host-setup.sh <slots> <uplink-interface>
set -euo pipefail
SLOTS="${1:?slots}"; UPLINK="${2:?uplink interface}"
sysctl -qw net.ipv4.ip_forward=1
for i in $(seq 0 $((SLOTS-1))); do
  NS="asvas-fc-$i"; TAP="asvastap$i"; VETH_H="asvafch$i"; VETH_N="asvafcn$i"
  ip netns list | grep -qw "$NS" || ip netns add "$NS"
  ip -n "$NS" link show "$TAP" >/dev/null 2>&1 || ip -n "$NS" tuntap add dev "$TAP" mode tap
  ip -n "$NS" addr replace "172.31.$i.1/30" dev "$TAP"; ip -n "$NS" link set "$TAP" up; ip -n "$NS" link set lo up
  ip link show "$VETH_H" >/dev/null 2>&1 || ip link add "$VETH_H" type veth peer name "$VETH_N" netns "$NS"
  ip addr replace "172.30.$i.1/30" dev "$VETH_H"; ip link set "$VETH_H" up
  ip -n "$NS" addr replace "172.30.$i.2/30" dev "$VETH_N"; ip -n "$NS" link set "$VETH_N" up
  ip -n "$NS" route replace default via "172.30.$i.1"
  ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$NS" nft -f - <<N
table ip asvas_nat { chain post { type nat hook postrouting priority 100; oifname "$VETH_N" masquerade; } }
N
done
nft -f - <<N
table ip asvas_fc_uplink { chain post { type nat hook postrouting priority 100; oifname "$UPLINK" ip saddr 172.30.0.0/16 masquerade; } }
N
echo "configured $SLOTS slots (netns asvas-fc-N, tap asvastapN)"
