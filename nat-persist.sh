#!/bin/bash
# Pineapple AP NAT — re-apply after Docker has set up its iptables at boot.
# Docker sets FORWARD policy to DROP and reorders iptables on daemon start,
# wiping the rogue-AP NAT. This oneshot (ordered After=docker.service) puts it
# back idempotently, inserting the FORWARD ACCEPTs ABOVE Docker's DROP policy.
set +e

AP_SUBNET="192.168.66.0/24"
LAN_IF="eth0"
AP_IF="wlan0"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# NAT: masquerade AP subnet out via the LAN uplink
iptables -t nat -C POSTROUTING -s "$AP_SUBNET" -o "$LAN_IF" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$AP_SUBNET" -o "$LAN_IF" -j MASQUERADE

# FORWARD: allow AP -> internet, and return traffic. Insert at top to beat
# Docker's FORWARD policy DROP.
iptables -C FORWARD -i "$AP_IF" -o "$LAN_IF" -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -i "$AP_IF" -o "$LAN_IF" -j ACCEPT
iptables -C FORWARD -i "$LAN_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 2 -i "$LAN_IF" -o "$AP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "pinacola-nat: rules applied (ip_forward=1, MASQUERADE $AP_SUBNET->$LAN_IF, FORWARD $AP_IF<->$LAN_IF)"
