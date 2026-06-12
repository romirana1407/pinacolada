#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - full rogue AP bring-up (used by pineapple-ap.service)
pkill hostapd; sleep 1
nmcli dev set $AP_IF managed no
ip addr flush dev $AP_IF; ip addr add 192.168.66.1/24 dev $AP_IF; ip link set $AP_IF up
hostapd -B /etc/hostapd/pineapple-lab.conf
[ -f /etc/pineapple-dnsmasq.conf ] || printf "interface=$AP_IF\nbind-interfaces\ndhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\ndhcp-option=option:router,192.168.66.1\ndhcp-option=option:dns-server,1.1.1.1\nserver=1.1.1.1\n" > /etc/pineapple-dnsmasq.conf
pkill -f pineapple-dnsmasq; dnsmasq --conf-file=/etc/pineapple-dnsmasq.conf
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -C FORWARD -i $AP_IF -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $AP_IF -o eth0 -j ACCEPT
iptables -C FORWARD -i eth0 -o $AP_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o $AP_IF -m state --state RELATED,ESTABLISHED -j ACCEPT
