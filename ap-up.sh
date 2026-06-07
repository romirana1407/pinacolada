#!/bin/bash
# Piña Colada - full rogue AP bring-up
pkill hostapd; sleep 1
nmcli dev set wlan0 managed no
ip addr flush dev wlan0; ip addr add 192.168.66.1/24 dev wlan0; ip link set wlan0 up
hostapd -B /etc/hostapd/pinacola.conf
[ -f /etc/pinacola-dnsmasq.conf ] || printf "interface=wlan0\nbind-interfaces\ndhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\ndhcp-option=option:router,192.168.66.1\ndhcp-option=option:dns-server,1.1.1.1\nserver=1.1.1.1\n" > /etc/pinacola-dnsmasq.conf
pkill -f pinacola-dnsmasq; dnsmasq --conf-file=/etc/pinacola-dnsmasq.conf
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -C FORWARD -i wlan0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
iptables -C FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
