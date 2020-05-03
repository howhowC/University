#!/usr/bin/python3
import scapy.all as scapy
import netifaces
import base64
from argparse import RawTextHelpFormatter
import argparse
import ipaddress

def getRouterIP():
	gw = netifaces.gateways()
	routerIP = gw['default'][2][0]
	return routerIP 

def get_device_list(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #利用scapy模組的Ether物件
    arp_request_broadcast = broadcast/arp_request #把arp_requeste跟broadcast混合，發送此混合封包，然後它會自動送到廣播的MAC

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=0)[0]
    client_list = []

    routerIP = getRouterIP()
    fil_1 = re.sub(r"\d+$","1",routerIP)
    fil_2 = re.sub(r"\d+$","2",routerIP)
    # print(fil_1 +" "+ fil_2)
    for element in answered_list:
        if element[1].psrc != fil_1 and element[1].psrc != fil_2:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n=========================================")
    for client in results_list:
        # print(client)
        print(client["ip"] + "\t\t" + client["mac"])

def scan_all_device():
    routerIP = str(getRouterIP()) + "/24"
    scan_result = get_device_list(routerIP) #scan("192.168.204.2")可拿到所有子網路的封包回應
    print_result(scan_result)

def sxor(s1):    
    return '.'.join([str((0xffffffff << (32 - s1) >> i) & 0xff) for i in [24, 16, 8, 0]])

if __name__ == "__main__":
    scan_all_device()
    # bbb = int(str(getRouterIP()))
    # print(bbb)
    # ccc = bbb and b"255.255.255.0"
    # print(ccc)

    # ddd = int(b"64")
    # eee = int(b"96")
    # print(ddd & eee)