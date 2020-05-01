#!/usr/bin/python3
import scapy.all as scapy
from argparse import RawTextHelpFormatter
import argparse

def scan(ip):
    # scapy.arping(ip)
    # scapy.ls(scapy.Ether())
    # print("\n")
    # scapy.ls(scapy.ARP())

    # arp_request = scapy.ARP()
    # print(arp_request.summary())

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #利用scapy模組的Ether物件
    arp_request_broadcast = broadcast/arp_request #把arp_requeste跟broadcast混合，發送此混合封包，然後它會自動送到廣播的MAC
    # print("---arp_request---")
    # print(arp_request.summary()+"\n")
    # print("---arp_request_broadcast---")
    # print(arp_request_broadcast.summary()+"\n")
    # arp_request_broadcast.show() #能印出更詳細的細節

    # answered, unanswered = scapy.srp(arp_request_broadcast, timeout = 1)
    # print(answered.summary())

    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    # print("IP\t\t\tMAC Address\n=====================================")
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
        # print(element[1].psrc + "\t\t" + element[1].hwsrc)
        # print("======================================")
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n=====================================")
    for client in results_list:
        # print(client)
        print(client["ip"] + "\t\t" + client["mac"])

def get_argments():
    parser = argparse.ArgumentParser(formatter_class = RawTextHelpFormatter)
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.\nPort 24 can catch all subnet packet.") #當使用者在終端機執行 python network_scanner.py -target 10.0.1.2/24，期望在終端機看到輸出看到IP range。
    options = parser.parse_args() #解析使用者輸入的值
        
    return options

input_cmd = get_argments()
scan_result = scan(input_cmd.target) #scan("192.168.204.2")可拿到所有子網路的封包回應
print_result(scan_result)
