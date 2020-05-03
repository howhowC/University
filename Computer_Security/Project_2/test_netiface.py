#!/usr/bin/python3
import netifaces
import pprint
import socket
import struct

# gws = netifaces.gateways()
# print(gws)
# ttt =  gws['default'][2][0]
# print(ttt)

# x = netifaces.interfaces()
# print(x)

# for i in x:
#     if i != "lo":
#         print("\nInterface: " + i)
#         mac = netifaces.ifaddresses(i)[netifaces.AF_LINK][0]["addr"]
#         print("Mac addr: " + mac)

#     try:
#         ip = netifaces.ifaddresses(i)[netifaces.AF_INET][0]["addr"]

#         print("IP addr: {0} ".format(ip))
#     except KeyError:
#         print("NO IP")
#         continue

