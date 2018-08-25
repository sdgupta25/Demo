'''
from scapy.all import * 

pkts = sniff(filter='tcp',count = 10)

for i in range(10):
	pkts[i].show()

'''
from scapy.all import * 

def sniffing(pkt):
	pkt.show()

sniff(filter='tcp',prn=sniffing)
