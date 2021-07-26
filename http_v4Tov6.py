import sys, argparse, ipaddress
from scapy.all import *
from scapy.layers.http import *

parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-p', '--pcap', type=str, help='pass pcap file name with path if not in cwd')
argsc = parser.parse_args()

load_layer("http")
pcap = argsc.pcap

pkts=rdpcap(str(pcap))

for pkt in pkts:
    l2 = Ether()
    l2.type = 'IPv6'
    l2.src = pkt[Ether].src
    l2.dst = pkt[Ether].dst
    i6 = IPv6()
    i6.src = str(ipaddress.IPv6Address('2002::' + pkt[IP].src))
    i6.dst = str(ipaddress.IPv6Address('2002::' + pkt[IP].dst))
    del pkt[TCP].chksum
    pkt6 = l2/i6/pkt[TCP]
    # pkt6.display()
    if pkt[TCP].dport==80:
        sendp(pkt6, iface="ens224")
    else:
        sendp(pkt6, iface="ens256")