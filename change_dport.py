import sys, argparse
from scapy.all import *
from scapy.layers.http import *

parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-p', '--pcap', type=str, help='pass pcap file name with path if not in cwd')
parser.add_argument('-d', '--dport', type=int, help='pass destination port of server in pcap')
parser.add_argument('-n', '--new_port', type=int, help='pass destination port of server to be changed to')
argsc = parser.parse_args()

load_layer("http")
pcap = argsc.pcap
dport= argsc.dport
new_port = argsc.new_port

load_layer("http")
pcap = argsc.pcap
dport= argsc.dport

# Load the packets from pcap
pkts=rdpcap(str(pcap))

# visit packet by packet
for pkt in pkts:
    del pkt[IP].len
    del pkt[IP].chksum
    if TCP in pkt:
        del pkt[TCP].chksum
        if pkt[TCP].dport==dport:
            # client side packets
            pkt[TCP].dport=new_port
            sendp(pkt, iface="ens224")
        else:
            # server side packets
            pkt[TCP].sport=new_port
            sendp(pkt, iface="ens256")