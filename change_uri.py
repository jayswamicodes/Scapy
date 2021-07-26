import sys, argparse
from scapy.all import *
from scapy.layers.http import *
load_layer("http")
parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-p', '--pcap', type=str, help='pass pcap file name with path if not in cwd')
parser.add_argument('-u', '--uri', type=str, help='pass URI for http method')
parser.add_argument('-m', '--httpmethod', type=str, help='type of http method')
argsc = parser.parse_args()
pcap = argsc.pcap
pkts=rdpcap(str(pcap))

for pkt in pkts:
    del pkt[IP].len
    del pkt[IP].chksum
    if TCP in pkt:
        del pkt[TCP].chksum
        if pkt[TCP].dport==80:
            if HTTP in pkt:
                if pkt[HTTP].Method==argsc.httpmethod:
                    pkt[HTTP].Path = argsc.uri
                    pkt.show2()
            sendp(pkt, iface="ens224")
        else:
            sendp(pkt, iface="ens256")