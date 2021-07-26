import sys, argparse
from scapy.all import *
from scapy.layers.http import *

# https://github.com/tintinweb/scapy-ssl_tls#option-3-manual-installation : install scapy SSL
# ace-se-downtown-pullman-1.pcap
parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-p', '--pcap', type=str, help='pass pcap file name with path if not in cwd')
parser.add_argument('-ip', '--dstip', type=str, help='pass pcap file name with path if not in cwd')
argsc = parser.parse_args()

load_layer("http")
pcap = argsc.pcap
dstip = argsc.dstip

pkts=rdpcap(str(pcap))

for pkt in pkts:
    del pkt[IP].len
    del pkt[IP].chksum
    if TCP in pkt:
        del pkt[TCP].chksum
        if pkt[TCP].dport==80:
            pkt[IP].dst= '192.168.1.1'
            sendp(pkt, iface="ens224")
        else:
            sendp(pkt, iface="ens256")
