import sys, argparse, ipaddress
from scapy.all import *
from scapy.layers.http import *

parser = argparse.ArgumentParser(description='Process some arguments')
parser.add_argument('-p', '--pcap', type=str, help='pass pcap file name with path if not in cwd')
argsc = parser.parse_args()

pcap = argsc.pcap

data = ('00 1c 23 10 f8 f1 00 1b 17 01 10 20 08 00 45 00 00 58 ca a4 00 00 80 11 f6 67 0a 69 ee 36 32 07 4e e2 50 fc 27 11 00 44 99 22 3e 2f 8d cc 40 d1 40 ca 2d 2d a8 2c 80 e6 ca da fa 3d de d4 0a 92 c5 68 69 cc 5c a8 14 bf af ed be a0 9b 2c 2e d0 40 ca 3e 7d 3b 1f 6e a4 0f d9 43 68 61 72 6f 69 65 20 69 70 2d 76')
data_list = data.split(" ")

data2 = ('00 1b 17 01 10 20 00 1c 23 10 f8 f1 08 00 45 00 00 58 26 dd 00 00 40 11 da 2f 32 07 4e e2 0a 69 ee 36 27 11 50 fc 00 44 3a bb 7e 2a 9d ec 40 d0 40 ca 3d 2d 08 2d 80 e4 ca da fa 3d de d4 0a 92 c5 68 69 cc 5c a8 14 bf af ed ca 4d 97 cc be d1 40 ca 3e 7d 3b 1f 64 a4 1f d9 43 68 61 72 6f 69 65 20 69 70 2d 76')
data2_list = data2.split(" ")


pkts=rdpcap(str(pcap))

for pkt in pkts:
    l2 = Ether()
    l2.type = 'IPv4'
    l2.src = pkt[Ether].src
    l2.dst = pkt[Ether].dst
    i4 = IP()
    i4.src = pkt[IP].src
    i4.dst = pkt[IP].dst
    u = UDP()
    u.sport = pkt[UDP].sport
    u.dport = pkt[UDP].dport
    if pkt[UDP].dport == 10001:
        data_s = ''.join(data_list)
        pktu = l2/i4/u/Raw(load=data_s)
        sendp(pktu, iface="ens224")
    else:
        data_s = ''.join(data2_list)
        pktu = l2/i4/u/Raw(load=data_s)
        sendp(pktu, iface="ens256")
