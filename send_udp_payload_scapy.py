from scapy.all import *
from ipaddress import IPv4Address

import random
import string

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    # print("Random string of length", length, "is:", result_str)
    return result_str

start_ip = IPv4Address('192.168.0.1')
# datal = ["testuser 19316 19230  0 Mar22 tty2", "00:17:28 /usr/lib/firefox/firefox -contentproc -childID 1 ", "-isForBrowser -prefsLen 1 -prefMapSize 224033", "-parentBuildID 20210222142601 -appdir /usr/lib/firefox/browser 19230 true tab"]

for i in range(1,10):
    datal = [get_random_string(501), get_random_string(501), get_random_string(501), get_random_string(501)]
    ip = str(start_ip + i)
    """
    for data in datal:
        a = Ether(dst="00:02:15:37:a2:44",src="00:ae:f3:52:aa:d1")/IP(src="10.6.3.11",dst=ip)/UDP(sport=20223, dport=1194)/Raw(load=data)
        sendp(a, iface="ens224")
    """
    for n, data in enumerate(datal):
        if n%2==0:
            a = Ether(src="00:ae:f3:52:aa:d1", dst="00:02:15:37:a2:44")/IP(src="10.6.3.11", dst=ip, ttl=3)/UDP(sport=20223, dport=1194)/Raw(load=data)
            sendp(a, iface="ens224")
        else:
            a = Ether(src="00:02:15:37:a2:44", dst="00:ae:f3:52:aa:d1")/IP(src=ip, dst="10.6.3.11", ttl=3)/UDP(sport=1194, dport=20223)/Raw(load=data)
            sendp(a, iface="ens256")
    print(i, "th flow done")