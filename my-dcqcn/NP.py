#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import IP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR
import time

from p4utils.utils import thrift_API
import nnpy
import struct
from p4utils.utils.helper import load_topo


count1=0
count2=0
count3=0

def get_if():
#获取接口列表['lo','eth0','eth1','eth2']
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def handle_pkt(pkt):
    print("got a packet")
    global count1
    global count2
    global count3
    
    iface = get_if()
    ip = pkt[IP]

    if ip.tos == 3:
   
        #print("got a feedback packet")  
        etherdst=pkt[Ether].src
        addr=ip.src#获取IP地址        
        cnp = Ether(src=get_if_hwaddr(iface), dst= etherdst) / IP(dst=addr, tos=2) / UDP(dport=4321, sport=1234) #反馈包  
        if ip.src == "10.0.1.1":    
            if count1>=50:#2个包返回一次
                sendp(cnp,iface = iface)
                count1=0
            else:
                count1 = count1+1

        if ip.src == "10.0.1.2":    
            if count2>=50:#2个包返回一次
                sendp(cnp,iface = iface)
                count2=0
            else:
                count2 = count2+1

        if ip.src == "10.0.1.3":    
            if count3>=50:#2个包返回一次
                sendp(cnp,iface = iface)
                count3=0
            else:
                count3 = count3+1
        


def main():
    #iface = 'h2-eth0'
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface, prn = lambda x: handle_pkt(x))
    #while True:
        #sniff(filter="udp", iface = iface, prn = lambda x: handle_pkt(x))
        #sendp(cnp,iface = iface)
        #time.sleep(5)


if __name__ == '__main__':
    main()
