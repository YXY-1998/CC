#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR
import time

from p4utils.utils import thrift_API
import nnpy
import struct
from p4utils.utils.helper import load_topo

class SwitchTrace(Packet):

    fields_desc = [ 
                    #BitField("priority", 0, 3),
                    #BitField("qdepth", 0,13),
                    #BitField("pkt_length", 0,16)
                    BitField("qdepth", 0,32),
                    BitField("lambda1",0,32),
                    BitField("lambda2",0,32)
                  ]
    def extract_padding(self, p):
                return "", p


class IPOption_INT(IPOption):
    name = "INT"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="int_headers",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),#短整形字段，名字count，初始值0
                    PacketListField("int_headers",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

pkt_count=0
start_time=time.time()


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
    #计算吞吐量
    global pkt_count
    global start_time
    if pkt[IP].dst == "10.0.2.5":
        pkt_count=pkt_count+1
        #t=time.time()
        #计算时间差
        elapsed_time = time.time() - start_time
        # 如果已经过去一秒，则计算并输出每秒抓取的数据包数量，并重置计数器和开始时间
        if elapsed_time >= 1:
            th = pkt_count/elapsed_time
            pkt_count = 0
            with open('data/throughput-dcqcn.txt', 'a') as f:
                f.write(str(th)+'\n')
            start_time = time.time()

        #计算RTT
        #iface = get_if()
        #ip = pkt[IP]
        time1=pkt.time#数据包发送时间
        #print(time1)
        time2=time.time()#接收时间
        #print(time1,time2)
        t=2*(time2-time1)#单位s
        #t=t*1000000#单位微妙
        t=t*1000#单位ms
        print(t)
        with open('data/rtt-dcqcn.txt', 'a') as f:
            f.write(str(t)+'\n')

        #队列长度
        if pkt.haslayer(IPOption_INT):
            pkt.show2()
            options = pkt.getlayer(IPOption_INT)
            #print(options)
            qdepth2 = options.int_headers[0].qdepth
            qdepth1 = options.int_headers[1].qdepth
            #print(qdepth)
            with open('data/qdepth1-dcqcn.txt', 'a') as f:
                f.write(str(qdepth1)+'\n')
            with open('data/qdepth2-dcqcn.txt', 'a') as f:
                f.write(str(qdepth2)+'\n')


    
        
 

def main():
    #iface = 'h2-eth0'
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface, prn = lambda x: handle_pkt(x))
    


if __name__ == '__main__':
    main()
