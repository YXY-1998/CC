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

    fields_desc = [ #BitField("swid", 0, 7),
                    #BitField("qid", 0, 3),
                    BitField("priority", 0, 3),
                    BitField("qdepth", 0,13),
                    #BitField("portid",0,6)
                    BitField("pkt_length", 0,16)
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

count1=0
count2=0
count3=0
start_time1=time.time()
start_time2=time.time()
start_time3=time.time()

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
    global start_time1
    global start_time2
    global start_time3    
    global count1
    global count2
    global count3
    ip = pkt[IP] 
    if ip.src == "10.0.1.1":  
        count1=count1+1
        #计算时间差
        elapsed_time1 = time.time() - start_time1
        if elapsed_time1 >= 1:
            th1 = count1/elapsed_time1
            count1 = 0
            with open('data/q/throughput-my-q1.txt', 'a') as f:
                f.write(str(th1)+'\n')
                start_time1 = time.time()
        #计算RTT
        time1=pkt.time#数据包发送时间
        time2=time.time()#接收时间
        t1=2*(time2-time1)#单位s
        t1=t1*1000#单位ms
        with open('data/q/rtt-my-q1.txt', 'a') as f:
            f.write(str(t1)+'\n')

        #队列长度      
        if pkt.haslayer(IPOption_INT):
            #pkt.show2()
            options = pkt.getlayer(IPOption_INT)
            qdepth2 = options.int_headers[0].qdepth
            qdepth1 = options.int_headers[1].qdepth
            #print(qdepth)
            with open('data/q/qdepth1-my-q1.txt', 'a') as f:
                f.write(str(qdepth1)+'\n')
            with open('data/q/qdepth2-my-q1.txt', 'a') as f:
                f.write(str(qdepth2)+'\n')
        
    if ip.src == "10.0.1.2":  
        count2=count2+1
        #计算时间差
        elapsed_time2 = time.time() - start_time2
        if elapsed_time2 >= 1:
            th2 = count2/elapsed_time2
            count2 = 0
            with open('data/q/throughput-my-q2.txt', 'a') as f:
                f.write(str(th2)+'\n')
                start_time2 = time.time()
        #计算RTT
        time1=pkt.time#数据包发送时间
        time2=time.time()#接收时间
        t2=2*(time2-time1)#单位s
        t2=t2*1000#单位ms
        with open('data/q/rtt-my-q2.txt', 'a') as f:
            f.write(str(t2)+'\n')
        #队列长度      
        if pkt.haslayer(IPOption_INT):
            #pkt.show2()
            options = pkt.getlayer(IPOption_INT)
            qdepth2 = options.int_headers[0].qdepth
            qdepth1 = options.int_headers[1].qdepth
            #print(qdepth)
            with open('data/q/qdepth1-my-q2.txt', 'a') as f:
                f.write(str(qdepth1)+'\n')
            with open('data/q/qdepth2-my-q2.txt', 'a') as f:
                f.write(str(qdepth2)+'\n')

    if ip.src == "10.0.1.3":  
        count3=count3+1
        #计算时间差
        elapsed_time3 = time.time() - start_time3
        if elapsed_time3 >= 1:
            th3 = count3/elapsed_time3
            count3 = 0
            with open('data/q/throughput-my-q3.txt', 'a') as f:
                f.write(str(th3)+'\n')
                start_time3 = time.time()
        #计算RTT
        time1=pkt.time#数据包发送时间
        time2=time.time()#接收时间
        t3=2*(time2-time1)#单位s
        t3=t3*1000#单位ms
        with open('data/q/rtt-my-q3.txt', 'a') as f:
            f.write(str(t3)+'\n')    
        #队列长度      
        if pkt.haslayer(IPOption_INT):
            #pkt.show2()
            options = pkt.getlayer(IPOption_INT)
            qdepth2 = options.int_headers[0].qdepth
            qdepth1 = options.int_headers[1].qdepth
            #print(qdepth)
            with open('data/q/qdepth1-my-q3.txt', 'a') as f:
                f.write(str(qdepth1)+'\n')
            with open('data/q/qdepth2-my-q3.txt', 'a') as f:
                f.write(str(qdepth2)+'\n')        
 

def main():
    #iface = 'h2-eth0'
    iface = get_if()
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface, prn = lambda x: handle_pkt(x))
    


if __name__ == '__main__':
    main()
