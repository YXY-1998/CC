这是自己复现的CC机制，其在P4+mininet平台上复现了DCQCN等算法的基本机制

环境使用的p4-utils，随着P4语言版本的更新，未来可能部分代码需要修改，可以根据P4语言进行修改

其中，RP.py和RP-ip.py文件为RP点实现，不同之处在于RP-ip.py可以自己指定发往的目的IP，而RP.py的IP写在了文件中，每次使用需要修改

RP端发送数据包使用了scapy库中的sendpfast函数，如不需要使用INT数据包，可使用hping3命令，实验中该命令发包效果会更好

get.py 和get2.py可以获得到达目的主机数据包携带的INT信息，并计算了带宽和时延，其中get.py面向所有数据包，get2.py根据数据包源IP分别记录

