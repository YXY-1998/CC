
from p4utils.utils import thrift_API
import nnpy
import struct
from p4utils.utils.helper import load_topo

import time


class controller():

    def __init__(self, port):
        self.port = port#监听端口
        
        pre_type = thrift_API.PreType.SimplePre
        
        self.controller = thrift_API.ThriftAPI(self.port, 'localhost', pre_type)
            
    
    def read_and_write(self,line):
        

        self.k=line
        self.controller.register_write("my_register", int(11), self.k)
        entries=self.controller.register_read("my_register")
        print(entries)


def main():
    port=int(9090)#监听端口
    #register_name="ecn"#寄存器名字
    
    with open('k.txt', 'w+') as f:#文件初始化
        f.write(str(0))
    
    while True:
        with open('k.txt', 'r+') as f:            
            line = f.read()
            line = line.strip("\n")
            line = line.strip()
            line = line.strip("\t")
            #k = int(float(line))
        if line!= 0:
            controller(port).read_and_write(line)
    

if __name__ == '__main__':
    main()
