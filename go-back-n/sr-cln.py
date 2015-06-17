#!/usr/bin/env python
#encoding: utf-8

import socket
import re
import os

UDP_IP = '0.0.0.0'
UDP_PORT = 8888
PKTFIXEDLEN = 512

# 获得ACK或SEQ序号
def header(data):
    retval = -1
    if data[0]=='A':
        retval = int(re.match(r'ACK:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='S':
        retval = int(re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval

class linknode():
    def __init__(self,seq):
        self.seq = seq
        self.chk = False
        self.next = None
        self.data = None

# 初始化窗口
def init_windows():
    global base
    global tail
    curptr = base
    for i in range(0,15):
        if i == 0:
            continue
        else:
            curptr.next = linknode(tail.seq+PKTFIXEDLEN)
            curptr = curptr.next
            tail = curptr

# 扫描窗口，处理
def scanwindows(seq,data):
    global tail
    global revsock
    global base
    global revbuf

    if seq <= tail.seq and seq != -2:
        print "recv data:"+repr(data)
        revsock.sendto("ACK:" + str(seq)+'\r\n\r\n', addr)
    if seq < base.seq:
        return False
    elif seq == base.seq:
        base.chk = True  
        base.data = data
        while base.chk:
            prefix = re.match(r'SEQ:[0-9]+\r\n\r\n',base.data).group(0)
            base.data = base.data[len(prefix):]
            revbuf += base.data
            base = base.next
            tail.next = linknode(tail.seq + PKTFIXEDLEN)
            tail = tail.next 
            print 'slide a window!' 
            print 'base:'+str(base.seq)
            print 'tail:'+str(tail.seq)
    elif seq <= tail.seq and seq > base.seq:
        curptr = base
        while curptr.seq < seq:
            curptr = curptr.next
        if curptr.seq == seq:
            curptr.chk = True
            curptr.data = data

if __name__ == '__main__':
    base = linknode(0)
    tail = base
    revsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    revsock.bind((UDP_IP, UDP_PORT))
    init_windows()
    lastack = 0
    expseq = 0
    revbuf = ''
    while True:
            data, addr = revsock.recvfrom(1024)    
            seq = header(data)
            if seq == -2:
                revsock.sendto("ACK:" + str(-2)+'\r\n\r\n', addr)  
                break   
            scanwindows(seq,data)

    print "savename:",
    savename = raw_input()
    with open(savename, 'wb') as f:
        f.write(revbuf)
    
