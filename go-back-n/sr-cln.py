import socket
import netlib1
import re
import os
from netlib1 import getseq

PREFIX = ""
if os.name == 'nt':
    PREFIX = os.path.abspath(os.path.join(os.path.dirname(__file__))) + '\\'

UDP_IP = '0.0.0.0'
UDP_PORT = 8888


class linknode():
    def __init__(self,seq):
        self.seq = seq
        self.chk = False
        self.next = None
        self.data = None



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

def scanwindows(seq,data):
    global tail
    global revsock
    global base
    global revbuf

    if seq <= tail.seq and seq != -2:
        print "recv data:"+repr(data)
        revsock.sendto("ack:" + str(seq)+'\r\n\r\n', addr)
    if seq < base.seq:
        return False
    elif seq == base.seq:
        base.chk = True  
        base.data = data
        while base.chk:
            prefix = re.match(r'seq:[0-9]+\r\n\r\n',base.data).group(0)
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



PKTFIXEDLEN = 512
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
        seq = getseq(data)
        if seq == -2:
            revsock.sendto("ack:" + str(-2)+'\r\n\r\n', addr)  
            break   
        #print 'expseq:'+str(expseq)
        #print 'seq' + str(seq) 
        
        #if seq != expseq:
        #    revsock.sendto("ack:" + str(lastack)+'\r\n\r\n', addr)
        #    continue
        scanwindows(seq,data)
        #    slide()  #slide and update data



print "savename:",
savename = raw_input()
with open(os.name == 'nt' and PREFIX + savename or savename, 'wb') as f:
    f.write(revbuf)
    
