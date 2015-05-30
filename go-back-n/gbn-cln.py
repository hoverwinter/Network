#!/usr/bin/env python
#encoding: utf-8
import socket
import re
import os

def header(data):
    retval = -1
    if data[0]=='A':
        retval = int(re.match(r'ACK:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='S':
        retval = int(re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval

PREFIX = ""
if os.name == 'nt':
    PREFIX = os.path.abspath(os.path.join(os.path.dirname(__file__))) + '\\'

UDP_IP = '0.0.0.0'
UDP_PORT = 8888

revsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
revsock.bind((UDP_IP, UDP_PORT))
lastack = 0
expseq = 0
revbuf = ''
while True:
        data, addr = revsock.recvfrom(1024)    
        seq = header(data)
        if seq == -2:
            revsock.sendto("ACK:" + str(-2)+'\r\n\r\n', addr)  
            break   
        print 'expseq:'+str(expseq)
        print 'seq' + str(seq) 
        if seq != expseq:
            revsock.sendto("ACK:" + str(lastack)+'\r\n\r\n', addr)
            continue
        print repr(data)
        #receive data and update the expseq and send ack pkt
        prefix = re.match(r'SEQ:[0-9]+\r\n\r\n',data).group(0)
        data = data[len(prefix):]
        pktlen = len(data)    
        revbuf += data
        revsock.sendto("ACK:" + str(seq)+'\r\n\r\n', addr)
        #print seq
        lastack = seq
        expseq += pktlen


print "savename:",
savename = raw_input()
with open(os.name == 'nt' and PREFIX + savename or savename, 'wb') as f:
    f.write(revbuf)