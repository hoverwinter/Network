#!/usr/bin/env python
#encoding: utf-8

import socket
import os
import random
import re

def header(data):
    retval = -1
    if data[0]=='A':
        retval = int(re.match(r'ACK:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='S':
        retval = int(re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval

def sendterminalsg(sdsocket, val=-2):
    expseq = val
    if random.randint(0, 5) != 0:
        sdsocket.sendto("SEQ:" + str(expseq) + "\r\n\r\n", dest)
    acknowledged = False
    ctnto = 0
    while not acknowledged:
        try:
            ACK, address = sdsocket.recvfrom(1024)
            ctnto = 0
            # print ACK
            ackseq = header(ACK)
            # print ackseq
            # print expseq
            if ackseq == expseq:
                acknowledged = True
        except socket.timeout:
            ctnto += 1
            if random.randint(0, 5) != 0:
                sdsocket.sendto("SEQ:" + str(expseq) + "\r\n\r\n", dest)
            if ctnto == 10:
                break


class linknode():
    def __init__(self,seq):
        self.seq = seq
        self.next = None

def init_window():
    global base
    global user_input
    global expseq
    global sdsocket
    global tail
    global expseq_tl
    global raw_str
    global dest
    curptr = base
    for i in range(0, 15):
            if not user_input:
                break
            user_input = 'SEQ:' + str(expseq) + '\r\n\r\n' + user_input
            if random.randint(0, 5) != 0:
                sdsocket.sendto(user_input, dest)
            if i == 0:
                continue
            else:
                curptr.next=linknode(expseq)                
                curptr=curptr.next
                tail = curptr
            expseq = expseq_tl
            expseq_tl = min(expseq + PKTFIXEDLEN, len(raw_str))
            user_input = raw_str[expseq:expseq_tl]

def slide():
    global user_input
    global expseq
    global sdsocket
    global expseq_tl
    global raw_str
    global dest
    if not user_input:
        return linknode(-1)
    user_input = 'SEQ:' + str(expseq) + '\r\n\r\n' + user_input
    if random.randint(0, 5) != 0:
        sdsocket.sendto(user_input, dest)
    retnode = linknode(expseq)
    expseq = expseq_tl    
    expseq_tl = min(expseq + PKTFIXEDLEN, len(raw_str))
    user_input = raw_str[expseq:expseq_tl]
    return retnode

def resend():
    global base
    global raw_str
    global sdsocket
    global dest
    curptr = base
    while curptr:
        tmpend=min(curptr.seq+PKTFIXEDLEN,len(raw_str))
        print 'resend seq:' + str(curptr.seq)
        if random.randint(0, 5) != 0:
            sdsocket.sendto('SEQ:' + str(curptr.seq) + '\r\n\r\n' +raw_str[curptr.seq:tmpend], dest)
        curptr = curptr.next

base = linknode(0)
tail = linknode(0)
N = 15


PREFIX = ""
if os.name == 'nt':
    PREFIX = os.path.abspath(os.path.join(os.path.dirname(__file__))) + '\\'
PKTFIXEDLEN = 512
sdsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sdsocket.settimeout(0.5)
print 'destip:',
destaddr = raw_input()
dest = (destaddr, 8888)
raw_str = ''
expseq = 0
print "filename:",
filename = raw_input()
with open(os.name == 'nt' and PREFIX + filename or filename, 'rb') as f:
    raw_str = f.read()
expseq_tl = min(expseq + PKTFIXEDLEN, len(raw_str))
# print raw_str
user_input = raw_str[expseq:expseq_tl]


#print expseq
# print expseq_tl
init_window()
#acknowledged = False
#seqchgfg = False
finish_fg = False
while True:
    try:
        if finish_fg:
            break
        ACK, address = sdsocket.recvfrom(1024)
        print repr(ACK)
        ackseq = header(ACK)

        # print ackseq
        print 'nextseq:'+str(expseq)
        while base.seq <= ackseq and not finish_fg:
            print 'base:'+str(base.seq)
            if base.seq == -1:
                finish_fg = True
                break
            base=base.next
            tail.next = slide()                
            if tail.next.seq == -1:
                print 'EOF!'
                pass
            else:
                tail = tail.next
                print  'slide a window!'        
    except socket.timeout:
        print 'timeout!'
        resend()
print repr(ACK)
# if not seqchgfg:
#    expseq = expseq_tl

sendterminalsg(sdsocket)
sendterminalsg(sdsocket, -3)
sdsocket.close()
