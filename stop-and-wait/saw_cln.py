#!/usr/bin/env python
#encoding: utf-8

# Author: Hover Winter
# Time: 2015-05-23
# License: GPL/v2.0
# This program works well in UNIX/LINUX, request for tests in Windows

import socket
import re
import time

CLN = ('localhost',10241)
PKTDATALEN = 512

def header(data):
    retval = -1
    if data[0]=='A':
        retval = int(re.match(r'ACK:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='S':
        retval = int(re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval

#
#	@input: 
#		flag: True 发生丢包 False 不丢包
#
def main(flag=False):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.bind(CLN)
	index = 0 # 应该接收到的序号
	recvbuf = '' # 接收到的数据

	while True:
		data,addr = sock.recvfrom(1024)
		rcvindex = header(data)
		if rcvindex == -1: # 结束信号
			sock.sendto('ACK:-1\r\n\r\n',addr)
			print 'Finish...'
			break
		if flag and rcvindex == 2*PKTDATALEN: # 模拟丢包
			time.sleep(2)
			# 丢掉超时重发的重复包
			_,_ = sock.recvfrom(1024)
			_,_ = sock.recvfrom(1024)
			_,_ = sock.recvfrom(1024)
			# 丢掉当前一个数据包
			index = PKTDATALEN
			recvbuf = recvbuf[:-PKTDATALEN]
			print 'Packet lost occured!'
			flag = False
			continue
		print 'rcv',rcvindex,'exp',index
		sock.sendto('ACK:%s\r\n\r\n' %index,addr) # 返回确认，不能是rcvindex，而是期待的序号，这样包括了丢包的情形
		print 'ACK %s' % index
		if rcvindex == index: # 正确接收处理 
			attach = re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(0)
			data = data[len(attach):] # 去掉报文头
			index += len(data) # 期待下一个数据起始位置
			recvbuf += data # 合并数据
		else:
			pass # 否则直接丢弃

	# 保存文件
	filename = raw_input('Save into file [default stdout] :')
	if not filename:
		print recvbuf
	else:
		with open(filename,'w') as f:
			f.write(recvbuf)
		
if __name__ == "__main__":
	lost = raw_input('Packet LOST if ANY key besides ENTER pressed...')
	if lost:
		main(True)
	else:
		main(False)