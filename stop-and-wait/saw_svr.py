#!/usr/bin/env python
#encoding: utf-8

# Author: Hover Winter
# Time: 2015-05-23
# License: GPL/v2.0
# This program works well in UNIX/LINUX, request for tests in Windows

import socket
import re

SVR = ('localhost',10240)
PKTDATALEN = 512 #每一个Packet附带数据最大字节数
# 协议格式
	# 数据
	# SQE:[num]\r\n
	# \r\n
	# data

	# 确认
	# ACK:[num]\r\n
	# \r\n

	# num表示包的起始字节在文件中位置,SQE:-1表示传输完毕,ACK:-1表示确认传输完毕

#
#	@function: 解析报文头 序号
#	@return: 序号 or -1
#
def header(data):
    retval = -1
    if data[0]=='A':
        retval = int(re.match(r'ACK:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='S':
        retval = int(re.match(r'SEQ:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval

def handle(dst,sock):
	raw_data = None # 需要发送的文件
	while True:
		filename = raw_input('filename:')
		# filename = 'saw_svr.py' #测试使用
		if filename:
			with open(filename) as f:
				raw_data = f.read()
			break
	# 数据传输
	index = 0 # 发送的序号
	nextindex = min(PKTDATALEN+index,len(raw_data)) # 待发的下一个序号
	data = raw_data[index:nextindex] # 取得当前分组数据

	while data:
		flag = True # 用于丢包时，将index设置为rcvindex
		ack = False # 是否已经确认
		pkt = "SEQ:"+str(index)+"\r\n\r\n"+data # 分组
		sock.sendto(pkt,(dst,10241))
		while not ack:
			try:
				res,addr = sock.recvfrom(1024)
				rcvindex = header(res) # 客户端返回的序号
				print 'rcv',rcvindex,'snd',index
				# 正确接收
				if rcvindex == index:
					ack = True
					print 'ACK %s' % index
				# ACK序号不一致，发生丢包
				else:
					index = rcvindex
					# print 'NAK %s' % rcvindex
					flag = False # 重发rcvindex而非nextindex
					break
			except socket.timeout:
				# 发生超时
				print 'timeout'
				sock.sendto(pkt,(dst,10241))
		# 确认，发下一个包
		if flag:
			index = nextindex
		# 到文件结束？
		nextindex = min(PKTDATALEN+index,len(raw_data))
		# print 'in',index,'next',nextindex
		data = raw_data[index:nextindex]
	# 关闭连接的确认
	sock.sendto("SEQ:-1\r\n\r\n",(dst,10241))
	ack = False
	counter = 1 # 计数：10个timeout仍未收到Client的传输结束确认，不再等待ACK -1
	while not ack:
		try:
			res,addr = sock.recvfrom(1024)
			rcvindex = header(res)
			if rcvindex == -1:
				ack = True
				print 'Finish and Close...'
		except socket.timeout:
			print 'timeout...'
			if counter > 10:
				break
			counter += 1
			sock.sendto("SEQ:-1\r\n\r\n",(dst,10241))

def main():
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.settimeout(0.5) # socket超时时间
	sock.bind(SVR)
	while True:
		dst = raw_input('DST IP ADDR:')
		# dst = 'localhost' #测试使用
		if dst:
			handle(dst,sock)
	sock.close()

if __name__ == "__main__":
	main()