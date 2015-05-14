#!/usr/bin/env python
#coding: utf-8
from socket import *
from threading import *
import re

def main():
	sock = socket(AF_INET,SOCK_STREAM)
	sock.bind(('',8888))
	sock.listen(1)
	while True:
		client, addr = sock.accept()
		req = client.recv(1024)
		host = re.search(r'Host: (\w+)',req).group(1)
		req = req.replace('localhost:8888','localhost')
		print req
		http = socket(AF_INET,SOCK_STREAM)
		http.connect((host,80))
		http.send(req)
		res = http.recv(1024)
		rt = res
		while len(res) == 1024:
			res = http.recv(1024)
			rt = rt + res
		client.send(rt)

		client.close()

if __name__ == '__main__':
	main()