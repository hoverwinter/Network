#!/usr/bin/env python
#-*- coding: UTF-8 -*-
import socket,select
import sys
import thread
from multiprocessing import Process
import re
import json
import os

config = None

class ProxyClient:
    def __init__(self,soc):
        self.client,_=soc.accept()
        self.server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server.connect((config['server'],config['server_port']))
        self.BUFSIZE=4096

    def auth(self):
    	self.server.send('%s\n%s'%(config['username'], config['password']))
        data=self.server.recv(self.BUFSIZE)
        if data == 'success':
        	return True
        else:
        	return False

    def run(self):
    	res =  self.auth()
        if not res:
            self.client.close()
            return
        self.request = self.client.recv(self.BUFSIZE)
        if self.request != '':
        	print "[",self.request.split(' ')[0],"]",self.request.split(' ')[1]
        	self.server.send(self.request)

	        inputs=[self.client,self.server]
	        while True:
	            readable,writeable,errs=select.select(inputs,[],inputs,3)
	            if errs:
	                break
	            for soc in readable:
	                data=soc.recv(self.BUFSIZE)
	                if data:
	                    if soc is self.client:
	                        self.server.send(data)
	                    elif soc is self.server:
	                        self.client.send(data)
	                else:
	                    break
	        self.client.close()
	        self.server.close()

def main():
    global config
    f = open('config/client.json')
    config = json.load(f)
    f.close()
    host = config['local']
    port = config['local_port']
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind((host,port)) 
    server.listen(10) 
    while True:
        thread.start_new_thread(ProxyClient(server).run,())
        # p=Process(target=Proxy(server).run, args=()) #多进程
        # p.start()

if __name__=='__main__': 
    main()     
    
