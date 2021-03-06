#!/usr/bin/env python
#-*- coding: UTF-8 -*-
import socket,select
import sys
import thread
from multiprocessing import Process
import re
import json
config = None

class ProxyServer:
    def __init__(self,soc):
        self.client,_=soc.accept()
        self.target=None
        self.request_url=None
        self.BUFSIZE=4096
        self.method=None
        self.targetHost=None

    def getClientRequest(self):
        request=self.client.recv(self.BUFSIZE)
        if not request:
            return None
        cn=request.find('\n')
        firstLine=request[:cn]
        print firstLine[:len(firstLine)-9]
        line=firstLine.split()
        self.method=line[0]
        self.targetHost=line[1]
        return request

    def commonMethod(self,request):
        tmp=self.targetHost.split('/')
        net=tmp[0]+'//'+tmp[2]
        request=request.replace(net,'')
        targetAddr=self.getTargetInfo(tmp[2])
        try:
            (fam,_,_,_,addr)=socket.getaddrinfo(targetAddr[0],targetAddr[1])[0]
        except Exception as e:
            print e
            return
        self.target=socket.socket(fam)
        self.target.connect(addr)
        self.target.send(request)
        self.nonblocking()

    def connectMethod(self,request):
        targetAddr=self.getTargetInfo(self.targetHost)
        try:
            (fam,_,_,_,addr)=socket.getaddrinfo(targetAddr[0],targetAddr[1])[0]
        except Exception as e:
            print e
            return
        self.target=socket.socket(fam)
        self.target.connect(addr)

        self.client.send(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")

        request = self.client.recv(self.BUFSIZE)
        
        self.target.send(request)
        self.nonblocking()

    def auth(self):
    	inputs=[self.client]
        readable,writeable,errs=select.select(inputs,[],inputs,3)
        for soc in readable:
            data=soc.recv(self.BUFSIZE)
            info = re.split('\s+',data.strip())
            print info[0]
            for users in config['users']:
                if users['username']  == info[0] and info[1] == users['password']:
                    if users['mode'] == 1:
                        self.mode = 1
                        self.rules = users['allow']
                    elif users['mode'] == 0:
                        self.mode = 0
                        self.rules = users['forbid']
                    elif users['mode'] == 2:
                        self.mode = 2
                        self.rules = users['phishing']
                    else:
                        self.mode = 3
                        self.rules = None
                    return True
        return False

    def filter(self):
        print 'FILTER:','[ALLOW]' if self.mode==1 else '[FORBID]',self.rules,self.targetHost
        for item in self.rules:
            if self.mode == 0:
                if re.findall(item,self.targetHost):
                    print "No right to access!"
                    return True
                else:
                    return False
            if self.mode == 1:
                if re.findall(item,self.targetHost):
                    return False
                else:
                    print "No right to access!"
                    return True
        if self.mode == 0:
            return False
        if self.mode == 1:
            return True

    def phishing(self,request):
        for item in self.rules:
            if re.findall(item['src'],self.targetHost):
                print 'PHISHING:',self.targetHost,'=>',item['dst']
                self.request = request.replace(self.targetHost.split('/')[2],item['dst'])
                self.targetHost = self.targetHost.replace(self.targetHost.split('/')[2],item['dst'])
                print self.request
                return True
        return False


    def run(self):
    	res =  self.auth()
        if not res:
            self.client.send('failure')
            self.client.close()
            return
        else:
        	self.client.send('success')

        request=self.getClientRequest()
        print request
        if request:
            if self.mode == 1 or self.mode == 0:
                if self.filter():
                    return
            if self.mode == 2:
                self.phishing(request)
            if self.method in ['GET','POST','PUT','DELETE','HAVE']:
                self.commonMethod(request)
            elif self.method=='CONNECT':
                self.connectMethod(request)

    def nonblocking(self):
        inputs=[self.client,self.target]
        while True:
            readable,writeable,errs=select.select(inputs,[],inputs,3)
            if errs:
                break
            for soc in readable:
                data=soc.recv(self.BUFSIZE)
                if data:
                    if soc is self.client:
                        self.target.send(data)
                    elif soc is self.target:
                        self.client.send(data)
                else:
                    break
        self.client.close()
        self.target.close()

    def getTargetInfo(self,host):
        port=0
        site=None
        if ':' in host:
            tmp=host.split(':')
            site=tmp[0]
            port=int(tmp[1])
        else:
            site=host
            port=80
        return site,port

def main():
    global config 
    f = open("config/server.json") 
    config = json.load(f)
    f.close()  
    host = config['server']
    port = config['port']
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind((host,port)) 
    server.listen(10) 
    while True:
        thread.start_new_thread(ProxyServer(server).run,())
        # p=Process(target=Proxy(server).run, args=()) #多进程
        # p.start()

if __name__=='__main__': 
    main()