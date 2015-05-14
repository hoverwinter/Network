
#-*- coding: UTF-8 -*-
import socket,select
import sys
import thread
from multiprocessing import Process

class Proxy:
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

    def connectMethod(self,request): #对于CONNECT处理可以添加在这里
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

    def run(self):
        request=self.getClientRequest()
        if request:
            if self.method in ['GET','POST','PUT',"DELETE",'HAVE']:
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

if __name__=='__main__':      
    host = '127.0.0.1' 
    port = 8888
    backlog = 5 
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind((host,port)) 
    server.listen(10) 
    while True:
        thread.start_new_thread(Proxy(server).run,())
        # p=Process(target=Proxy(server).run, args=()) #多进程
        # p.start()
