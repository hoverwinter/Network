import socket
import sys
import threading
import re
cache={}
threads=[]
dspoofurl='www.provence-tomato.com'
def s2cworker(nsock,connection):
    print "receiving data from server"
    while True:
        print "----------receive------------"
        print 'server:  '+data
        ssdata = nsock.recv(65535)
        #print len(ssdata)
        #print 'ssdata:'+ssdata

        if ssdata and len(ssdata):
            connection.sendall(ssdata)                    
        else:
            break
    print "exit thread"
    nsock.close()
    connection.close()
    return 

def checkcache(remoteaddr,cturl,data):
    nsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    nsaddr = (remoteaddr,80)
    nsock.connect(nsaddr)
    nsock.settimeout(1.5)
    nsock.sendall(data)
    #print "receiving data from server"
    rawdata = ''
    #print "**********GlobRecStart***********"
    try:
        while True:
            ssdata = nsock.recv(65535)
            #print 'hehe'
            sslen = re.search(r'Content-Length:\s*([0-9]+)\s*\r\n',ssdata)
            etoken = re.search(r'Last-Modified:\s*([^\r]+)\s*\r\n',ssdata)
            if etoken:
                etoken=etoken.group(1)

            #print 'cnmb'
            #print sslen
            #print ssdata
            if sslen:
                sslen = int(sslen.group(1))
                rawdata = ssdata
                fg=True
                sslen -= len(ssdata[ssdata.find('\r\n\r\n')+4:])
                #print repr(ssdata)
                #print 'ssdata:'+ssdata
            else:                        
                if ssdata and len(ssdata):
                    #print repr(ssdata)
                    continue
                else:
                    break
            
            while sslen>0:
                ssdata = nsock.recv(65535)
                #print ssdata
                rawdata+=ssdata
                sslen-=len(ssdata)

                #print "----------receive------------"
                #print 'server:  '
                #print repr(ssdata)
                #print len(ssdata)
                #print 'ssdata:'+ssdata
                if ssdata and len(ssdata):
                    continue                    
                else:                
                    raise
            #print repr(rawdata)
            #print '1$$$$$$$$$$$$$$$$$$$$$'
            #print etoken
            #print cturl
            if etoken and cturl :
                #print '$$$$$$$$$$$$$$$$$$$$$'
                if cturl in cache and cache[cturl][1]!=etoken:
                    cache[cturl]=(rawdata,etoken)
                else:
                    if not (cturl in cache):
                        cache[cturl]=(rawdata,etoken)
            #if sslen!=0:
            #    print "buduibuduibuduibuduibuduibuduibuduibudui"
            #    print sslen
            #print "*****************************************"                    
            #print rawdata
            #print "#########################################"
    except:
        pass
    finally:
        nsock.close()
        return
blockedhostlist=set([])
blockeduserlist=set([])
spoofurllist=set(['www.qq.com'])
def c2sworker(connection):
    try:
        while True:
            data = connection.recv(65535)   
            if not (data and len(data)):
                break
            # print repr(data)
            #print "----------send------------"
            #print 'client:  '
            #print repr(data)
            ctoken = re.search(r'If-Modified-Since:\s*([^\r]+)\s*\r\n',data)
            cturl = re.search(r'GET\s+([^\s]+)\s+HTTP[^\r]*\r\n',data)
            if cturl:
                cturl = cturl.group(1)
            remoteaddr = re.search(r'Host:\s*([^\n\r]*)\s*[\r\n]+',data)
            cfg = False                
            ''' wrong!!!
            if ctoken:
                ctoken = ctoken.group(1)
                if ctoken in cache:
                    print 'Yay!'+ctoken
                    connection.sendall(cache[ctoken])
                    continue
            '''
            if remoteaddr:
                remoteaddr=remoteaddr.group(1)
                print remoteaddr
                if remoteaddr in blockedhostlist:
                    print remoteaddr + 'is blocked!'
                    break

            else:
                break   
            #print remoteaddr

            if cturl and ctoken == None: #at the same time resend packet to the server
                if cturl in cache:
                    print 
                    print 'Yay!'+cturl
                    print 'Cached'
                    print 
                    connection.sendall(cache[cturl][0])
                    cnm = data
                    data = cnm[0:cnm.find('\r\n\r\n')] +'\r\nIf-Modified-Since: ' + cache[cturl][1] +cnm[cnm.find('\r\n\r\n'):]
                    #print repr(data)
                    cfg=True         
                    t = threading.Thread(target=checkcache,args=(remoteaddr,cturl,data)) 
                    t.start() 
                    continue          
            elif ctoken:#return 304
                #print '#############################'
                print cturl
                print 'cached:',(cturl in cache)
                if cturl and (cturl in cache):
                    print "******************************"
                    tmpdata = 'HTTP/1.1 304 Not Modified\r\nDate: '+ cache[cturl][1]+  '\r\nServer: Apache\r\nConnection: Keep-Alive\r\nExpires: Sun, 11 May 2025 17:30:46 GMT\r\nCache-Control: max-age=315360000\r\n\r\n'
                    #print repr(tmpdata)
                    connection.sendall( tmpdata)                
                    cfg=True
                    t = threading.Thread(target=checkcache,args=(remoteaddr,cturl,data)) 
                    t.start()
                    continue
            if remoteaddr in spoofurllist:
                data.replace(remoteaddr,dspoofurl)
                remoteaddr=dspoofurl
            nsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
               
            nsaddr = (remoteaddr,80)
             
            nsock.connect(nsaddr)
            nsock.settimeout(1.5)
            nsock.sendall(data)
            #print "receiving data from server"
            rawdata = ''
            #print "**********GlobRecStart***********"
            try:
                while True:
                    ssdata = nsock.recv(65535)
                    #print 'hehe'
                    sslen = re.search(r'Content-Length:\s*([0-9]+)\s*\r\n',ssdata)
                    etoken = re.search(r'Last-Modified:\s*([^\r]+)\s*\r\n',ssdata)
                    if etoken:
                        etoken=etoken.group(1)

                    #print 'cnmb'
                    #print sslen
                    #print ssdata
                    if sslen:
                        sslen = int(sslen.group(1))
                        rawdata = ssdata
                        fg=True
                        sslen -= len(ssdata[ssdata.find('\r\n\r\n')+4:])
                        if not cfg:
                            connection.sendall(ssdata)
                        #print repr(ssdata)
                        #print 'ssdata:'+ssdata
                    else:                        
                        if ssdata and len(ssdata):
                            if not cfg:
                                connection.sendall(ssdata)
                            #print repr(ssdata)
                            continue
                        else:
                            break
                    
                    while sslen>0:
                        ssdata = nsock.recv(65535)
                        #print ssdata
                        rawdata+=ssdata
                        sslen-=len(ssdata)
                        """
                        sslen = re.search(r'Content-Length:\s*([0-9]+)\s*\r\n')
                        if sslen and len(sslen):
                            sslen = int(sslen.group(1))
                            rawdata = ssdata[ssdata.find('\r\n\r\n')+4:]
                            fg=True
                            sslen-=len(rawdata)
                        else:
                            pass
                        """

                        #print "----------receive------------"
                        #print 'server:  '
                        #print repr(ssdata)
                        #print len(ssdata)
                        #print 'ssdata:'+ssdata
                        if ssdata and len(ssdata):
                            if not cfg:
                                connection.sendall(ssdata)                    
                        else:                
                            raise
                    #print repr(rawdata)
                    #print '1$$$$$$$$$$$$$$$$$$$$$'
                    print etoken
                    print cturl
                    if etoken and cturl :
                        #print '$$$$$$$$$$$$$$$$$$$$$'
                        if cturl in cache and cache[cturl][1]!=etoken:
                            cache[cturl]=(rawdata,etoken)
                        else:
                            if not (cturl in cache):
                                cache[cturl]=(rawdata,etoken)
                    #if sslen!=0:
                    #    print "buduibuduibuduibuduibuduibuduibuduibudui"
                    #    print sslen
                    #print "*****************************************"                    
                    #print rawdata
                    #print "#########################################"
            except:
                pass
            finally:                
                nsock.close()
                #print rawdata
                #print "##############################################"
            #print "###########GlobRecEnd###############"
            #print "exit thread"
    except:
        pass
    finally:
        connection.close()  
        return 

    
     

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_address = ('localhost',16270)
#print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
sock.listen(100)
while True:
    #print  'waiting for a connection'
    connection , client_address =  sock.accept()
    if client_address[0] in blockeduserlist:
        connection.close()
        print client_address[0] + " is forbiddened!"
        continue
    connection.settimeout(1.5)
    print  'connection from',client_address
    #print "receiving data from client"
    t = threading.Thread(target=c2sworker,args=(connection,)) 
    #threads.append(t)
    t.start()

