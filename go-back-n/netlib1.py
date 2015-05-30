import re

def getseq(data):
    retval = -2
    if data[0]=='a':
        retval = int(re.match(r'ack:([\-0-9]+)\r\n\r\n',data).group(1))
    elif data[0]=='s':
        retval = int(re.match(r'seq:([\-0-9]+)\r\n\r\n',data).group(1))
    return retval