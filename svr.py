#!/usr/bin/python
from socket import *
from time import ctime
from binascii import hexlify, unhexlify
HOST = ""
PORT = 20000
BUFSIZ = 1024
ADDR = (HOST, PORT)
 
ReadRequest="056405c903000400bd71"

def debug():
    if DEBUG == 1:
        print ("debug: goes here...")

def main():
    try:
        tcpSerSock = socket(AF_INET, SOCK_STREAM)
    except error, e:
        print  ("create socket failed %s" % e)
        sys.exit(1)

    tcpSerSock.bind(ADDR)
    tcpSerSock.listen(5)
 
    while True:
        #print("waiting for connection...")
        tcpCliSock, addr = tcpSerSock.accept()
        #print("connected from :", addr)
 
        while True:
            data = tcpCliSock.recv(BUFSIZ)
            if not data:
                break
            content = '[%s] %s' % (bytes(ctime()), data)
            rcv_msg = hexlify(data)
            print("Received PDU from %s: %s" % (addr[0], rcv_msg))
 
        tcpCliSock.close()

if __name__ == "__main__":

    main() 
