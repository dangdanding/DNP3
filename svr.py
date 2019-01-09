#!/usr/bin/python
from socket import *
from time import time
from binascii import hexlify, unhexlify
from datetime import datetime,timedelta

HOST = ""
PORT = 20000
BUFSIZ = 1024
ADDR = (HOST, PORT)
 
ReadRequest="056405c903000400bd71"
ResponseLinkStatus="0564000b040003000000"

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
 
        while True:
            rcv_msg = tcpCliSock.recv(BUFSIZ)
            if not rcv_msg:
                break
            print("Received Link Status Request from %s: %s" % (addr[0], hexlify(rcv_msg)))
            if hexlify(rcv_msg) == ReadRequest:
                print ("Sending Link Status Response to %s: %s" %(addr[0],ResponseLinkStatus))
                tcpCliSock.sendall(unhexlify(ResponseLinkStatus))
 
        tcpCliSock.close()

if __name__ == "__main__":

    main() 
