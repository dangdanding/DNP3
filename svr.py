#!/usr/bin/python
from socket import *
from time import time
from binascii import hexlify, unhexlify
from datetime import datetime,timedelta

HOST = ""
PORT = 20000
BUFSIZ = 1024
ADDR = (HOST, PORT)
 
ResponseLinkStatus="0564000b040003000000"
dnp3_list=[
           "056405c001000004e921",  #dnp3_HealthCheck
           "056408c40a000100fc42c0c00e7edc", #dnp3_WarmRestart
           "056408c40a000100fc42c0c00d9c86", #dnp3_ColdRestart
           "056412c403000400152dc1c10232010701fa7d0b460d01c863", #dnp3_Write
           "056408c401000200390ddece0f32e7", #dnp3_InitData
           "056408c401000200390ddece12f645", #dnp3_AppTermination
           "056408c401000200390ddece1b218c", #dnp3_DeleteFile
           "056405c903000400bd71"            #dnp3_ReadRequest
    ]


dnp3_resp=[
    "", #dnp3_healthcheck
    "05640a4401000a006e25c1c0810001c4fd", #dnp3_WarmRestart
    "05640a4401000a006e25c0c0810001c2de", #dnp3_ColdRestart
    "056405c903000400bd71", #dnp3_Write
    "056408c401000200390ddece0f32e7", #dnp3_InitData
    "056408c401000200390ddece12f645", #dnp3_AppTermination
    "056408c401000200390ddece1b218c", #dnp3_DeleteFile
    "056405c903000400bd71"            #dnp3_ReadRequest
]


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

            print("Received DNP3 packet from %s: %s" % (addr[0], hexlify(rcv_msg)))

            for idx in range (0, (len(dnp3_list))):
                if hexlify(rcv_msg) == dnp3_list[idx - 1]:
                    tcpCliSock.sendall(unhexlify(dnp3_resp[idx-1]))
                    print ("Sending DNP3 Response to %s: %s" %(addr[0],dnp3_resp[idx -1]))
 
        tcpCliSock.close()

if __name__ == "__main__":

    main() 
