#!/usr/bin/python
# -*- coding: UTF-8 -*-
from socket import *
from time import time
from binascii import hexlify, unhexlify
from datetime import datetime,timedelta
import getopt,sys,optparse

HOST = ""
BUFSIZ = 1024
PORT = 20000
 
rcv_list=[
           "0001000000060a0100000001",  #1 modbus read coils
           "0001000000060a0300050002",  #2 modbus read holding reg
           "0001000000060a0500020000",  #4 modbus write signle coil
           "000100000006ff020063001e",  #5 modbus Read discrete Inputs
           "297500000006ff0400300028",  #6 modbus read input registers
           "485a00000008ff0f000700030100", #7 modbus write multiple coils
           "0001000000060a0100000001",  #3 modbus read coils
           "056411c40a0001000615c0c0143c02063c03063c04067896",  #dnp3_Enable spontaneous message
           "056408c40a000100fc42c0c00e7edc", #dnp3_WarmRestart
           "056408c40a000100fc42c0c00d9c86", #dnp3_ColdRestart
           "056412c403000400152dc1c10232010701fa7d0b460d01c863", #dnp3_Write
           "056408c401000200390ddece0f32e7", #dnp3_InitData
           "056408c401000200390ddece12f645", #dnp3_AppTermination
           "056408c401000200390ddece1b218c", #dnp3_DeleteFile
           "056414c40a0001008fedc0c0013c02063c03063c04063c01068a51"            #dnp3_Read
 
    ]

send_resp=[
    "0001000000040a010100", #1 response to read coils
    "0001000000070a030400090018", #2 response to  read holding reg
    "0001000000060a0500020000", #4 response to write single coils
    "000000000007ff040400000000000100000007ff0204bd4f6739", #5 response to Read discrete Inputs
    "297500000053ff0450303030303030303030303030303333333730000000000000000000000000000058303030303632353633353800000000000000000000000000000000000000000fe80000000600000000000000000000", #6 response to read input registers
    "297a00000008ff0f000500010100", #7 response to write multiple coils
    "0001000000040a010100", #3 response to read coils
    "05640a4401000a006e25d2c08100000204", #dnp3_Enable spontaneous message response
    "05640a4401000a006e25c1c0810001c4fd", #dnp3_WarmRestart
    "05640a4401000a006e25c0c0810001c2de", #dnp3_ColdRestart
    "056405c903000400bd71", #dnp3_Write
    "056408c401000200390ddece0f32e7", #dnp3_InitData
    "056408c401000200390ddece12f645", #dnp3_AppTermination
    "056408c401000200390ddece1b218c", #dnp3_DeleteFile
    "005056c00008000c29243a0a08004500004b3449400040060c90c0a83c82c0a83c014e20c5a2244febad0084555c501800e5a90f000005641a4401000a00af5d9402000000000200000000020000000066420200000000f3b9"            #dnp3_Read Response
]


def debug():
    if DEBUG == 1:
        print ("debug: goes here...")

def usage():
    print(sys.argv[0])
    print(u"""
    -h / --help :help
    -p / --prot :destination port

    """)
 
def send_response(tcpCliSock, addr, port, rcv, rcv_msg):
    #only modbus default port 502 will send response back, DNP3 doesn't
    if  ( port == 502):
            matched = False
            for idx in range (0, (len(rcv))):
                print ("lookup response idx: %s" % idx)
                if hexlify(rcv_msg) == rcv[idx]:
                    matched = True
                    tcpCliSock.sendall(unhexlify(send_resp[idx]))
                    print ("Sending attack response to %s: %s" %(addr[0],send_resp[idx]))
                    break

            if (matched == False):
                 tcpCliSock.sendall(unhexlify(def_resp))
    #DNP3 simulator doesn't reply to client side
    elif  ( port == 20000):
            print ("PORT: %s NOT send attack response to %s" %(port, addr[0]) )

def main(argv):
    global  HOST,BUFSIZ,PORT,send_resp, rcv_list

    def_resp = "297500000053ff0450303030303030303030303030303333333730000000000000000000000000000058303030303632353633353800000000000000000000000000000000000000000fe80000000600000000000000000000"; #6 response to read input registers

    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:",["help","port="])

    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for opt, arg in opts:
          if opt in ('-h', "--help"):
             usage()
             sys.exit(1)
          elif opt in ("-p", "--port"):
             PORT= int(arg)
             print  ("Listen on PORT: %s"% PORT)
          else:
             usage()
             sys.exit(1)
 

    try:
        tcpSerSock = socket(AF_INET, SOCK_STREAM)
        tcpSerSock.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1) 
    except error, e:
        print  ("create socket failed %s" % e)
        sys.exit(1)

    ADDR = (HOST, PORT)
    tcpSerSock.bind(ADDR)
    tcpSerSock.listen(5)
 
    while True:
        #print("waiting for connection...")
        tcpCliSock, addr = tcpSerSock.accept()
 
        while True:
            rcv_msg = tcpCliSock.recv(BUFSIZ)
            if not rcv_msg:
                break

            print("Received attack packet from %s: %s" % (addr[0], hexlify(rcv_msg)))
            #str1 = raw_input('any key to continue> ')

            send_response(tcpCliSock, addr, PORT, rcv_list, hexlify(rcv_msg) )

 
        tcpCliSock.close()

if __name__ == "__main__":

    main(sys.argv[1:])
