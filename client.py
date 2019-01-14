#!/usr/bin/python
# -*- coding: UTF-8 -*-
import getopt,sys,optparse
from socket import *
from binascii import hexlify, unhexlify

DEBUG = 1

ReadRequest = "056405c903000400bd71"
LinkReset = ""

dnp3_HealthCheck="\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21" 
dnp3_WarmRestart="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0e\x6c\xd1" 
dnp3_ColdRestart="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0d\x8E\x8B" 
dnp3_Write="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x02\x9d\xf7" 
dnp3_InitData="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0f\x32\xe7" 
dnp3_AppTermination="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x12\xf6\x45" 
dnp3_DeleteFile="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x1b\x21\x8c" 
dnp3_ReadRequest="056405c903000400bd71"

HOST = "127.0.0.1"
PORT = 20000
BUFSIZ = 1024
TYPE = dnp3_ReadRequest

def usage():
    print(sys.argv[0])
    print(u"""
    -h / --help :help
    -i / --ip :ip address
    -p / --prot :destination port
    -t / --type: DNP3 PDU tye

Defined DNP3 packet for parmater -t / --type:
'1: Health check'
'2: Warm Restart'
'3: Cold Restart'
'3: Cold Restart'
'4: Write'
'5: Initialize data'
'6: App function termination'
'7: Delete file'
'8: Request Link'

    """)

def debug():
    if DEBUG == 1:
        print ("debug: goes here...")

def main(argv):
    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:i:t:",["help","ip=","port=","type"])

    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for opt, arg in opts:
          if opt in ('-h', "--help"):
             usage()
             sys.exit(1)
          elif opt in ("-i", "--ip"):
             HOST= arg
             print  ("target HOST IP: %s"% HOST)
          elif opt in ("-p", "--port"):
             PORT= arg
             print  ("Destination PORT: %s"% PORT)
          elif opt in ("-t", "--type"):
             TYPE= arg
             print  ("DNP3 type: %s"% TYPE)


    #debug()
 
    try:
        tcpCliSock = socket(AF_INET, SOCK_STREAM)
    except error, e:
        print  ("create socket failed %s" % e)
        sys.exit(1)
    try:
        tcpCliSock.connect((HOST, int(PORT)))
    except gaierror, e:
        print  ("HOST IP address error: %s" % e)
        sys.exit(1)
    except error, e:
        print  ("Connect to target %s: %s error: %s" % (HOST, PORT, e))
 
    #sending request
    print  ("Sending Link Status Request to Source %s: %s"%(HOST, ReadRequest))
    tcpCliSock.sendall(unhexlify(ReadRequest))

    #get response
    resp = tcpCliSock.recv(BUFSIZ)
    print("Received Link Status Response from %s: %s" % (HOST, resp.encode('hex')))
 
    str1 = raw_input('> ')
    tcpCliSock.close()

if __name__ == "__main__":

    if len(sys.argv) <= 1:  
         usage()
         sys.exit(1)

    main(sys.argv[1:])
