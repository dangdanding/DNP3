#!/usr/bin/python
# -*- coding: UTF-8 -*-
import getopt,sys,optparse
from socket import *
from binascii import hexlify, unhexlify
import time

DEBUG = 1


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
MODBUS_type = 8  #default to Request Link Status, if not specify MODBUS packet attack type [1..8]
COUNT=1


def usage():
    print(sys.argv[0])
    print(u"""
    -h / --help :help
    -i / --ip :ip address
    -p / --prot :destination port
    -t / --type: MODBUS PDU tye
    -c / --count: how many packets to send in a session 
                  if count > 1, -t / --type would be invalid

    """)
    print_attack_type()


def print_attack_type():
    print(u"""
Defined MODBUS attack type:
'1: Read Decrete Inputs'
'2: Read Input Registers
    """)


def debug(msg):
    if DEBUG == 1:
        print ("debug: %s" % msg)


def send_modbus_packet(socket, modbus_type = 0, tm = 10):
    global  HOST,BUFSIZ,PORT,MODBUS_type,COUNT,modbus_list
 
    print  ("Sending MODBUS packet %s to target %s: %s"%(modbus_type, HOST, modbus_list[(modbus_type)]))
    socket.sendall(unhexlify(modbus_list[(modbus_type)]))

    #get response
    resp = socket.recv(BUFSIZ)
    print("Received MODBUS Response from %s: %s" % (HOST, resp.encode('hex')))

    time.sleep(tm)
    #str1 = raw_input('any key to continue> ')
 

def debug(msg):
    if DEBUG == 1:
        print ("debug: %s" % msg)

def main(argv):
    global  HOST,BUFSIZ,PORT,MODBUS_type,COUNT,modbus_list

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
                 MODBUS_type= int(arg)
             except: 
                 print ("MODBUS type %s is NOT recogizable!" % arg)
                 sys.exit(1)
             if (MODBUS_type > len(modbus_list)):
                     print ("MODBUS type %s is out of range [1-%s]!" % (arg, len(modbus_list)))
                     sys.exit(1)
           
                

    print  ("MODBUS injected type: %s"% MODBUS_type)
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
        send_modbus_packet(tcpCliSock, MODBUS_type)
    elif ( COUNT <= 0 ):
        print  ("count %s invalid, should be >=1" % e)
        sys.exit(1)
    else:
        print ("list length: %s" % len(modbus_list))
        cnt=0
        while (cnt < COUNT):
            for idx in range (0, (len(modbus_list)) ):
                print ("list idx: %s" % (idx))
                send_modbus_packet(tcpCliSock, idx)
                cnt += 1
                print ("iteration cnt: %s" % (cnt + 1))
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
