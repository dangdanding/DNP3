#!/usr/bin/python
import getopt,sys,optparse
from socket import *

HOST = "127.0.0.1"
PORT = 20000
BUFSIZ = 1024

DEBUG=1

def usage():
    print(u"""
    -h / --help :help
    -i / --ip :ip address
    -p / --prot :destination port
    """)
def debug():
    if DEBUG == 1:
        print ("debug: goes here...")

def main(argv):
    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:i:",["help","ip=","port="])

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

    debug()
 
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
        print  ("connect to target %s: %s error: %s" % (HOST, PORT, e))
 
    while True:
        data = input("> ")
        if not data:
            break
 
        tcpCliSock.send(data.encode("utf8"))
        data = tcpCliSock.recv(BUFSIZ)
        if not data:
            break
        print(data.decode("utf-8"))
 
    tcpCliSock.close()

if __name__ == "__main__":

    if len(sys.argv) <= 1:  
         usage()
         sys.exit(1)

    main(sys.argv[1:])
