#!/usr/bin/python

import sys
import string
import socket
from time import sleep

data = string.digits + string.lowercase + string.uppercase

ip, port = sys.argv[1], int(sys.argv[2])

s = socket.socket()
s.connect((ip, port))

for i in range(10):
    s.send(data)
    print s.recv(1000)
    sleep(1)

s.close()
