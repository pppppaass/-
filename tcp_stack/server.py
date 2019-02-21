#!/usr/bin/python

import sys
import string
import socket
from time import sleep

data = string.digits + string.lowercase + string.uppercase

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

port = int(sys.argv[1])

s.bind(('0.0.0.0', port))
s.listen(3)

cs, addr = s.accept()
print addr

while True:
    data = cs.recv(1000)
    if data:
        data = 'server echoes: ' + data
        cs.send(data)
    else:
        break

s.close()
