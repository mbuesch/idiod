#!/usr/bin/python3

import socket

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/idiod/idiod.sock")
sock.sendall(b"idiod v1; test; 1.2.3.4; 1000; /path")
