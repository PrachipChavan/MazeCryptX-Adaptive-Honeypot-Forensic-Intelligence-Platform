import os
import socket

print("Hello from malware")
os.system("echo hacked")
s = socket.socket()
print("Socket created")