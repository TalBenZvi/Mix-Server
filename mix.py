# Tal Ben-zvi, 213420003

import sys
import threading
import socket
import time
import random
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# requests to be sent
pendingRequests = []
requestLock = threading.Lock()

def asymmetricDecrypt(secretKey, cipherBytes):
    plainBytes = secretKey.decrypt(
        cipherBytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plainBytes

# receives 4 ip bytes and returns ip string 'xxx.xxx.xxx.xxx'
def decodeIP(ipBytes):
    ipText = ""
    for byte in ipBytes:
        ipText += str(int.from_bytes([byte], 'big')) + "."
    return ipText[:-1]

# receives 2 port bytes and returns port number
def decodePort(portBytes):
    return int.from_bytes(portBytes, 'big')

class Request:
    def __init__(self, ip, port, l):
        self.ip = ip
        self.port = port
        self.l = l

def lookForRequests(pendingRequests):
    secretKey = load_pem_private_key(open("sk" + sys.argv[1] + ".pem", "r").read().encode('utf-8'), password=None)
    socketIn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(open("ips.txt", "r").readlines()[int(sys.argv[1]) - 1].split(" ")[1])
    socketIn.bind(('', port))
    socketIn.listen()
    while True:
        conn, addr = socketIn.accept()
        data = conn.recv(8192)
        conn.close()
        plainBytes = asymmetricDecrypt(secretKey, data)
        targetIP = decodeIP(plainBytes[:4])
        targetPort = decodePort(plainBytes[4:6])
        msg = plainBytes[6:]
        request = Request(targetIP, targetPort, msg)
        requestLock.acquire()
        pendingRequests.append(request)
        requestLock.release()

# send the pending requests every 60 seconds
def sendRequests(pendingRequests):
    while True:
        time.sleep(5)
        requestLock.acquire()
        outgoingRequests = pendingRequests.copy()
        pendingRequests.clear()
        requestLock.release()
        random.shuffle(outgoingRequests)
        for request in outgoingRequests:
            socketOut = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketOut.connect((request.ip, request.port))
            socketOut.sendall(request.l)
            socketOut.close()

inThread = threading.Thread(target=lookForRequests, args=(pendingRequests,))
outThread = threading.Thread(target=sendRequests, args=(pendingRequests,))
inThread.start()
outThread.start()