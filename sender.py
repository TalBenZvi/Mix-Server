# Tal Ben-zvi, 213420003

import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
import socket

def symmetricEncrypt(key, bytes):
    return Fernet(key).encrypt(bytes)

def asymmetricEncrypt(publicKey, bytes):
    cipherBytes = publicKey.encrypt(
        bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipherBytes

# receives an ip string 'xxx.xxx.xxx.xxx' and returns its 4 byte encoding
def encodeIP(ipText):
    code = b""
    ipValues = ipText.split(".")
    for value in ipValues:
        code += bytes([int(value)])
    return code

# receives a port number and returns its 4 byte encoding
def encodePort(port):
    return port.to_bytes(2, 'big')

class Request:
    def __init__(self, ip, port, l):
        self.ip = ip
        self.port = port
        self.l = l

ips = {}
ports = {}
publicKeys = {}
index = 1
for line in open("ips.txt", "r").readlines():
    ipAndPort = line.split(" ")
    ips[index] = ipAndPort[0]
    ports[index] = int(ipAndPort[1])
    index += 1

lastRound = -1
# messageSchedule[i] is a list of requests to be sent in round i
messageSchedule = {}

for line in open("messages" + sys.argv[1] + ".txt", "r").readlines():
    # parse arguments
    args = line.split(" ")
    message = args[0]
    path = args[1]
    round = int(args[2])
    password = args[3]
    salt = args[4]
    destIP = args[5]
    destPort = int(args[6])
    # create key from password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    cipherText = symmetricEncrypt(key, message.encode('utf-8'))
    msg = encodeIP(destIP) + encodePort(destPort) + cipherText
    mixes = path.split(",")
    mixes.reverse()
    firstIndex = int(mixes[0])
    if firstIndex not in publicKeys:
        publicKeys[firstIndex] = load_pem_public_key(open("pk" + str(firstIndex) + ".pem", "r").read().encode('utf-8'))
    # wrap message in encodings for the mixes
    l = asymmetricEncrypt(publicKeys[firstIndex], msg)
    for i in range(len(mixes) - 1):
        index = int(mixes[i])
        nextIndex = int(mixes[i + 1])
        if nextIndex not in publicKeys:
            publicKeys[nextIndex] = load_pem_public_key(open("pk" + str(nextIndex) + ".pem", "r").read().encode('utf-8'))
        l = asymmetricEncrypt(publicKeys[nextIndex], encodeIP(ips[index]) + encodePort(ports[index]) + l)
    if round not in messageSchedule:
        messageSchedule[round] = []
        if round > lastRound:
            lastRound = round
    lastIndex = int(mixes[len(mixes) - 1])
    messageSchedule[round].append(Request(ips[lastIndex], ports[lastIndex], l))

# delay the requests to make sure they are received on the right round
time.sleep(2)
for i in range(lastRound + 1):
    if i in messageSchedule:
        for request in messageSchedule[i]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((request.ip, request.port))
            s.sendall(request.l)
            s.close()
    if i != lastRound:
        time.sleep(5)