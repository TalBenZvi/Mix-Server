# Tal Ben-zvi, 213420003

import sys
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives import hashes
from datetime import datetime

def symmetricDecrypt(key, cipherBytes):
    return Fernet(key).decrypt(cipherBytes)

# create key from password and salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=sys.argv[2].encode('utf-8'),
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(sys.argv[1].encode('utf-8')))
socketIn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socketIn.bind(('', int(sys.argv[3])))
socketIn.listen()
while True:
    conn, addr = socketIn.accept()
    data = conn.recv(8192)
    conn.close()
    msg = symmetricDecrypt(key, data)
    print(msg.decode('utf-8') + " " + datetime.now().strftime("%H:%M:%S"))
