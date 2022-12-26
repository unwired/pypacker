# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
from pypacker import psocket

FILE_CERT = "/home/mike/folder/tmp/cert.pem"
FILE_KEY = "/home/mike/folder/tmp/key.pem"
FILE_KEY_PW = "1234"

serversock_ssl = psocket.get_ssl_serversocket(FILE_CERT, FILE_KEY, ("127.0.0.1", 443), password_privkey=FILE_KEY_PW)
print("Listening...")
clientsock_ssl, addr = serversock_ssl.accept()

while True:
	print(clientsock_ssl)
	data = clientsock_ssl.recv()
	print(data)
	clientsock_ssl.send(data)
