"""
clint chat
"""

import socket
import threading
from rsa import RSA


class Client:
    """class for client"""
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        """takes server ip, port and username"""
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        """establishes connection"""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs
        self.encryption = RSA()
        self.private_key = self.encryption.secret_key
        clk1, clk2= self.encryption.share_public_key()

        # exchange public keys
        pk1 = int(self.s.recv(1024).decode())
        self.s.send(str(clk1).encode())

        pk2 = int(self.s.recv(1024).decode())
        self.s.send(str(clk2).encode())

        self.server_public_key = (pk1,pk2)
        # print(self.server_public_key)

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        """
        receives message
        """
        while True:
            msg_hash = self.s.recv(1024).decode()
            message = self.s.recv(1024).decode()
            # print(message)

            # decrypt message with the secrete key

            message = self.encryption.decode(message, self.encryption.secret_key)
            hash2 = self.encryption.eveluate_hash(message)
            # print(msg_hash)
            # print(hash2)
            if hash2 != msg_hash:
                print('Someone tried to modified a folowing message:')

            print(message)

    def write_handler(self):
        """sends message"""
        while True:
            message = input()

            # encrypt message with the secrete key
            msg_hash = self.encryption.eveluate_hash(message)

            message = self.encryption.encode(message, self.server_public_key)
            # print(message)
            self.s.send(msg_hash.encode())
            self.s.send(message.encode())

if __name__ == "__main__":
    nam = input('enter your username: ')
    cl = Client("192.168.178.60", 9001, nam)
    cl.init_connection()
