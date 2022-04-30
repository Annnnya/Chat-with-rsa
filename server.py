"""
server module
"""

# from http import client
import socket
import threading
from rsa import RSA


class Server:
    """chat server class"""

    def __init__(self, port: int) -> None:
        """crates all values"""
        self.host = "127.0.0.1"
        self.port = port
        self.clients = []
        self.client_keys = {}
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.encryption = RSA()
        self.private_key = self.encryption.secret_key

    def start(self):
        """starts server"""
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client

            my_pubkey1, my_pubkey2 = self.encryption.share_public_key()
            my_pubkey1 = str(my_pubkey1)
            my_pubkey2 = str(my_pubkey2)

            c.send(my_pubkey1.encode())
            pk1 = int(c.recv(1024).decode())
            c.send(my_pubkey2.encode())
            pk2 = int(c.recv(1024).decode())

            # encrypt the secret with the clients public key
            client_public_key = (pk1, pk2)
            self.client_keys[c] = client_public_key
            # print(client_public_key)

            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        """sends message to everyone in the chat"""
        for client in self.clients:

            # encrypt the message

            msg_hash = self.encryption.eveluate_hash(msg)

            msg = self.encryption.encode(msg, self.client_keys[client])

            client.send(msg_hash.encode())
            client.send(msg.encode())

    def handle_client(self, c: socket, addr):
        """receives client messages and sens them"""
        while True:
            msg_hash = c.recv(1024).decode()
            msg = c.recv(1024).decode()
            # print(msg)
            message = self.encryption.decode(msg, self.private_key)

            hash2 = self.encryption.eveluate_hash(message)

            # print(msg_hash)
            # print(hash2)

            if hash2 !=msg_hash:
                print('! Modified message received. Sending refused.')
            else:

                print('[', self.username_lookup[c], ']', message)

                for client in self.clients:
                    if client != c:
                        msg = self.encryption.encode(message, self.client_keys[client])
                        # print(msg)
                        client.send(hash2.encode())
                        client.send(msg.encode())

if __name__ == "__main__":
    s = Server(9001)
    s.start()
