import socket

BUFFER_SIZE = 2048


class Client:
    def __init__(self, ip, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((ip, port))
        print('[*] Connected successfully to the server')

    def close(self):
        print('[*] Closing connection to the server...')
        self.client_socket.close()

    def send(self, message):
        self.client_socket.sendall(message.encode())

    def receive(self, raw_response=False):
        chunk = self.client_socket.recv(BUFFER_SIZE)
        data = chunk
        while len(chunk) == BUFFER_SIZE:
            chunk = self.client_socket.recv(BUFFER_SIZE)
            data += chunk
        return data.decode() if not raw_response else data


class Server:
    def __init__(self, ip, port):
        self.server_socket = socket.socket()
        self.server_socket.bind((ip, port))
        self.server_socket.listen(1)
        print('[*] Waiting for connections...')
        (self.client_socket, self.client_address) = self.server_socket.accept()
        print('[*] Established connection...')

    def close(self):
        print('[*] Closing server...')
        self.server_socket.close()

    def send(self, message):
        self.client_socket.sendall(message.encode())

    def receive(self):
        chunk = self.client_socket.recv(BUFFER_SIZE)
        data = chunk
        while len(chunk) == BUFFER_SIZE:
            chunk = self.client_socket.recv(BUFFER_SIZE)
            data += chunk
        return data.decode()
