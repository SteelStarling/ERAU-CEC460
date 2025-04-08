"""Code for client side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

from socket import *

TEST_SERVER = '127.0.0.1'
REAL_SERVER = '???'

SERVER_PORT = 12460

def run_connection(server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> None:
    """Opens a connection to the given server"""
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    while True:
        message = input('Input lowercase sentence:').encode()
        client_socket.send(message)
        reply = client_socket.recv(1024)
        print('From Server: ', reply.decode())
        # client_socket.close()

if __name__ == "__main__":
    run_connection()
