"""Code for server side of Cryptography assignment
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
    """Starts a server with the given connection info"""
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print("The server is ready to recieve")

    connection_socket, addr = server_socket.accept()
    while True:
        message = connection_socket.recv(1024)
        print(f'Skt: {connection_socket}, addr: {addr}, msg: {message}')
        reply = message.decode().upper().encode()
        connection_socket.send(reply)
        # connection_socket.close()


if __name__ == "__main__":
    run_connection()
