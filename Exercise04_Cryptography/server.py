"""Code for server side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

import socket as sock
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  # for loading keys
from cryptography.fernet import Fernet  # symmetric key encryption

TEST_SERVER = '127.0.0.1'
REAL_SERVER = '???'

SERVER_PORT = 12460

RECV_SIZE = 1024


def run_connection(server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> tuple:
    """Starts a server with the given connection info"""

    # Open server socket
    server_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print("The server is ready to recieve")

    # Test Code
    connection_socket, addr = server_socket.accept()
    # message = connection_socket.recv(1024)
    # print(f'Skt: {connection_socket}, addr: {addr}, msg: {message}')
    # reply = message.decode().upper().encode()
    # connection_socket.send(reply)

    # Recieve Client Diffie-Hellman Public Key & Salt
    dh_client_public_bytes, salt = connection_socket.recv(RECV_SIZE).splitlines()

    # Decode values before use
    dh_client_public_bytes = base64.urlsafe_b64decode(dh_client_public_bytes)
    salt = base64.urlsafe_b64decode(salt)

    dh_client_public_key = serialization.load_pem_public_key(dh_client_public_bytes, None)

    # Send Server Diffie-Hellman Public Key
    dh_server_private_key = ec.generate_private_key( ec.SECP384R1() )
    dh_server_public_key = dh_server_private_key.public_key()
    dh_server_public_bytes = dh_server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    connection_socket.send(base64.urlsafe_b64encode(dh_server_public_bytes))

    # Use Diffie-Hellman to create shared key
    shared_key = dh_server_private_key.exchange(ec.ECDH(), dh_client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data'
    ).derive(shared_key)

    fixed_key = base64.urlsafe_b64encode(derived_key)
    fernet_key = Fernet( fixed_key )

    # Recieve Symmetrically Encrypted Name (Name, Signature, Key)
    encrypted_output = connection_socket.recv(RECV_SIZE)
    name, signature, signing_key = base64.urlsafe_b64decode(fernet_key.decrypt(encrypted_output)).splitlines()

    name = name.decode('utf-8')
    signature = signature.decode('utf-8')
    signing_key = signing_key.decode('utf-8')

    print(f"Name: {name}, Signature: {signature}, Signing Key: {signing_key}")

    # Verify Info
    status = bytes(False)

    # Transmit Success/Failure
    connection_socket.send(fernet_key.encrypt(status))

    return (name, addr)


if __name__ == "__main__":
    name_table = []

    while True:
        name, ip_info = run_connection()

        # add value to table
        name_table += f"{name} @ {ip_info[0]}"

        for data in name_table:
            print(data)
