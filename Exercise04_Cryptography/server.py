"""Code for server side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

import socket as sock
from base64 import urlsafe_b64decode, urlsafe_b64encode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
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

    # Recieve Client Diffie-Hellman Public Key & Salt (split by rightmost newline)
    dh_client_public_str, salt = connection_socket.recv(RECV_SIZE).decode('utf-8').rsplit('\n', 1)
    dh_client_public_bytes = dh_client_public_str.encode('utf-8')

    dh_client_public_key = serialization.load_pem_public_key(dh_client_public_bytes, None)

    # Send Server Diffie-Hellman Public Key
    dh_server_private_key = ec.generate_private_key( ec.SECP384R1() )
    dh_server_public_key = dh_server_private_key.public_key()
    dh_server_public_bytes = dh_server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    connection_socket.send(dh_server_public_bytes)

    # Use Diffie-Hellman to create shared key
    shared_key = dh_server_private_key.exchange(ec.ECDH(), dh_client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        info=b'handshake data'
    ).derive(shared_key)

    fixed_key = urlsafe_b64encode(derived_key)
    fernet_key = Fernet( fixed_key )

    # Recieve Symmetrically Encrypted Name (Name, Signature, Key)
    encrypted_output = connection_socket.recv(RECV_SIZE)
    decrypted_output = fernet_key.decrypt(encrypted_output).decode('utf-8')

    # splits first two items without affecting linebreaks in public key
    name, raw_signature, signing_public_str = decrypted_output.split('\n', 2)

    signature = urlsafe_b64decode(raw_signature)

    # print(f"Name: {name}, Signature: {signature}, Signing Key: {signing_public_str}")

    # Verify Info
    signing_public_key = serialization.load_pem_public_key(signing_public_str.encode('utf-8'))

    # Transmit success/failure
    try:
        signing_public_key.verify(signature, name.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        print("Signature Valid")
        connection_socket.send(b'\x01')
    except InvalidSignature as e:
        print(f"Invalid signature: {e}")
        connection_socket.send(b'\x00')

    return (name, addr)


if __name__ == "__main__":
    name_table = []

    while True:
        name, ip_info = run_connection()

        # add value to table
        name_table.append(f"{name} @ {ip_info[0]}")

        print("\nConnections:")
        for data in name_table:
            print(data)
        print("\n")
