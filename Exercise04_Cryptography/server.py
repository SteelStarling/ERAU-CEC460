"""Code for server side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

import socket as sock
from base64 import urlsafe_b64decode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet  # symmetric key encryption

from cryptography_tools import derive_fernet_from_shared_key, private_key_to_public_bytes,\
                            public_str_to_public_key


TEST_SERVER = '127.0.0.1'
REAL_SERVER = '???'

SERVER_PORT = 12460

RECV_SIZE = 1024


def parse_encrypted_data(encrypted_data: str, fernet_key: Fernet) -> tuple[str, bytes, str]:
    """Parses symmetrically encrypted data and outputs it in valid format"""
    # decrypt data
    decrypted_bytes = fernet_key.decrypt(encrypted_data)

    # convert to string
    decrypted_str = decrypted_bytes.decode('utf-8')

    # splits first two items without affecting linebreaks in public key
    name, raw_signature, signing_public_str = decrypted_str.split('\n', 2)

    # decode signature block
    signature = urlsafe_b64decode(raw_signature)

    # combine and return
    return (name, signature, signing_public_str)


def run_connection(server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> tuple:
    """Starts a server with the given connection info"""
    # Open server socket
    server_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print("The server is ready to recieve")

    # accept sockets, but ignore address
    connection_socket, addr = server_socket.accept()

    # Recieve Client Diffie-Hellman Public Key & Salt (split by rightmost newline)
    dh_client_public_str, salt = connection_socket.recv(RECV_SIZE).decode('utf-8').rsplit('\n', 1)
    dh_client_public_key = public_str_to_public_key(dh_client_public_str)

    # Send Server Diffie-Hellman Public Key
    dh_server_private_key = ec.generate_private_key( ec.SECP384R1() )
    connection_socket.send(
        private_key_to_public_bytes(dh_server_private_key)
    )

    # Use Diffie-Hellman to create shared key
    fernet_key = derive_fernet_from_shared_key(
        dh_server_private_key,
        dh_client_public_str.encode('utf-8'),
        salt
    )

    # Recieve Symmetrically Encrypted Data (Name, Signature, Key)
    encrypted_output = connection_socket.recv(RECV_SIZE)

    # parse into segments
    name, signature, signing_public_str = parse_encrypted_data(encrypted_output, fernet_key)

    # print(f"Name: {name}, Signature: {signature}, Signing Key: {signing_public_str}")

    # Verify Info
    signing_public_key = public_str_to_public_key(signing_public_str)

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
