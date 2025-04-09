"""Code for client side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

import base64
import os
import socket as sock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  # for loading keys
from cryptography.fernet import Fernet  # symmetric key encryption

TEST_SERVER = '127.0.0.1'
REAL_SERVER = '???'

CLIENT_PRIVATE_KEY = 'private.pem'

SERVER_PORT = 12460

RECV_SIZE = 1024


def run_connection(name: str, server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> None:
    """Opens a connection to the given server"""

    # Open client socket
    client_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Test Code
    # message = input('Input lowercase sentence:').encode()
    # client_socket.send(message)
    # reply = client_socket.recv(RECV_SIZE)
    # print('From Server: ', reply.decode())

    # Create Client Diffie-Hellman (DH) Keys
    dh_client_private_key = ec.generate_private_key( ec.SECP384R1() )
    dh_client_public_key = dh_client_private_key.public_key()

    # Convert public key for transmission
    dh_client_public_bytes = dh_client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    salt = base64.urlsafe_b64encode( os.urandom(24) )

    # Send Diffie-Hellman Public Key & Salt
    message = base64.urlsafe_b64encode(dh_client_public_bytes) + b"\n" + salt
    client_socket.send(message)

    # Recieve Server Diffie-Hellman Public Key
    dh_server_public_bytes = base64.urlsafe_b64decode(client_socket.recv(RECV_SIZE))
    dh_server_public_key = serialization.load_pem_public_key(dh_server_public_bytes, None)

    # Use Diffie-Hellman to create shared key
    shared_key = dh_client_private_key.exchange(ec.ECDH(), dh_server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    fixed_key = base64.urlsafe_b64encode(derived_key)
    fernet_key = Fernet( fixed_key )

    # Encrypt Name, Signature, & Key
    signature = b"potato"
    signing_key = b"apple"

    name_sig_key = base64.urlsafe_b64encode(name.encode('utf-8')) \
                    + b"\n" \
                    + base64.urlsafe_b64encode(signature) \
                    + b"\n" \
                    + base64.urlsafe_b64encode(signing_key)

    fernet_token = fernet_key.encrypt(name_sig_key)

    # Send Symmetrically Encrypted Info
    client_socket.send(fernet_token)

    # Recieve Success/Failure
    validity = client_socket.recv(RECV_SIZE)

    validity = fernet_key.decrypt(validity)

    print(f"Validity: {bool(validity)}")


if __name__ == "__main__":
    run_connection("Tay :3")
