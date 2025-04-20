"""Code for client side of Cryptography assignment
Author: Taylor Hancock
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom
import socket as sock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet  # symmetric key encryption

from cryptography_tools import load_private_key


TEST_SERVER = '127.0.0.1'
REAL_SERVER = '172.30.115.175'

CLIENT_PRIVATE_KEY = 'private.pem'

SERVER_PORT = 12460

RECV_SIZE = 1024

def generate_salt() -> str:
    """Generates and returns random salt for use"""
    return urlsafe_b64encode(urandom(24)).decode('utf-8')


def public_key_to_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Converts a public key to bytes, per assignment specification"""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes


def derive_key_from_shared_key(client_private_key: ec.EllipticCurvePrivateKey, \
                               server_public_key_bytes: bytes, salt: str = None) -> bytes:
    """Converts a pair of keys and salt to a Diffie-Hellman-derived shared key"""
    # convert bytes to actual key
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes, None)

    # Use Diffie-Hellman to create shared key
    shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        info=b'handshake data'
    ).derive(shared_key)

    return derived_key


def generate_signature(signing_private_key: ec.EllipticCurvePrivateKey, message: str) -> bytes:
    """Generates a signature based on a private key and message to sign"""
    signature = urlsafe_b64encode(
        signing_private_key.sign(
            name.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
    )

    return signature



def run_connection(name: str, server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> None:
    """Opens a connection to the given server"""

    # Open client socket
    client_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Get signing keys
    signing_private_key = load_private_key(CLIENT_PRIVATE_KEY)
    signing_public_key = signing_private_key.public_key()

    # Create Client Diffie-Hellman (DH) Keys
    dh_client_private_key = ec.generate_private_key( ec.SECP384R1() )
    dh_client_public_key = dh_client_private_key.public_key()

    # Convert public key for transmission
    dh_client_public_str = public_key_to_bytes(dh_client_public_key).decode('utf-8')

    # generate random salt
    salt = generate_salt()

    # Send Diffie-Hellman Public Key & Salt
    message = dh_client_public_str + "\n" + salt
    client_socket.send(message.encode('utf-8'))

    # Recieve Server Diffie-Hellman Public Key
    dh_server_public_bytes = client_socket.recv(RECV_SIZE)
    derived_key = derive_key_from_shared_key(dh_client_private_key, dh_server_public_bytes, salt)

    fixed_key = urlsafe_b64encode(derived_key)
    fernet_key = Fernet( fixed_key )

    # Encrypt Name, Signature, & Key
    signature = generate_signature(signing_private_key, name)

    signing_public_bytes = public_key_to_bytes(signing_public_key)

    name_sig_key = name.encode('utf-8') + b"\n" + signature + b"\n" + signing_public_bytes

    fernet_token = fernet_key.encrypt(name_sig_key)

    # Send Symmetrically Encrypted Info
    client_socket.send(fernet_token)

    # Recieve Success/Failure
    validity = client_socket.recv(RECV_SIZE)

    print(f"Validity: {bool(validity)}")


if __name__ == "__main__":
    run_connection("Taylor", REAL_SERVER)
