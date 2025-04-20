"""Code for client side of Email assignment
Author: Taylor Hancock
Date:   04/19/2025
Class:  CEC460 - Telecom Systems
Assignment: EX05 - Cryptography
"""

import socket as sock

from cryptography.hazmat.primitives.asymmetric import ec

from cryptography_tools import load_private_key, generate_salt, public_key_to_bytes, \
                            private_key_to_public_bytes, derive_fernet_from_shared_key,\
                            generate_signature


TEST_SERVER = '127.0.0.1'
REAL_SERVER = '172.30.115.175'

CLIENT_PRIVATE_KEY = 'private.pem'

SERVER_PORT = 12460

RECV_SIZE = 1024


def run_connection(name: str, server_ip: str = TEST_SERVER, server_port: int = SERVER_PORT) -> None:
    """Opens a connection to the given server"""

    # Open client socket
    client_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Get signing keys
    signing_private_key = load_private_key(CLIENT_PRIVATE_KEY)

    # Create Client Diffie-Hellman (DH) Key
    dh_client_private_key = ec.generate_private_key( ec.SECP384R1() )

    # Convert to public key for transmission
    dh_client_public_str = private_key_to_public_bytes(dh_client_private_key).decode('utf-8')

    # generate random salt
    salt = generate_salt()

    # Send Diffie-Hellman Public Key & Salt
    message = dh_client_public_str + "\n" + salt
    client_socket.send(message.encode('utf-8'))

    # Recieve Server Diffie-Hellman Public Key
    dh_server_public_bytes = client_socket.recv(RECV_SIZE)
    fernet_key = derive_fernet_from_shared_key(dh_client_private_key, dh_server_public_bytes, salt)

    # Encrypt Name, Signature, & Key
    signature = generate_signature(signing_private_key, name)

    # convert signing key to bytes
    signing_public_bytes = public_key_to_bytes(signing_private_key.public_key())

    name_sig_key = name.encode('utf-8') + b"\n" + signature + b"\n" + signing_public_bytes

    fernet_token = fernet_key.encrypt(name_sig_key)

    # Send Symmetrically Encrypted Info
    client_socket.send(fernet_token)

    # Recieve Success/Failure
    validity = client_socket.recv(RECV_SIZE)

    print(f"Validity: {bool(validity)}")


if __name__ == "__main__":
    run_connection("Taylor")
