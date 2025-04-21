"""Code for client side of Email assignment
Author: Taylor Hancock
Date:   04/19/2025
Class:  CEC460 - Telecom Systems
Assignment: EX05 - Cryptography
"""

import os

from cryptography.hazmat.primitives.asymmetric import ec
from dotenv import load_dotenv

from cryptography_tools import load_private_key, generate_salt, \
                            public_key_to_bytes, private_key_to_public_bytes, \
                            derive_fernet_from_shared_key, generate_signature

from email_handler import EmailHandler

load_dotenv()

CLIENT_PRIVATE_KEY = 'private.pem'

SERVER_PORT = 12460

RECV_SIZE = 1024


def run_connection(name: str, email_handler: EmailHandler, server_email: str) -> None:
    """Opens a connection to the given server"""
    # Generate SessionID (16 random characters and numbers), salt generator does the same
    session_id = generate_salt(16)

    # Get signing keys
    signing_private_key = load_private_key(CLIENT_PRIVATE_KEY)

    # Create Client Diffie-Hellman (DH) Key
    dh_client_private_key = ec.generate_private_key( ec.SECP384R1() )

    # Convert to public key for transmission
    dh_client_public_str = private_key_to_public_bytes(dh_client_private_key).decode('utf-8')

    # generate random salt
    salt = generate_salt()

    # Send Diffie-Hellman Public Key & Salt
    message_str = dh_client_public_str + "\n" + salt

    email_handler.send_email(
        server_email,
        f"Client Info: {session_id}",
        message_str
    )

    print('A')
    print(salt)

    # Recieve Server Diffie-Hellman Public Key
    server_data = email_handler.receive_email_continuous(f"Server Info: {session_id}")[-1]
    dh_server_public_bytes = server_data.encode('utf-8')
    fernet_key = derive_fernet_from_shared_key(dh_client_private_key, dh_server_public_bytes, salt)

    # Encrypt Name, Signature, & Key
    signature = generate_signature(signing_private_key, name)

    print('B')

    # convert signing key to bytes
    signing_public_bytes = public_key_to_bytes(signing_private_key.public_key())

    print('C')

    name_sig_key = name.encode('utf-8') + b"\n" + signature + b"\n" + signing_public_bytes

    fernet_token = fernet_key.encrypt(name_sig_key).decode('utf-8')

    print('D')

    # Send Symmetrically Encrypted Info
    email_handler.send_email(
        server_email,
        f"Encrypted Info: {session_id}",
        fernet_token
    )

    print('E')

    # Recieve Success/Failure
    validity = email_handler.receive_email_continuous(f"Verification Info: {session_id}")[-1]

    print(f"Validity: {bool(validity)}")


if __name__ == "__main__":
    # get all OS values
    client_email = os.environ["CLIENT_EMAIL"]
    server_email = os.environ["SERVER_EMAIL"]
    client_password = os.environ["CLIENT_PASSWORD"]

    email_handler = EmailHandler(client_email, client_password)

    run_connection("Taylor", email_handler, server_email)
