"""Code for server side of Email assignment
Author: Taylor Hancock
Date:   04/19/2025
Class:  CEC460 - Telecom Systems
Assignment: EX05 - Email
"""

import os
from base64 import urlsafe_b64decode
from imaplib import IMAP4_SSL

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet  # symmetric key encryption
from dotenv import load_dotenv

from cryptography_tools import derive_fernet_from_shared_key, private_key_to_public_bytes,\
                            public_str_to_public_key

from email_handler import EmailHandler

load_dotenv()

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


def run_connection(email_handler: EmailHandler) -> tuple:
    """Starts a server with the given connection info"""
    # Listen for emails
    session_id, email, body = email_handler.receive_email_continuous("Client Info: ")

    # Recieve Client Diffie-Hellman Public Key & Salt (split by rightmost newline)
    dh_client_public_str, salt = body.rsplit('\n', 1)

    print(salt)

    # Send Server Diffie-Hellman Public Key
    dh_server_private_key = ec.generate_private_key( ec.SECP384R1() )
    email_handler.send_email(
        email,
        f"Server Info: {session_id}",
        private_key_to_public_bytes(dh_server_private_key).decode('utf-8')
    )

    # Use Diffie-Hellman to create shared key
    fernet_key = derive_fernet_from_shared_key(
        dh_server_private_key,
        dh_client_public_str.encode('utf-8'),
        salt
    )

    print('D')

    # Recieve Symmetrically Encrypted Data (Name, Signature, Key)
    encrypted_output = email_handler.receive_email_continuous(f"Encrypted Info: {session_id}")[-1]
    encrypted_bytes = encrypted_output.encode('utf-8')

    # parse into segments
    name, signature, signing_public_str = parse_encrypted_data(encrypted_bytes, fernet_key)

    print('E')

    # print(f"Name: {name}, Signature: {signature}, Signing Key: {signing_public_str}")

    # Verify Info
    signing_public_key = public_str_to_public_key(signing_public_str)

    print('F')

    # Transmit success/failure
    connection_validity = b'\x00'
    try:
        signing_public_key.verify(signature, name.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        print("Signature Valid")
        connection_validity = b'\x01'
    except InvalidSignature as e:
        print(f"Invalid signature: {e}")

    print('G')

    email_handler.send_email(
        email,
        f"Verification Info: {session_id}",
        connection_validity.decode('utf-8')
    )

    return (name, email)


if __name__ == "__main__":
    # get all OS values
    server_email = os.environ["SERVER_EMAIL"]
    server_password = os.environ["SERVER_PASSWORD"]

    email_handler = EmailHandler(server_email, server_password)

    name_table = []

    while True:
        name, email = run_connection(email_handler)

        # add value to table
        name_table.append(f"{name} @ {email}")

        print("\nConnections:")
        for data in name_table:
            print(data)
        print("\n")
