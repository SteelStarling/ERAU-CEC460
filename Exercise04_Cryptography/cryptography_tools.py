"""Helper functions for cryptography, based on those provided by Dr. McNeill
Author: Taylor Hancock, based on code from Dr. McNeill
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

from os import path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet  # symmetric key encryption


KEY_LOCATION = "private_key.pem"

def load_private_key(key_path: str = KEY_LOCATION) -> any:
    """Loads private key from the path or creates a new key if one is not provided"""

    if path.exists(key_path):
        print(f"File '{key_path}' exists.")

        # load signing private key from disk
        try:
            with open(key_path, "rb") as key_file:
                signing_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            print("Successfully loaded signing key")

        except FileNotFoundError:
            print(f"Error: File not found at {key_path}")

        except Exception as e:
            print(f"An error occurred loading the signing key: {e}")

    # if key doesn't exist, make a new one
    else:
        # create new signing key and save to disk
        print(f"File '{key_path}' does not exist.")
        signing_key = ec.generate_private_key(
            ec.SECP384R1()  # Also called NIST P-384. https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves
        )
        signing_str = signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # do not encrypt key for storage
        ).decode('utf-8')
        with open(key_path, 'w') as f:
            f.write(signing_str)
            f.close()
    
    return signing_key

load_private_key()