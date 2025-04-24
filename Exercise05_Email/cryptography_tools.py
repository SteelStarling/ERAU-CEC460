"""Helper functions for cryptography, based on those provided by Dr. McNeill
Author: Taylor Hancock, based on code from Dr. McNeill
Date:   04/07/2025
Class:  CEC460 - Telecom Systems
Assignment: EX04 - Cryptography
"""

from base64 import urlsafe_b64encode
from os import path, urandom

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet  # symmetric key encryption


KEY_LOCATION = "private_key.pem"


def generate_salt(size: int = 24) -> str:
    """Generates and returns random salt for use"""
    return urlsafe_b64encode(urandom(size)).decode('utf-8')


def private_key_to_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Converts a private key to its public key in string format"""
    # get public key
    public_key = private_key.public_key()

    # convert public key to bytes then string
    public_bytes = public_key_to_bytes(public_key)

    return public_bytes


def public_key_to_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Converts a public key to bytes, per assignment specification"""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes


def public_str_to_public_key(public_str: str) -> ec.EllipticCurvePublicKey:
    """Converts a public key in string format to key format"""
    # convert to bytes
    public_bytes = public_str.encode('utf-8')

    # convert bytes to key
    public_key = serialization.load_pem_public_key(public_bytes)

    return public_key


def derive_fernet_from_shared_key(private_key: ec.EllipticCurvePrivateKey, \
                               public_key_bytes: bytes, salt: str = None) -> Fernet:
    """Converts a pair of keys and salt to a Diffie-Hellman-derived shared Fernet key"""
    # convert bytes to actual key
    public_key = serialization.load_pem_public_key(public_key_bytes, None)

    # Use Diffie-Hellman to create shared key
    exchanged_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        info=b'handshake data'
    ).derive(exchanged_key)

    print(f"Derived Key: {derived_key}")

    # encode and convert to Fernet
    fernet_key = Fernet( urlsafe_b64encode(derived_key) )
    return fernet_key


def generate_signature(signing_private_key: ec.EllipticCurvePrivateKey, message: str) -> bytes:
    """Generates a signature based on a private key and message to sign"""
    signature = urlsafe_b64encode(
        signing_private_key.sign(
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
    )

    return signature


def load_private_key(key_path: str = KEY_LOCATION) -> ec.EllipticCurvePrivateKey:
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
            # Also called NIST P-384.
            # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves
            ec.SECP384R1()
        )
        signing_str = signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # do not encrypt key for storage
        ).decode('utf-8')
        with open(key_path, 'w', encoding='utf-8') as f:
            f.write(signing_str)
            f.close()

    return signing_key
