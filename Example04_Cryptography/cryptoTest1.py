# from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.ECDH
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

# modified by
# Seth McNeill
# 2025 April 01

import base64  # for encoding the keys for transport and loading into Fernet
import pdb 
import os  # for checking file existence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  # for loading keys
from cryptography.fernet import Fernet  # symmetric key encryption

fname_privateKey = 'private.pem'
signing_key = None
if os.path.exists(fname_privateKey):
  # load signing private key from disk
  print(f"File '{fname_privateKey}' exists.")
  try:
    with open(fname_privateKey, "rb") as key_file:
      signing_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
      )
    print("Successfully loaded signing key")
  except FileNotFoundError:
    print(f"Error: File not found at {fname_privateKey}")
  except Exception as e:
    print(f"An error occurred loading the signing key: {e}")
else:
  # create new signing key and save to disk
  print(f"File '{fname_privateKey}' does not exist.")
  signing_key = ec.generate_private_key(
      ec.SECP384R1()  # Also called NIST P-384. https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves
  )
  signing_str = signing_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # do not encrypt key for storage
  ).decode('utf-8')
  with open(fname_privateKey, 'w') as f:
    f.write(signing_str)
    f.close()


# Generate a private key for use in the exchange.
# This should be renewed for every new exchange. 
private_key = ec.generate_private_key(
    ec.SECP384R1()
)
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key
# and get a public key from that.
peer_key = ec.generate_private_key(
    ec.SECP384R1()
)
peer_public_key = peer_key.public_key()
private_shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
# Perform key derivation.
private_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(private_shared_key)

# derive a key the other way
peer_shared_key = peer_key.exchange(ec.ECDH(), private_key.public_key())
# Perform key derivation.
peer_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(peer_shared_key)
print(private_derived_key == peer_derived_key)
print("Private derived key")
print(private_derived_key)
print("Peer derived key")
print(peer_derived_key)

# symmetric key encryption using Fernet
# https://cryptography.io/en/latest/fernet/
# this uses AES in CBC mode with 128-bit key for encryption and PKCS7 padding
# Fernet implementation not suitable for data that does not fit in memory
private_msg = "Hello world from private!"
print(f"Private message: {private_msg}")

# encrypt with private derived key
private_F_key = base64.urlsafe_b64encode(private_derived_key)
private_F = Fernet(private_F_key)
private_token = private_F.encrypt(private_msg.encode('utf-8'))
private_token2 = private_F.encrypt(private_msg.encode('utf-8'))
print(f"private symmetrically encrypted message 1:\nlength: {len(private_token)}\n{private_token}")
print(f"private symmetrically encrypted message 2:\nlength: {len(private_token2)}\n{private_token2}")
private_t1_time = private_F.extract_timestamp(private_token)
private_t1_b64decoded = base64.urlsafe_b64decode(private_token)
print(f"Base64 decoded token 1: {private_t1_b64decoded}")
print(f"T1 time: {private_t1_time}")

# decrypt with peer derived key
peer_F_key = base64.urlsafe_b64encode(peer_derived_key)
peer_F = Fernet(peer_F_key)
peer_F_decrypted_msg = peer_F.decrypt(private_token).decode('utf-8')
print(f"Peer decoded message: {peer_F_decrypted_msg}")

# Encrypt with peer derived key
peer_msg = "Hello from peer"
peer_token = peer_F.encrypt(peer_msg.encode('utf-8'))
print(f"peer symmetrically encrypted message:\nlength: {len(peer_token)}\n{peer_token}")

# Decrypt with private derived key
private_decrypted_msg = private_F.decrypt(peer_token).decode('utf-8')
print(f"Private decoded message: {private_decrypted_msg}")

# print("Private public key is:")
# print(private_key.public_key().public_bytes(
#   encoding=serialization.Encoding.PEM,
#   format=serialization.PublicFormat.SubjectPublicKeyInfo
# ).decode('utf-8'))

# print("Peer public key is:")
# print(peer_public_key.public_bytes(
#   encoding=serialization.Encoding.PEM,
#   format=serialization.PublicFormat.SubjectPublicKeyInfo
# ).decode('utf-8'))

# pdb.set_trace()
