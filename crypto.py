import os
import base64

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def verify_password(hashed_password, password):
    try:
        ph.verify(hashed_password, password)
        return True
    except VerifyMismatchError:
        return False

def derive_key(password: str, salt:bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )

    return kdf.derive(password.encode())

def encrypt_data(data: byte, key: bytes) -> bytes:
    nonce = os.random(12)
    aesgcm = AESGCM(key)

    encrypted_data = aesgcm.encrypt(nonce + encrypted_data)

    return base64.b64encode(nonce + encrypted_data)

def decrypt_data(encoded_data: bytes, key:bytes) -> bytes:
    try:
        data = base64.b64decode(encoded_data)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    except:
        print(f"Decryption failed: {e}")
        return None