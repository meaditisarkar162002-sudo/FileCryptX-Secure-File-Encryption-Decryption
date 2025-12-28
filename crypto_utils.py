from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(password, salt)
    cipher = ChaCha20Poly1305(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # VERY IMPORTANT: write in ONE go
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

def decrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        raw = f.read()

    if len(raw) < 28:
        raise ValueError("Invalid encrypted file format")

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = derive_key(password, salt)
    cipher = ChaCha20Poly1305(key)

    plaintext = cipher.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(plaintext)
