"""AES-128(ECB)+PKCS#7 helpers (use library).""" 

import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 128  # AES block size in bits

def aes_encrypt(key: bytes, plaintext: bytes) -> (str, str):
    """AES-128-CBC encrypt -> returns (iv_b64, ct_b64)."""
    iv = os.urandom(16)
    padder = padding.PKCS7(BLOCK).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(iv).decode(), base64.b64encode(ct).decode()

def aes_decrypt(key: bytes, iv_b64: str, ct_b64: str) -> bytes:
    """Decrypt AES-128-CBC. Returns raw plaintext bytes."""
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext
