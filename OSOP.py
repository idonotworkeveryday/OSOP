# OSOP.py
import struct
import zstandard as zstd
from Crypto.Cipher import ChaCha20_Poly1305
import os

HEADER_SIZE = 18  # BatchID(2) + ClientID(2) + Reserved(14)
NONCE_SIZE = 12

def compress_data(data: bytes) -> bytes:
    return zstd.ZstdCompressor(level=1).compress(data)

def decompress_data(data: bytes) -> bytes:
    return zstd.ZstdDecompressor().decompress(data)

def encrypt_batch(key: bytes, plaintext: bytes) -> (bytes, bytes):
    nonce = os.urandom(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext, tag

def decrypt_batch(key: bytes, ciphertext_with_nonce: bytes, tag: bytes) -> bytes:
    nonce = ciphertext_with_nonce[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce[NONCE_SIZE:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
