#!/usr/bin/env python3
# pip3 install cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os


def aes_generate_key():
    # 256bit random data
    return os.urandom(32)


def aes_gcm_encrypt(key: bytes, message: bytes) -> bytes:
    # Generate 96bit Initialization Vector
    iv = os.urandom(12)

    # Init AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    # Encrypt 'message'
    aes_data = encryptor.update(message) + encryptor.finalize()
    # Get the full cipherText: IV + Encrypted-Message + Auth-Tag
    ciphertext = iv + aes_data + encryptor.tag
    return ciphertext


def aes_gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[0:12]
    aes_data = ciphertext[12:-16]
    tag = ciphertext[-16:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    text = decryptor.update(aes_data) + decryptor.finalize()
    return text


if __name__ == '__main__':
    MESSAGE = b'hello world'

    aes_key = aes_generate_key()
    ciphertext = aes_gcm_encrypt(aes_key, MESSAGE)
    plaintext = aes_gcm_decrypt(aes_key, ciphertext)
    assert plaintext == MESSAGE, (plaintext, MESSAGE)

    print('AES key', base64.b64encode(aes_key))
    print('Ciphertext', base64.b64encode(ciphertext))
