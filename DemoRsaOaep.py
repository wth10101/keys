# code from video link below
# https://www.youtube.com/watch?v=kD6Pc3yu5e8

#!/usr/bin/env python3
# pip3 install cryptography
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

import base64
import os


def generate_rsa_keys(key_size: int = 4096) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def export_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    public_key_spki = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_spki


def export_rsa_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    private_key_pkcs8 = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()  # Optional encryption algorithm
    )
    return private_key_pkcs8


def load_rsa_public_key(public_key_spki: bytes) -> rsa.RSAPublicKey:
    return load_der_public_key(public_key_spki)


def load_rsa_private_key(private_key_pkcs8: bytes) -> rsa.RSAPrivateKey:
    return load_der_private_key(private_key_pkcs8, password=None)


OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA512()),
    algorithm=hashes.SHA512(),
    label=None
)


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    return public_key.encrypt(message, OAEP_PADDING)


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, OAEP_PADDING)


def rsa_sign_sha256(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def rsa_verify_sign_sha256(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bytes:
    public_key.verify(
        signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


if __name__ == '__main__':
    MESSAGE = b'hello world'

    private_key, public_key = generate_rsa_keys()
    ciphertext = rsa_oaep_encrypt(public_key, MESSAGE)
    plaintext = rsa_oaep_decrypt(private_key, ciphertext)
    assert plaintext == MESSAGE, (plaintext, MESSAGE)

    signature = rsa_sign_sha256(private_key, MESSAGE)
    rsa_verify_sign_sha256(public_key, signature, MESSAGE)

    print('RSA public-key', base64.b64encode(export_rsa_public_key(public_key)))
    print('RSA private-key', base64.b64encode(export_rsa_private_key(private_key)))
    print('Ciphertext', len(ciphertext), base64.b64encode(ciphertext))
    print('Signature', len(signature), base64.b64encode(signature))