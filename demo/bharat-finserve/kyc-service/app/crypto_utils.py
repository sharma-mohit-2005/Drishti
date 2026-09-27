"""Crypto helpers for the KYC service (Aadhaar-linked identity records)."""
import hashlib
import os

import jwt
from Crypto.Cipher import AES, DES3
from cryptography.hazmat.primitives.asymmetric import ec, rsa

RSA_BITS = 3072


def new_record_key():
    # Encrypts identity documents at rest.
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def new_device_key():
    return ec.generate_private_key(ec.SECP256R1())


def aadhaar_lookup_hash(aadhaar_number: str) -> str:
    return hashlib.sha1(aadhaar_number.encode()).hexdigest()


def document_checksum(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def issue_session_token(claims: dict, private_key) -> str:
    return jwt.encode(claims, private_key, algorithm="RS256")


def encrypt_legacy_blob(key: bytes, iv: bytes, data: bytes) -> bytes:
    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(data)


def encrypt_document(data: bytes):
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_GCM)
    return key, cipher.encrypt_and_digest(data)
