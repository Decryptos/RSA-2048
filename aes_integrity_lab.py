"""Offline integrity comparison inspired by Prof. Bill Buchanan's AES-CTR example.

Requires: python -m pip install cryptography
Run: python aes_integrity_lab.py
AES-CTR provides no authentication; use authenticated encryption in real systems.
Source: https://billatnapier.medium.com/can-i-break-aes-encryption-yes-31bdf539aba0
"""
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def run_lab():
    key = os.urandom(32)
    plaintext = b"Pay Bob 1 dollar"
    altered_plaintext = b"Pay Bob 2 dollar"
    position = plaintext.index(b"1")
    change = plaintext[position] ^ altered_plaintext[position]

    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    modified = bytearray(ciphertext)
    modified[position] ^= change
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    ctr_result = decryptor.update(bytes(modified)) + decryptor.finalize()
    assert ctr_result == altered_plaintext

    nonce = os.urandom(12)
    aead = AESGCM(key)
    encrypted = aead.encrypt(nonce, plaintext, None)
    assert aead.decrypt(nonce, encrypted, None) == plaintext
    modified_gcm = bytearray(encrypted)
    modified_gcm[position] ^= change
    try:
        aead.decrypt(nonce, bytes(modified_gcm), None)
    except InvalidTag:
        gcm_rejected = True
    else:
        gcm_rejected = False
    assert gcm_rejected, "Modified GCM ciphertext must be rejected"

    print("CTR original message:", plaintext.decode())
    print("CTR modified message:", ctr_result.decode())
    print("GCM original round-trip: passed")
    print("GCM modified ciphertext: rejected")
    print("Local demonstration only; this does not test a deployed system.")


if __name__ == "__main__":
    run_lab()
