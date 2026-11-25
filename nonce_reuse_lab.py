"""Offline AES-CTR and ChaCha20 nonce-reuse teaching lab. Synthetic data only."""
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xor_equal(left, right):
    if len(left) != len(right):
        raise ValueError("Inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(kind, key, nonce, message):
    if kind == "aes-ctr":
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    elif kind == "chacha20":
        # cryptography's raw API takes a 64-bit counter + 64-bit nonce,
        # not the RFC 8439 32-bit counter + 96-bit nonce layout.
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Unsupported cipher")
    context = cipher.encryptor()
    return context.update(message) + context.finalize()


def run_lab(kind):
    key = bytes(range(32))  # Fixed fixtures; never use these in production.
    reused = bytes(16)
    fresh = b"\x00" * 8 + b"\x01" * 8
    known = b"known message 01"
    secret = b"other message 02"
    first = encrypt(kind, key, reused, known)
    second = encrypt(kind, key, reused, secret)
    recovered = xor_equal(xor_equal(first, second), known)
    control = xor_equal(xor_equal(first, encrypt(kind, key, fresh, secret)), known)
    return {
        "cipher": kind,
        "fixture": "synthetic fixed key and messages",
        "known_plaintext_bytes": len(known),
        "recovered_plaintext": recovered.decode("ascii"),
        "reused_nonce_recovery": recovered == secret,
        "fresh_nonce_recovery": control == secret,
        "key_recovered": False,
    }


if __name__ == "__main__":
    print(json.dumps([run_lab(k) for k in ("aes-ctr", "chacha20")], indent=2))
