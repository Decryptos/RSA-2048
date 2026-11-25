"""Real high-level AEAD regression checks, not a reproduction of EVP_Cipher CVEs."""
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def run_lab():
    results = []
    for cls in (AESGCM, ChaCha20Poly1305):
        cipher = cls(os.urandom(32))
        for plaintext in (b"", b"Decrypto local integrity check"):
            nonce, aad = os.urandom(12), b"lab context"
            encrypted = cipher.encrypt(nonce, plaintext, aad)
            row = {"algorithm": cls.__name__, "plaintext_bytes": len(plaintext),
                   "roundtrip": cipher.decrypt(nonce, encrypted, aad) == plaintext}
            modified = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
            for name, data, context in (("altered_tag_rejected", modified, aad),
                                         ("wrong_aad_rejected", encrypted, b"wrong context")):
                try:
                    cipher.decrypt(nonce, data, context)
                except InvalidTag:
                    row[name] = True
                else:
                    row[name] = False
            results.append(row)
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_lab(), indent=2))
