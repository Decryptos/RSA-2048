"""Local RSA key/certificate parsing and genuine OAEP-SHA256 decryption."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def parse_rsa_public(data):
    loaders = (serialization.load_pem_public_key, serialization.load_der_public_key,
               lambda b: x509.load_pem_x509_certificate(b).public_key(),
               lambda b: x509.load_der_x509_certificate(b).public_key())
    for loader in loaders:
        try:
            key = loader(data)
        except ValueError:
            continue
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Expected an RSA public key or RSA certificate")
        return key
    raise ValueError("Invalid PEM/DER RSA public key or X.509 certificate")


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def decrypt_oaep(key, ciphertext):
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("An RSA private key is required")
    if len(ciphertext) != (key.key_size + 7) // 8:
        raise ValueError("Ciphertext must be exactly one RSA block")
    return key.decrypt(ciphertext, oaep())


def recovered_key(result):
    if result.get("status") != "recovered":
        raise ValueError("No verified recovered key available")
    p, q, d, n, e = (result[k] for k in ("p", "q", "d", "n", "e"))
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1),
                                 pow(q, -1, p), rsa.RSAPublicNumbers(e, n)).private_key()


def known_key_demo():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"Decrypto real RSA-OAEP round trip"
    ciphertext = key.public_key().encrypt(message, oaep())
    return {"bits": key.key_size, "decrypted": decrypt_oaep(key, ciphertext).decode(),
            "verified": decrypt_oaep(key, ciphertext) == message,
            "method": "locally generated private key; no attack"}
