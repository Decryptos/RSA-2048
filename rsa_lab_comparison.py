"""Offline, generated-key RSA comparison; requires cryptography.

The close-prime case is intentionally defective. No external keys are accepted.
"""
import importlib.machinery
import math
import pathlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

factor = importlib.machinery.SourceFileLoader('factor_lab', str(pathlib.Path(__file__).with_name('Main'))).load_module()


def attempt(label, n, budget=3):
    start = time.monotonic()
    try:
        parts = factor.factor(n, seconds=budget, seed=42)
        valid = len(parts) == 2 and all(1 < p < n for p in parts) and math.prod(parts) == n
        print(f'{label}: {n.bit_length()} bits; factors verified={valid}; elapsed={time.monotonic()-start:.2f}s')
    except factor.FactorisationTimeout:
        print(f'{label}: {n.bit_length()} bits; timeout after {time.monotonic()-start:.2f}s (inconclusive)')


def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b'RSA laboratory test'
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    encrypted = key.public_key().encrypt(message, oaep)
    print('Normal key OAEP round trip:', key.decrypt(encrypted, oaep) == message)
    print('The round trip uses the generated private key, not recovered factors.')
    p = key.private_numbers().p
    q = p + 2
    while not factor.is_probable_prime(q):
        q += 2
    print('Close-prime modulus is deliberately constructed and insecure.')
    attempt('Close-prime control', p*q)
    attempt('Normal-key control', key.public_key().public_numbers().n)
    print('SIQS is not included; these tests do not demonstrate a general RSA break.')


if __name__ == '__main__':
    main()
