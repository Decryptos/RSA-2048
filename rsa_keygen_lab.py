#!/usr/bin/env python3
"""Offline textbook RSA demonstration with selectable total modulus size.

Educational demonstration only: raw RSA is deterministic and must not be used
for real-world message encryption. Generated private factors are sensitive.
"""
import argparse
import math

from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

SUPPORTED_SIZES = (2048, 3072, 4096)
PUBLIC_EXPONENT = 65537


def generate_key_numbers(key_bits, prime_factory=getPrime, random_bytes=get_random_bytes):
    """Return (p, q, n, e, d) with exactly key_bits in the modulus."""
    if key_bits not in SUPPORTED_SIZES:
        raise ValueError(f"Choose a key size from {SUPPORTED_SIZES}")
    prime_bits = key_bits // 2
    e = PUBLIC_EXPONENT
    while True:
        p = prime_factory(prime_bits, randfunc=random_bytes)
        q = prime_factory(prime_bits, randfunc=random_bytes)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if n.bit_length() == key_bits and math.gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            return p, q, n, e, d


def textbook_roundtrip(message, n, e, d):
    """Demonstrate raw RSA math, NOT secure encryption."""
    encoded = message.encode("utf-8")
    m = bytes_to_long(encoded)
    if m >= n:
        raise ValueError("Encoded message integer must be smaller than the modulus")
    c = pow(m, e, n)
    recovered = pow(c, d, n)
    if recovered != m:
        raise RuntimeError("RSA round-trip verification failed")
    return c, long_to_bytes(recovered).decode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("message", nargs="?", default="Hello")
    parser.add_argument("bits", nargs="?", type=int, default=2048,
                        choices=SUPPORTED_SIZES, help="Total RSA modulus bits")
    parser.add_argument("--show-private", action="store_true",
                        help="Print p, q and d; only in a private lab")
    args = parser.parse_args(argv)
    p, q, n, e, d = generate_key_numbers(args.bits)
    ciphertext, plaintext = textbook_roundtrip(args.message, n, e, d)
    print(f"Requested RSA size: {args.bits} bits")
    print(f"Actual modulus size: {n.bit_length()} bits")
    print(f"Prime sizes: {p.bit_length()} and {q.bit_length()} bits")
    print(f"Public exponent e: {e}")
    print(f"Public modulus n: {n}")
    print(f"Ciphertext (raw textbook RSA): {ciphertext}")
    print(f"Decrypted: {plaintext}")
    print(f"Verified: {plaintext == args.message}")
    if args.show_private:
        print(f"Prime p: {p}")
        print(f"Prime q: {q}")
        print(f"Private exponent d: {d}")
    else:
        print("Private factors and exponent hidden; use --show-private in a private lab.")
    print("Warning: raw textbook RSA without padding is not secure encryption.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
