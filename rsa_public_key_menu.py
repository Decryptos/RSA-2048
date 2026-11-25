"""Inspect a pasted RSA public key in the offline education lab."""

import hashlib
import sys

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)


def main():
    sizes = {"1": 2048, "2": 3072, "3": 4096}
    print("Select your RSA public-key size:")
    for option, bits in sizes.items():
        print(f"  {option}. {bits} bits")

    try:
        expected_bits = sizes.get(input("Choice (1, 2, or 3): ").strip())
        if expected_bits is None:
            print("Choose 1, 2, or 3.", file=sys.stderr)
            return 1

        print("Paste the PEM public key, then enter a blank line:")
        lines = []
        while True:
            line = input().strip()
            if not line:
                break
            lines.append(line)
        pem = "\n".join(lines).encode("ascii")
        public_key = load_pem_public_key(pem)
    except (EOFError, ValueError, TypeError, UnsupportedAlgorithm):
        print("Enter a valid PEM public key followed by a blank line.", file=sys.stderr)
        return 1

    if not isinstance(public_key, rsa.RSAPublicKey):
        print("The submitted key is not an RSA public key.", file=sys.stderr)
        return 1
    if public_key.key_size != expected_bits:
        print(
            f"Selected {expected_bits} bits, but the key has {public_key.key_size} bits.",
            file=sys.stderr,
        )
        return 1

    numbers = public_key.public_numbers()
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(der).hexdigest()

    print(f"RSA modulus size: {numbers.n.bit_length()} bits")
    print(f"Public exponent: {numbers.e}")
    print(f"SHA-256 public-key fingerprint (SPKI DER): {fingerprint}")
    print("Prime generation and private-key custody require separate evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
