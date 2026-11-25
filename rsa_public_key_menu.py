"""Inspect a pasted RSA or elliptic-curve public key in the offline education lab."""

import hashlib
import sys

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)


def main():
    sizes = {"1": 2048, "2": 3072, "3": 4096}
    print("Select your public-key type:")
    for option, bits in sizes.items():
        print(f"  {option}. RSA-{bits}")
    print("  4. Elliptic curve (EC)")

    try:
        choice = input("Choice (1, 2, 3, or 4): ").strip()
        if choice not in sizes and choice != "4":
            print("Choose 1, 2, 3, or 4.", file=sys.stderr)
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

    if choice == "4":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            print("The submitted key is not an elliptic-curve public key.", file=sys.stderr)
            return 1
        print(f"Elliptic curve: {public_key.curve.name}")
        print(f"EC key size: {public_key.key_size} bits")
    else:
        if not isinstance(public_key, rsa.RSAPublicKey):
            print("The submitted key is not an RSA public key. For EC keys, choose 4.", file=sys.stderr)
            return 1
        expected_bits = sizes[choice]
        if public_key.key_size != expected_bits:
            print(
                f"Selected {expected_bits} bits, but the key has {public_key.key_size} bits.",
                file=sys.stderr,
            )
            return 1
        numbers = public_key.public_numbers()
        print(f"RSA modulus size: {numbers.n.bit_length()} bits")
        print(f"Public exponent: {numbers.e}")

    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(der).hexdigest()
    print(f"SHA-256 public-key fingerprint (SPKI DER): {fingerprint}")
    print("Key generation and private-key custody require separate evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
