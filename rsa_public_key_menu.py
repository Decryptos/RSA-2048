"""Inspect a pasted RSA public key in the offline education lab."""

import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


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

    print(f"Confirmed RSA public key: {public_key.key_size} bits.")
    print("Running factorisation on the fixed synthetic modulus 3233.", flush=True)
    factorisation_script = Path(__file__).with_name("Main")
    return subprocess.run(
        [sys.executable, str(factorisation_script), "3233", "--seconds", "5"],
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
