#!/usr/bin/env python3
"""Offline chosen-ciphertext demonstration against textbook RSA.

This is a synthetic local decryption oracle with a fixed, deliberately tiny
RSA key. No network activity, third-party targets, or real-world key recovery.
The private exponent remains inside the simulated oracle.
"""
import math

N = 3233
E = 17
_MESSAGE = 65
_D = 2753
R = 7


def simulated_raw_rsa_oracle(ciphertext):
    """Vulnerable raw RSA oracle: returns an integer plaintext."""
    return pow(ciphertext, _D, N)


def recover_plaintext_from_oracle(ciphertext, n, e, oracle, blinding_factor):
    """Recover plaintext using one raw RSA decryption-oracle response."""
    if not 1 < blinding_factor < n or math.gcd(blinding_factor, n) != 1:
        raise ValueError("Blinding factor must be invertible modulo n")
    transformed = ciphertext * pow(blinding_factor, e, n) % n
    oracle_plaintext = oracle(transformed)
    if not isinstance(oracle_plaintext, int) or not 0 <= oracle_plaintext < n:
        raise ValueError("Oracle must return a raw RSA plaintext integer")
    recovered = oracle_plaintext * pow(blinding_factor, -1, n) % n
    if pow(recovered, e, n) != ciphertext % n:
        raise ValueError("Recovered plaintext failed public-key verification")
    return transformed, oracle_plaintext, recovered


def run_demo():
    ciphertext = pow(_MESSAGE, E, N)
    modified, oracle_result, recovered = recover_plaintext_from_oracle(
        ciphertext, N, E, simulated_raw_rsa_oracle, R
    )
    return {
        "modulus": N,
        "public_exponent": E,
        "ciphertext": ciphertext,
        "blinding_factor": R,
        "modified_ciphertext": modified,
        "oracle_response": oracle_result,
        "recovered_plaintext": recovered,
        "verified": recovered == _MESSAGE,
        "scope": "synthetic offline textbook RSA oracle only",
    }


def main():
    result = run_demo()
    for key, value in result.items():
        print(f"{key}: {value}")
    print("This is plaintext recovery via a raw decryption oracle, not private-key recovery.")
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
