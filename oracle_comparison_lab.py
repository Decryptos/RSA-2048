"""Offline RSA oracle comparison using locally generated keys.

Requires cryptography. No network access or external targets.
Boundary distinguishability is NOT full Manger plaintext recovery.
"""
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def run_comparison(bits=2048, message=b"Decrypto isolated lab message", trials=8):
    if bits not in (2048, 3072, 4096):
        raise ValueError("Supported key sizes: 2048, 3072, 4096")
    if not 1 <= trials <= 128:
        raise ValueError("trials must be between 1 and 128")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = key.private_numbers()
    n, e, d = numbers.public_numbers.n, numbers.public_numbers.e, numbers.d
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(message, "big")
    if not 0 < m < n:
        raise ValueError("message integer outside RSA domain")

    # Raw textbook RSA: one-query plaintext recovery.
    c = pow(m, e, n)
    r = 2
    while math.gcd(r, n) != 1:
        r += 1
    modified = c * pow(r, e, n) % n
    oracle_response = pow(modified, d, n)
    recovered = oracle_response * pow(r, -1, n) % n
    raw_success = recovered == m and pow(recovered, e, n) == c

    # Deliberately vulnerable boundary oracle, not a complete Manger attack.
    boundary = 1 << (8 * (k - 1))
    def boundary_oracle(ciphertext):
        return pow(ciphertext, d, n) < boundary
    below = boundary_oracle(pow(boundary - 1, e, n))
    at = boundary_oracle(pow(boundary, e, n))

    # OAEP-SHA256 negative control.
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    )
    oaep_ct = key.public_key().encrypt(message, oaep)
    valid_decrypt = key.decrypt(oaep_ct, oaep) == message
    oaep_int = int.from_bytes(oaep_ct, "big")
    rejected = 0
    for factor in range(2, 2 + trials):
        altered = (oaep_int * pow(factor, e, n) % n).to_bytes(k, "big")
        try:
            key.decrypt(altered, oaep)
        except ValueError:
            rejected += 1

    return {
        "key_bits": bits,
        "raw_plaintext_recovered": raw_success,
        "raw_oracle_queries": 1,
        "boundary_below": below,
        "boundary_at": at,
        "boundary_distinguishable": below != at,
        "manger_plaintext_recovered": False,
        "oaep_valid_decryption": valid_decrypt,
        "oaep_modified_rejected": rejected,
        "oaep_modified_total": trials,
        "timing_resistance_tested": False,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bits", type=int, choices=(2048, 3072, 4096), default=2048)
    parser.add_argument("--trials", type=int, default=8)
    args = parser.parse_args()
    for name, value in run_comparison(args.bits, trials=args.trials).items():
        print(f"{name}: {value}")
