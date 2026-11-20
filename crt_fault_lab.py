"""Offline Bellcore-style RSA-CRT single-branch fault demonstration.

Only uses a freshly generated local RSA key. No network or target probing.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from math import gcd, lcm


def experiment(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private = key.private_numbers()
    p, q, d = private.p, private.q, private.d
    n, e = private.public_numbers.n, private.public_numbers.e
    message = int.from_bytes(b'Decrypto isolated CRT fault lab', 'big')
    assert 0 < message < n

    sp = pow(message, d % (p-1), p)
    sq = pow(message, d % (q-1), q)

    def recombine(p_branch, q_branch):
        # CRT: s = sq + q * ((sp-sq)*q^{-1} mod p)
        return (q_branch + q * ((p_branch-q_branch) * pow(q, -1, p) % p)) % n

    good = recombine(sp, sq)
    assert pow(good, e, n) == message
    fault = recombine((sp+1) % p, sq)
    assert pow(fault, e, n) != message

    recovered_factor = gcd((pow(fault, e, n)-message) % n, n)
    assert recovered_factor in (p, q)
    other_factor = n // recovered_factor
    assert recovered_factor * other_factor == n
    recovered_d = pow(e, -1, lcm(recovered_factor-1, other_factor-1))
    assert (e * recovered_d) % lcm(p-1, q-1) == 1
    assert pow(pow(message, e, n), recovered_d, n) == message

    # Hardened signer verifies the CRT result before exposing it.
    def verified_sign(p_branch, q_branch):
        result = recombine(p_branch, q_branch)
        if pow(result, e, n) != message:
            raise ValueError('CRT signature verification failed')
        return result

    assert verified_sign(sp, sq) == good
    fault_rejected = False
    try:
        verified_sign((sp+1) % p, sq)
    except ValueError:
        fault_rejected = True
    assert fault_rejected

    return {
        'bits': bits,
        'valid_signature_verified': True,
        'faulty_signature_failed_verification': True,
        'factor_recovered': True,
        'factor_product_verified': True,
        'private_exponent_reconstructed': True,
        'recovered_key_decryption_verified': True,
        'defensive_fault_rejected': fault_rejected,
        'fault_model': 'synthetic +1 corruption of p-side CRT residue',
        'scope': 'locally generated key, no network',
    }


if __name__ == '__main__':
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument('--bits', type=int, choices=[2048,3072,4096], default=2048)
    args = parser.parse_args()
    print(json.dumps(experiment(args.bits), indent=2))
