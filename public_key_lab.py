#!/usr/bin/env python3
"""Interactive, offline RSA public-key factorisation laboratory.

Only use locally generated keys or keys explicitly authorised for testing.
This tool uses the repository's existing bounded factoriser. Accepting an
RSA-2048 modulus does not imply that ordinary RSA-2048 can be factored.
"""
import argparse
import importlib.machinery
import importlib.util
import math
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_factoriser():
    source = Path(__file__).with_name("Main")
    loader = importlib.machinery.SourceFileLoader("rsa_factor_engine", str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module

def parse_public_key(pem_bytes):
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported")
    numbers = key.public_numbers()
    if not (numbers.n > 1 and numbers.e > 1 and numbers.e % 2 == 1):
        raise ValueError("Invalid RSA public numbers")
    return numbers.n, numbers.e

def load_public_key(path=None, *, input_fn=input):
    if path:
        return parse_public_key(Path(path).read_bytes())
    print("Paste your RSA public key (PEM format). End with -----END PUBLIC KEY-----")
    lines = []
    while len(lines) < 1000:
        line = input_fn()
        lines.append(line)
        if line.strip() in ("-----END PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"):
            break
    else:
        raise ValueError("Public key input too long")
    return parse_public_key(("\n".join(lines) + "\n").encode())

def reconstruct_private_numbers(n, e, factors, engine):
    if len(factors) != 2:
        raise ValueError("Exactly two prime factors are required for RSA")
    p, q = sorted(factors, reverse=True)
    if p == q or p * q != n or not all(engine.is_probable_prime(v) for v in (p, q)):
        raise ValueError("Factors failed primality, distinctness or product verification")
    lam = math.lcm(p - 1, q - 1)
    if math.gcd(e, lam) != 1:
        raise ValueError("Public exponent is not invertible modulo lambda(n)")
    d = pow(e, -1, lam)
    numbers = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d,
        dmp1=d % (p - 1), dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    # Private-key validation is performed by the cryptography backend.
    numbers.private_key()
    return numbers

def main(argv=None, *, input_fn=input):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, help="Path to a local PEM RSA public key; otherwise paste it")
    parser.add_argument("--seconds", type=float, default=10.0, help="Total bounded factorisation budget")
    parser.add_argument("--max-bits", type=int, default=2056, help="Maximum modulus size accepted by the engine")
    args = parser.parse_args(argv)
    try:
        n, e = load_public_key(args.public_key, input_fn=input_fn)
        if n.bit_length() > args.max_bits:
            raise ValueError(f"Modulus exceeds the configured {args.max_bits}-bit input limit")
        print(f"RSA public exponent: {e}")
        print(f"RSA modulus bit length: {n.bit_length()}")
        print("Attempting bounded factorisation using the existing engine...")
        engine = load_factoriser()
        try:
            factors = engine.factor(n, seconds=args.seconds, max_bits=args.max_bits)
        except engine.FactorisationTimeout:
            print("No factors recovered within the time budget (inconclusive).")
            return 2
        if math.prod(factors) != n:
            raise ValueError("Factorisation product verification failed")
        print("Factors recovered and their product verified:")
        for index, factor in enumerate(factors, 1):
            print(f"  factor {index}: {factor}")
        if len(factors) != 2 or factors[0] == factors[1]:
            print("Cannot reconstruct a standard two-prime RSA key from these factors.")
            return 2
        reply = input_fn("Attempt to reconstruct the private key with the current version? [y/N]: ").strip().lower()
        if reply not in ("y", "yes"):
            print("Private-key reconstruction skipped.")
            return 0
        numbers = reconstruct_private_numbers(n, e, factors, engine)
        print("Private-key reconstruction verified in memory.")
        print(f"Private exponent d: {numbers.d}")
        print("The private key was not saved or exported.")
        return 0
    except (ValueError, OSError, EOFError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
