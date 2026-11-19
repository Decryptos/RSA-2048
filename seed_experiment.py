#!/usr/bin/env python3
"""Offline seed repeatability experiment. Run: python3 seed_experiment.py

This demonstration produces tiny 16-bit primes using Python's non-cryptographic
random.Random. Never use it to create RSA keys. It does not assess or recover
third-party keys. The OS randomness source may use hardware, but this program
does not directly access or verify a hardware random-number generator.
"""
import hashlib
import math
import os
import random
import secrets
import time


def prime(n):
    return n >= 2 and all(n % d for d in range(2, math.isqrt(n) + 1))


def prime_pair(seed):
    rng = random.Random(seed)
    def next_prime():
        while True:
            candidate = rng.randrange(1 << 15, 1 << 16) | 1
            if prime(candidate):
                return candidate
    p = next_prime()
    q = next_prime()
    while q == p:
        q = next_prime()
    return p, q


def main():
    now = int(time.time())
    pid = os.getpid()
    # A fixed salt is used solely to make this teaching example repeatable.
    password_seed = hashlib.scrypt(b'example-password', salt=b'example-lab-salt',
                                   n=1 << 14, r=8, p=1, dklen=32)
    os_seed = secrets.token_bytes(32)
    mixed_seed = hashlib.sha256(os_seed + f'{now}:{pid}'.encode()).digest()
    seeds = [('fixed', 42), ('time', now), ('time and PID', f'{now}:{pid}'),
             ('password and fixed salt', password_seed), ('OS randomness', os_seed),
             ('OS randomness mixed with time and PID', mixed_seed)]
    print('Tiny-prime laboratory: random.Random is not suitable for real keys.')
    for label, seed in seeds:
        p, q = prime_pair(seed)
        assert prime(p) and prime(q) and p != q
        assert (p, q) == prime_pair(seed)
        print(f'{label}: same seed repeats pair; modulus bits: {(p*q).bit_length()}')
    print('Fresh OS seed sample differs:', secrets.token_bytes(32) != os_seed)
    print('Direct hardware RNG: not tested; OS sources are implementation-dependent.')
    print('Reproducibility does not establish whether a seed is guessable.')


if __name__ == '__main__':
    main()
