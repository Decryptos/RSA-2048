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
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


def hardware_seed():
    """Return a RDRAND sample on supported Linux x86-64 systems, else None.

    This sample is only for the teaching experiment, not key generation or
    certification of the CPU's random source.
    """
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        return None
    compiler = shutil.which('cc')
    try:
        cpuinfo = Path('/proc/cpuinfo').read_text()
        flags = next((line.split(':', 1)[1].split() for line in cpuinfo.splitlines()
                      if line.startswith('flags') and ':' in line), [])
    except OSError:
        return None
    if not compiler or 'rdrand' not in flags:
        return None
    source = '''#include <immintrin.h>\n#include <stdio.h>\nint main(void) { unsigned long long x; for(int i=0;i<10;i++) if(_rdrand64_step(&x)) { printf("%016llx\\n",x); return 0; } return 1; }\n'''
    try:
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / 'sample.c'
            binary = Path(directory) / 'sample'
            src.write_text(source)
            subprocess.run([compiler, '-mrdrnd', str(src), '-o', str(binary)],
                           check=True, capture_output=True, timeout=15)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, timeout=5)
            return int(result.stdout.strip(), 16)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


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
    sample = hardware_seed()
    if sample is not None:
        seeds.append(('hardware RDRAND sample', sample))
    print('Tiny-prime laboratory: random.Random is not suitable for real keys.')
    for label, seed in seeds:
        p, q = prime_pair(seed)
        assert prime(p) and prime(q) and p != q
        assert (p, q) == prime_pair(seed)
        print(f'{label}: same seed repeats pair; modulus bits: {(p*q).bit_length()}')
    def mix(entropy, timestamp, process_id):
        return hashlib.sha256(entropy + f'{timestamp}:{process_id}'.encode()).digest()
    other_os_seed = secrets.token_bytes(32)
    other_password = hashlib.scrypt(b'other-example-password', salt=b'example-lab-salt',
                                    n=1 << 14, r=8, p=1, dklen=32)
    comparisons = [
        ('fixed number', 42, 43), ('time', now, now + 1),
        ('process ID', f'{now}:{pid}', f'{now}:{pid + 1}'),
        ('password', password_seed, other_password), ('OS sample', os_seed, other_os_seed),
        ('mixed time', mix(os_seed, now, pid), mix(os_seed, now + 1, pid)),
        ('mixed PID', mix(os_seed, now, pid), mix(os_seed, now, pid + 1)),
        ('mixed entropy', mix(os_seed, now, pid), mix(other_os_seed, now, pid)),
    ]
    if sample is not None:
        other_sample = hardware_seed()
        if other_sample is not None:
            comparisons.append(('RDRAND sample', sample, other_sample))
    for label, first, second in comparisons:
        print(f'{label}: different seed: {first != second}; '
              f'different small-prime pair: {prime_pair(first) != prime_pair(second)}')
    print('Small-prime pairs can collide even when seeds differ.')
    print('Fresh OS seed sample differs:', secrets.token_bytes(32) != os_seed)
    print('Direct RDRAND:', 'sampled' if sample is not None else 'unavailable or failed')
    print('Reproducibility does not establish whether a seed is guessable.')


if __name__ == '__main__':
    main()

