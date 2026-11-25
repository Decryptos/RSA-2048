"""Offline generated-key RSA lab. Requires cryptography and sympy.

The close-prime key is deliberately defective. No external keys are accepted.
SIQS is demonstrated only on a small, fixed educational composite.
"""
import importlib.machinery
import math
import multiprocessing as mp
import pathlib
import queue
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from factor_engine import load_engine
factor = load_engine()


def attempt(label, n, budget=3):
    start = time.monotonic()
    try:
        parts = factor.factor(n, seconds=budget, seed=42)
        valid = len(parts) == 2 and all(1 < p < n for p in parts) and math.prod(parts) == n
        print(f'{label}: {n.bit_length()} bits; factors verified={valid}; elapsed={time.monotonic()-start:.2f}s')
        return parts if valid else None
    except factor.FactorisationTimeout:
        print(f'{label}: {n.bit_length()} bits; timeout after {time.monotonic()-start:.2f}s (inconclusive)')
        return None


def siqs_worker(n, output):
    try:
        from sympy.ntheory.qs import qs
        output.put(('ok', sorted(qs(n, 3000, 10000, seed=7))))
    except Exception as exc:
        output.put(('error', str(exc)))


def siqs_demo():
    # Small published-size educational numbers, not production RSA keys.
    from sympy import nextprime, isprime
    p = int(nextprime(2**39 + 12345)); q = int(nextprime(2**40 + 56789)); n = p*q
    ctx = mp.get_context('spawn'); out = ctx.Queue()
    worker = ctx.Process(target=siqs_worker, args=(n, out)); worker.start()
    try:
        try:
            status, result = out.get(timeout=15)
        except queue.Empty:
            print('SIQS small control: timed out after 15s (inconclusive)'); return
        if status != 'ok':
            print('SIQS small control error:', result); return
        valid = len(result) == 2 and math.prod(result) == n and all(isprime(v) for v in result)
        print(f'SIQS small control: {n.bit_length()} bits; factors verified={valid}')
    finally:
        if worker.is_alive(): worker.terminate()
        worker.join(); out.close(); out.join_thread()


def main():
    from sympy import nextprime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e = 65537; p = key.private_numbers().p; q = int(nextprime(p))
    while math.gcd(e, (p-1)*(q-1)) != 1:
        q = int(nextprime(q))
    n = p*q; public = rsa.RSAPublicNumbers(e, n).public_key()
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    message = b'RSA laboratory test'; ciphertext = public.encrypt(message, oaep)
    print('Close-prime modulus is deliberately constructed and insecure.')
    parts = attempt('Close-prime control', n)
    if parts:
        a,b = parts; d = pow(e, -1, math.lcm(a-1,b-1))
        recovered = rsa.RSAPrivateNumbers(a,b,d,rsa.rsa_crt_dmp1(d,a),rsa.rsa_crt_dmq1(d,b),rsa.rsa_crt_iqmp(a,b),rsa.RSAPublicNumbers(e,n)).private_key()
        print('OAEP decrypted with recovered lab factors:', recovered.decrypt(ciphertext,oaep) == message)
    else:
        print('Recovered-key decryption skipped: no validated factors')
    attempt('Normal-key control', key.public_key().public_numbers().n)
    siqs_demo()
    print('Small SIQS test and close-prime control do not establish a general RSA break.')


if __name__ == '__main__':
    main()
