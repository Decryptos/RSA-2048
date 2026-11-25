"""Verified offline weak-RSA recovery. No remote oracle or general RSA break."""
import math


def factors_from_phi(n, phi):
    total = n - phi + 1
    delta = total * total - 4 * n
    if delta < 0:
        return None
    root = math.isqrt(delta)
    if root * root != delta or (total + root) % 2:
        return None
    p, q = (total + root) // 2, (total - root) // 2
    return (p, q) if p > 1 and q > 1 and p != q and p * q == n else None


def wiener(n, e):
    """Continued-fraction small-d attack; NOT the N^0.287 lattice attack.

    Returns factors only after exact product verification. A miss is inconclusive.
    """
    if not isinstance(n, int) or not isinstance(e, int) or n < 4 or not 1 < e < n:
        raise ValueError("Require n >= 4 and 1 < e < n")
    numerator, denominator = e, n
    h0, h1, k0, k1 = 0, 1, 1, 0
    while denominator:
        a, remainder = divmod(numerator, denominator)
        numerator, denominator = denominator, remainder
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        k, d = h1, k1
        if k and (e * d - 1) % k == 0:
            result = factors_from_phi(n, (e * d - 1) // k)
            if result:
                return result
    return None


def shared_factor(n, peer_n):
    if n < 4 or peer_n < 4:
        raise ValueError("Moduli must be >= 4")
    divisor = math.gcd(n, peer_n)
    if 1 < divisor < n:
        return divisor, n // divisor
    return None


def roca_fingerprint(n):
    """Small-prime subgroup fingerprint, not ROCA factorisation or proof.

    Infineon primes have p = 65537^a mod M. Their products inherit
    subgroup membership modulo each small prime. Matches can be false positives.
    """
    if n < 3:
        raise ValueError("Modulus must be >=3")
    primes = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
              53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
              109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167)
    for prime in primes:
        residues, value = set(), 1
        while value not in residues:
            residues.add(value)
            value = value * 65537 % prime
        if n % prime not in residues:
            return False
    return True


def recover(n, e, seconds=5, peer_n=None):
    from factor_engine import load_engine
    engine = load_engine()
    if n.bit_length() > 8192 or not 1 < e < n or not math.isfinite(seconds) or not 0 < seconds <= 60:
        raise ValueError("Require <=8192-bit n, 1 < e < n and 0 < seconds <= 60")
    parts = shared_factor(n, peer_n) if peer_n is not None else None
    method = "shared prime GCD"
    if parts is None:
        parts, method = wiener(n, e), "Wiener continued fractions"
    if parts is None:
        method = "bounded factorisation"
        try:
            parts = engine.factor(n, seconds=seconds, max_bits=8192)
        except engine.FactorisationTimeout:
            return {"status": "inconclusive", "method": method, "reason": "budget exhausted"}
    if len(parts) != 2 or parts[0] == parts[1] or math.prod(parts) != n:
        return {"status": "inconclusive", "method": method, "reason": "not two distinct prime factors"}
    if not all(engine.is_probable_prime(p) for p in parts):
        return {"status": "inconclusive", "method": method, "reason": "primality check failed"}
    p, q = sorted(parts, reverse=True)
    lam = math.lcm(p - 1, q - 1)
    if math.gcd(e, lam) != 1:
        raise ValueError("Exponent is not invertible for these factors")
    d = pow(e, -1, lam)
    # Validate public/private operation on several representatives.
    if not all(pow(pow(m, e, n), d, n) == m for m in (0, 1, 2, n - 1)):
        raise ValueError("Recovered key failed round-trip verification")
    return {"status": "recovered", "method": method, "p": p, "q": q, "d": d, "n": n, "e": e}
