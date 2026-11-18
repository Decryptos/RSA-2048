# Bounded RSA Factorisation for Education

An offline Python laboratory implementation of classical integer-factorisation methods for learning and controlled exercises with arbitrary-precision integers. It implements the algorithms directly; it is not a simulator.

> **Educational use only.** This code could be misused to attempt recovery of weak RSA keys. Use it only with synthetic examples or data you are explicitly authorized to assess. A successful factorisation of a weak RSA modulus can enable private-key recovery and may expose encrypted data or allow forged signatures. This project is not a practical RSA-2048 cracker.

## What it does

The command-line factorisation program accepts one decimal integer and tries a bounded sequence of methods:

- Small-prime elimination
- Miller–Rabin primality testing
- Fermat factorisation
- Pollard p−1, stage one
- Basic affine elliptic-curve factorisation, stage one
- Pollard–Brent

The factorisation CLI uses only the Python standard library. It has no network scanning, public-key or certificate parsing, private-key derivation, or decryption. The separate lab guide uses OpenSSL with a locally generated private key to demonstrate real RSA-OAEP encryption and decryption.

## Hands-on RSA lab

See [LAB_GUIDE.md](LAB_GUIDE.md) for an end-to-end local exercise: generate a standards-size RSA-2048 key pair, encrypt and decrypt a short message with RSA-OAEP, then try the factoriser on the public modulus. The decryption uses the private key already generated for the exercise; it is distinct from recovering a private key by factoring.

## Important limits

- The default input-size ceiling is **2056 bits**. This only limits the size of an accepted integer; it does not mean the program can factor every integer of that size.
- The default time budget is **10 seconds**.
- The default Fermat, Pollard p−1, and ECM settings are deliberately bounded. Pollard–Brent runs only until the time budget expires.
- The implementation does not include the General Number Field Sieve or an optimized production ECM engine. It is not expected to factor properly generated, balanced RSA-2048 moduli.
- Factors larger than 64 bits are reported as *probable primes*, not formally proven primes.
- A deterministic `--seed` is for reproducing laboratory runs only; it must not be used for cryptographic key generation.

A 2048-bit input can still be factored quickly when it is deliberately weak—for example, when it contains a very small factor. That demonstrates a weakness in the input, not that balanced RSA-2048 is breakable.

## Quick start

Requires Python 3.8 or later; there are no third-party dependencies.

```sh
python Main 3233
```

Expected output:

```text
3233 = 53 * 61
Verification: True
```

The input is a decimal integer. For example, the following uses a shorter time budget and raises the input-size limit:

```sh
python Main 3233 --seconds 5 --max-bits 2056
```

Run the test suite with:

```sh
python -m unittest test_factorisation.py
```

## Responsible use

This project is intended for education, synthetic test cases, and controlled labs. Do not use it to investigate third-party keys or systems without explicit authorization. Treat any factorisation of a real key as a potential key compromise and follow the applicable disclosure process; do not publish recovered private material.

## Reuse

There is currently no license file in this repository. Ask the maintainer before reusing or redistributing the code.
