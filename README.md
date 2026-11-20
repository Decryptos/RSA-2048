# Bounded RSA Factorisation for Education

An offline Python laboratory implementation of classical integer-factorisation methods for learning and controlled exercises with arbitrary-precision integers. It implements the algorithms directly; it is not a simulator.

> **Educational use only.** This code could be misused to attempt recovery of weak RSA private keys. Use it only with synthetic examples or data you are explicitly authorized to assess. Factoring a weak RSA modulus may expose encrypted data or enable forged signatures. The local OAEP exercise decrypts with the lab private key; the factorisation CLI does not decrypt messages or recover a normal RSA-2048 private key.

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


## Interactive public-key factorisation lab

For **locally generated or explicitly authorised RSA keys only**, install the
`cryptography` package and run:

```sh
python -m pip install cryptography
python public_key_lab.py --public-key rsa2048-lab-public.pem --seconds 10
```

For Buchanan's `getPrime(bits)` example with `bits=1024`, the two primes are
1024 bits **each**, while their product `n` is 2047 or 2048 bits. The CLI
therefore defaults to `--prime-bits 1024` and `--max-bits 2056`.
`--prime-bits` is an expected size for reporting and consistency checking;
it cannot reveal or verify the actual prime sizes without factoring `n`.

Omit `--public-key` to paste a PEM-encoded RSA public key when prompted.
The tool extracts the RSA modulus (`n`) and public exponent (`e`), attempts
factorisation using the existing bounded engine, prints verified candidate
prime factors if found, then asks whether to reconstruct the private key.
When reconstruction succeeds, it prints the private exponent `d` to the
terminal but does not save or export a private-key file. Treat terminal
output as sensitive. Do not run the command on someone else's keys without
explicit authorisation.

**Important:** The ordinary outcome for a properly generated RSA-2048 key
is that the program does *not* find its two prime factors within the budget.
A timeout proves neither security nor vulnerability. The separate OAEP lab
uses an already-known private key, not an RSA breakthrough.

Run offline tests with:

```sh
python -m unittest -v test_public_key_lab.py
```


## Selectable 2048-, 3072-, and 4096-bit textbook RSA generator

The offline `rsa_keygen_lab.py` script adapts Buchanan's prime-generation
demonstration. The selected size refers to **total modulus bits**, not bits
per prime: 2048 uses two 1024-bit primes, 3072 uses two 1536-bit primes, and
4096 uses two 2048-bit primes. The generator enforces the requested actual
modulus length, distinct primes, and invertibility of exponent 65537.

Install PyCryptodome and choose a size:

```sh
python -m pip install pycryptodome
python rsa_keygen_lab.py Hello 2048
python rsa_keygen_lab.py Hello 3072
python rsa_keygen_lab.py Hello 4096
```

To print sensitive private factors and exponent in a **private offline lab**
only, add `--show-private`. By default only public numbers, raw ciphertext,
decrypted plaintext and the verification outcome are printed. This is
**textbook RSA without secure padding**, suitable for demonstration only,
not production encryption and not a public-key factorisation attack.

```sh
python -m unittest -v test_rsa_keygen_lab.py
```

## Offline chosen-ciphertext attack lab

`chosen_ciphertext_lab.py` demonstrates the multiplicative malleability of
**textbook RSA** with a fixed local key (n=3233, e=17). The attacker modifies
a ciphertext by multiplying by `r**e mod n`, obtains the raw decrypted
integer from a **simulated** vulnerable oracle, and unblinds it using the
modular inverse of `r`. The expected recovered plaintext is 65.

```sh
python chosen_ciphertext_lab.py
python -m unittest -v test_chosen_ciphertext_lab.py
```

Expected known-vector values: ciphertext 2790, modified ciphertext 1258,
oracle response 455, recovered plaintext 65, verified True.

This is **plaintext recovery from a deliberately vulnerable raw RSA oracle**,
not recovery of the RSA private key, not factorisation of RSA-2048/3072/4096,
and not a demonstration against OAEP or any external service. The lab
performs no network activity.

## Responsible use

This project is intended for education, synthetic test cases, and controlled labs. Do not use it to investigate third-party keys or systems without explicit authorization. Treat any factorisation of a real key as a potential key compromise and follow the applicable disclosure process; do not publish recovered private material.

## Reuse

There is currently no license file in this repository. Ask the maintainer before reusing or redistributing the code.
