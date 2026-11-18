# Lab Guide: Integer Factorisation and RSA

This guide uses real RSA arithmetic and locally generated keys. It is for education and controlled laboratory work. It does not scan hosts, recover third-party keys, or decrypt messages.

> **Safety:** A factorisation of a real RSA modulus can enable recovery of its private key. Use only keys you generate yourself or data explicitly authorized for assessment. Keep the generated private key local and never commit it.

## 1. Run the existing tests

From the repository root:

```sh
python -m unittest -v test_factorisation.py
```

The tests exercise the actual implementations of Miller–Rabin, Fermat, Pollard p−1, ECM stage one, Pollard–Brent, and the configured input-size boundary. The fixtures are controlled small integers; they validate algorithm paths, not performance against balanced RSA-2048.

## 2. Check a known small composite

```sh
python Main 3233
```

Expected output:

```text
3233 = 53 * 61
Verification: True
```

This is a compact way to inspect factor ordering and the product check.

## 3. Generate and inspect a local RSA-2048 key

Requires OpenSSL and Python 3.8 or later. These commands create a fresh local key pair and extract only the public modulus as a decimal integer:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048-lab-private.pem
openssl pkey -in rsa2048-lab-private.pem -pubout -out rsa2048-lab-public.pem
openssl rsa -pubin -in rsa2048-lab-public.pem -modulus -noout \
  | sed 's/^Modulus=//' \
  | python -c 'import sys; print(int(sys.stdin.read().strip(), 16))' \
  > rsa2048-lab-modulus.txt
```

Run the factoriser against that local public modulus with a bounded budget:

```sh
python Main "$(cat rsa2048-lab-modulus.txt)" --seconds 10
```

For a properly generated balanced key, the expected result is a time-budget error. This demonstrates that the program accepts a full-size RSA modulus while its current algorithms and bounds do not practically factor a normal RSA-2048 key. It is one experiment, not a proof about every possible modulus.

The private key is not needed by the factoriser. Keep `rsa2048-lab-private.pem` private and remove the lab files when finished.

## 4. Study why specially structured inputs differ

The methods have different favorable conditions:

- **Fermat:** factors that are unusually close together.
- **Pollard p−1:** a factor whose predecessor has a sufficiently smooth factorisation within the chosen stage-one bound.
- **ECM stage one:** composites with a factor small enough for the selected curve bound.
- **Pollard–Brent:** general-purpose small-factor search whose work grows rapidly with the size of the smallest factor.

Use the existing unit-test fixtures to observe each method under a controlled condition. Change one parameter at a time, record the input, seed, setting, elapsed time, and whether the product check passes. A seeded run is for experiment replay only, not key generation.

## 5. Interpret results correctly

- A 2056-bit default input ceiling describes accepted input size, not factoring capability.
- Factors above 64 bits are probable primes according to Miller–Rabin; they are not formally proven prime by this program.
- A timeout is an inconclusive result for that input and budget. It is not evidence that a key is secure.
- A successful factorisation identifies a weak modulus. This program does not parse PEM keys, derive RSA private keys, or decrypt ciphertexts.
- The implementation has no network functionality and does not include GNFS or a production-optimized ECM engine.

## Suggested lab record

For each run, record:

| Field | Example |
|---|---|
| Input source | Locally generated RSA key or published synthetic fixture |
| Modulus bit length | 2048 |
| Factor structure | Known from lab construction, or unknown |
| Time budget and algorithm bounds | Defaults or explicit values |
| Seed | Integer seed, or “system random” |
| Outcome | Factors found, timeout, or validation error |
| Product verification | True/false |
| Interpretation | What this experiment shows and what it does not show |
