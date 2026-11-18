# Lab Guide: RSA Encryption, Decryption, and Integer Factorisation

This guide uses real RSA arithmetic and a locally generated RSA-2048 key pair. It separates two activities:

1. Encrypting and decrypting a short message with the matching public and private keys.
2. Studying whether the repository's bounded factoriser can factor the public modulus.

The first demonstrates ordinary RSA decryption. It uses the private key already generated for the lab. It does not recover a private key from a public key.

> **Educational use only.** A factorisation of a real RSA modulus can enable private-key recovery. Use only keys you generate yourself or data explicitly authorized for assessment. Keep the generated private key local and never commit it.

## 1. Run the existing tests

From the repository root:

```sh
python -m unittest -v test_factorisation.py
```

The tests exercise the actual implementations of Miller–Rabin, Fermat, Pollard p−1, ECM stage one, Pollard–Brent, and the configured input-size boundary. The fixtures are controlled integers; they validate algorithm paths, not performance against balanced RSA-2048.

## 2. Check a known composite

```sh
python Main 3233
```

Expected output:

```text
3233 = 53 * 61
Verification: True
```

## 3. Generate a local RSA-2048 key pair

Requires OpenSSL and Python 3.8 or later. These commands create a local key pair and extract only the public modulus as a decimal integer:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048-lab-private.pem
openssl pkey -in rsa2048-lab-private.pem -pubout -out rsa2048-lab-public.pem
openssl rsa -pubin -in rsa2048-lab-public.pem -modulus -noout \
  | sed 's/^Modulus=//' \
  | python -c 'import sys; print(int(sys.stdin.read().strip(), 16))' \
  > rsa2048-lab-modulus.txt
```

The private key is used only in the next local decryption exercise. Do not share it or commit it.

## 4. Encrypt and decrypt a message with RSA-OAEP

This uses the public key to encrypt a short local message and the matching private key to decrypt it. OpenSSL's `pkeyutl` supports RSA OAEP encryption and decryption; both commands use SHA-256 for OAEP and MGF1.

```sh
printf 'Local RSA-OAEP lab message\n' > rsa2048-lab-message.txt

openssl pkeyutl -encrypt -pubin -inkey rsa2048-lab-public.pem \
  -in rsa2048-lab-message.txt -out rsa2048-lab-ciphertext.bin \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

openssl pkeyutl -decrypt -inkey rsa2048-lab-private.pem \
  -in rsa2048-lab-ciphertext.bin -out rsa2048-lab-decrypted.txt \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

cmp rsa2048-lab-message.txt rsa2048-lab-decrypted.txt
```

A zero exit status from `cmp` means the decrypted bytes match the original. This is genuine RSA-2048 OAEP decryption using the lab private key. It is independent of factorisation.

## 5. Try the factoriser on the local public modulus

```sh
python Main "$(cat rsa2048-lab-modulus.txt)" --seconds 10
```

For a properly generated balanced key, the expected result is a time-budget error. The program accepts the full-size modulus, but its current algorithms and bounds do not practically factor an ordinary RSA-2048 key. This is one experiment, not proof about every possible modulus.

## 6. Study why specially structured inputs differ

The methods have different favorable conditions:

- **Fermat:** factors that are unusually close together.
- **Pollard p−1:** a factor whose predecessor has a sufficiently smooth factorisation within the chosen stage-one bound.
- **ECM stage one:** composites with a factor small enough for the selected curve bound.
- **Pollard–Brent:** general-purpose small-factor search whose work grows rapidly with the size of the smallest factor.

Use the existing test fixtures to observe each method under a controlled condition. Change one parameter at a time, record the input, seed, setting, elapsed time, and whether the product check passes. A seeded run is for experiment replay only, not key generation.

## 7. Interpret results correctly

- A 2056-bit default input ceiling describes accepted input size, not factoring capability.
- Factors above 64 bits are probable primes according to Miller–Rabin; they are not formally proven prime by this program.
- A timeout is inconclusive for that input and budget. It is not evidence that a key is secure.
- The factorisation CLI does not parse PEM keys, derive RSA private keys, or decrypt ciphertexts. The OAEP exercise above uses the private key generated for the lab.
- The implementation has no network functionality and does not include GNFS or a production-optimized ECM engine.

## Suggested lab record

| Field | Example |
|---|---|
| Input source | Locally generated RSA key or controlled fixture |
| Modulus bit length | 2048 |
| Experiment | OAEP decrypt or factorisation attempt |
| Factor structure | Known from lab construction, or unknown |
| Time budget and algorithm bounds | Defaults or explicit values |
| Seed | Integer seed, or “system random” |
| Outcome | Plaintext matched, factors found, timeout, or validation error |
| Product verification | True/false, when factors are returned |
| Interpretation | What this experiment shows and what it does not show |
