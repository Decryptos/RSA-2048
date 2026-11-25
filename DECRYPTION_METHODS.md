# Decrypto: decryption and cryptanalysis map

Maintainer: Decrypto. Offline education and explicitly authorised assessment.
This is a map of major families, not an exhaustive implementation of all
encryption. No universal decryption algorithm is known for properly implemented
modern cryptography without the required secrets. A failed bounded experiment
is inconclusive, not a security proof.

## Choose a path from the evidence

First identify the exact algorithm, mode, padding, container, key derivation,
nonce/IV, authentication tag and associated data. A byte string alone rarely
identifies these reliably. Preserve the original input. Prefer legitimate key
recovery from backups or the owner before attempting cryptanalysis.

| Family | Normal decryption | Conditional recovery or weakness | Repository coverage |
|---|---|---|---|
| RSA | Private key and matching OAEP/hash/label | Small factors, close primes (Fermat), smooth p-1, shared factors (GCD), low-exponent unpadded messages, broadcast/common-modulus misuse | Bounded engine in `Main`; OAEP in `LAB_GUIDE.md`; broadcast regression exists; other listed methods are not all implemented |
| RSA oracle/fault misuse | Private-key operation through a correct protocol | Raw decryption oracle allows unblinding; a faulty CRT signature can expose a factor; padding oracles require a specific observable leak | `chosen_ciphertext_lab.py`, `crt_fault_lab.py`, `oracle_comparison_lab.py`; boundary classifier is not a full Manger attack |
| AES-CTR / raw ChaCha20 | Secret key and exact nonce/counter | Reused keystream gives C1 XOR C2 = P1 XOR P2; known P1 reveals the overlapping bytes of P2, not the key | `nonce_reuse_lab.py`, including fresh-nonce controls |
| AES-GCM / ChaCha20-Poly1305 | Key, nonce, tag and matching associated data | Nonce reuse compromises confidentiality and can compromise authentication; details depend on construction and observations | Existing AES integrity lab; no general GCM/Poly1305 forgery implementation |
| AES-CBC | Key, IV and correct padding | Malleability without authentication; adaptive padding oracle only where a padding-validity leak exists | Catalogue only; no external oracle client |
| AES-ECB | Key and block/padding convention | Equal plaintext blocks expose patterns; this alone does not reveal arbitrary plaintext or the key | Catalogue only |
| DES / 3DES / RC4 | Correct legacy key and parameters | DES key space is small; 64-bit block modes have volume limits; RC4 has statistical biases | Catalogue only; these are different weaknesses, not one decryption method |
| DH / ECDH / ElGamal / ECIES | Private scalar/exponent, valid peer key and matching KDF/symmetric layer | Small toy groups permit discrete-log searches; invalid-curve or subgroup attacks require validation flaws and an oracle | Catalogue only; DH/ECDH are key agreement, not message encryption |
| Password-encrypted files | Password, salt, KDF parameters and format | Offline password guessing if the password is weak and guesses can be verified; cost depends on KDF | Catalogue only; no password recovery engine |
| Hybrid TLS / PGP / encrypted archives | Relevant session/content key plus correct format | Compromised endpoints or keys may expose data; forward-secret TLS is not decrypted merely by obtaining the certificate private key | Catalogue only; no capture collection |
| Classical substitution / Caesar / Vigenere | Historical key or inverse transformation | Exhaustive shifts, frequency analysis and period analysis; short samples may remain ambiguous | Catalogue only |
| One-time pad | Truly random secret pad of sufficient length | Reused pad has the XOR failure above; correctly used OTP is information-theoretically secret | Algebraic relationship only; no OTP implementation |
| Post-quantum KEM / hybrid KEM | Secret decapsulation key, ciphertext, specified KDF and symmetric data layer | Implementation defects must be demonstrated specifically; a KEM produces a shared secret rather than directly decrypting a document | Catalogue only; no general lattice-breaking claim |
| Hashes / Base64 | Hashes have no decryption; Base64 is decoded | Guessing a hash preimage differs from decryption; encoding provides no secrecy | Classification only |

## Reproduce the added lab

Install the existing dependency `cryptography`, then run:

```sh
python nonce_reuse_lab.py
python -m unittest -v test_nonce_reuse_lab.py
python -m unittest discover -v
```

Both cipher fixtures should recover `other message 02` with nonce reuse and
fail to recover it using the fresh-nonce control. Recovery is limited to the
known-plaintext overlap and does not recover either cipher's secret key.
These are synthetic demonstrations, not findings in deployed systems.
The raw ChaCha20 API used here has a 64/64 counter/nonce layout; do not
confuse it with the IETF ChaCha20-Poly1305 wire format.

## Teaching sources and attribution

Bill Buchanan explains established cryptographic methods; credit for RSA,
Fermat factorisation and other algorithms remains with their original authors.
The added code is an independent implementation, not copied website code,
and does not imply Buchanan's endorsement or discovery of a new attack.

- Buchanan, [RSA: Step-by-Step](https://medium.com/asecuritysite-when-bob-met-alice/rsa-step-by-step-feaa97e20030): public introduction to RSA. Full article was subscription-limited during review.
- Buchanan, [Fermat's attack on RSA](https://medium.com/asecuritysite-when-bob-met-alice/after-nearly-50-years-rsa-is-still-in-the-news-femats-attack-on-rsa-7537dd90c974): close-prime premise verified in the publicly readable introduction; full method was subscription-limited.
- [ASecuritySite](https://asecuritysite.com/): Buchanan's teaching collection; direct page retrieval returned HTTP 403 during this review. Unread pages are not treated as verified implementations.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), especially security considerations: ChaCha20/Poly1305 construction and nonce-reuse requirements.
- [NIST SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A): block-cipher modes.
- [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D): GCM.
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017): RSA primitives and encryption schemes.

The catalogue distinguishes teaching references from executed evidence.
It contains no private research methodology or recovered real-world secrets.
