# Research status - reviewed 25 November 2026

Implementation status is explicit. Published research results are not claims that
this repository reproduces the experiments or breaks ordinary RSA-2048.

| Requested technique | Implemented here | Prerequisite / limitation |
|---|---|---|
| Small private exponent | General Wiener continued-fraction recovery, beyond the old fixed demo | Deliberately small d; this is NOT the lattice attack near N^0.287 |
| N^0.287 lattice recovery | Research reference only | Li et al. report a 2048-bit experiment taking about a month. No tested lattice implementation is included |
| Cache timing / partial-prime lattice recovery | Research reference only | Requires a vulnerable implementation and usable trace data; public n alone is insufficient |
| ROCA | Independent small-prime subgroup fingerprint screen | Match is not proof; confirm with official detector. No ROCA factoring engine |
| Fault injection | Existing synthetic CRT residue-fault lab integrated in menu | Not physical HSM modulus replacement; no hardware access or fault injector |
| September 2026 signature forgery | Research reference only; existing raw-RSA oracle lab is separate | Paper uses a raw oracle, 2^32 queries and 1380 core-years; no SNFS implementation or private-key extraction claim |
| AES / ChaCha20 failures | Actual nonce-reuse and integrity controls | Synthetic local fixtures; no full-round mathematical break |
| Empty AEAD ciphertext | High-level API regression for AES-GCM and ChaCha20-Poly1305 | Not a reproduction or audit of OpenSSL EVP_Cipher CVE-2026-75803 |
| ECDSA / DSA nonce reuse, DH downgrades | Catalogue only | No curve/discrete-log or protocol attack implementation |
| ML-KEM / ML-DSA / SLH-DSA / FN-DSA / HAWK | Catalogue only | No post-quantum implementation or key-recovery engine |
| MD5 / SHA-1 / SHA-2 / SHA-3 / BLAKE | Catalogue only | Hashes are not encryption; no general preimage recovery |

## Verified sources and corrections

- [Li et al., 2023](https://doi.org/10.1007/s10623-023-01295-5): practical small-d results under special key parameters. Wiener has a narrower range and must not be described as reproducing this result.
- [Cache-Timing Attacks on RSA Key Generation](https://researchportal.tuni.fi/en/publications/cache-timing-attacks-on-rsa-key-generation/): empirical roughly 27% success after collecting and processing side-channel traces; not a public-key-only break.
- [Original ROCA researchers](https://crocs.fi.muni.cz/public/papers/rsa_ccs17): hardware-library prime structure; original costs for affected 2048-bit keys were measured in CPU-years, not generally minutes. Official offline detector: https://github.com/crocs-muni/roca.
- [Shea et al., 2026](https://opencryptology.org/2026/2131): 1024-bit raw-oracle signature forgery, not general RSA decryption or private-key recovery.
- [Red Hat CVE-2026-75803 advisory](https://access.redhat.com/security/cve/cve-2026-75803): narrow empty-ciphertext EVP_Cipher API conditions; standard TLS and typical EVP_Decrypt workflows are unaffected according to the advisory.
- [Anthropic's report](https://www.anthropic.com/research/discovering-cryptographic-weaknesses): published 28 July 2026, not October. HAWK and reduced-round AES results do not imply full AES or standardized PQC are broken.
- [NIST IR 8547 final, October 2026](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf): federal high-value/high-impact system deadlines are 31 December 2030 for key establishment and 31 December 2031 for signatures; quantum-vulnerable public-key algorithms are deprecated after 2030 and disallowed under NIST standards after 2035. These dates are policy scope, not mathematical expiry dates.

Other corrections: SHA-1 collisions attack the hash used in a signature protocol,
not RSA factoring. SHA-1 does not have a general 112-bit preimage claim here.
ECDSA, EdDSA and DSA are signatures; DH/ECDH are key agreement. Shor attacks
factoring and discrete logs, not literally every asymmetric construction.
Quantum resource figures depend on the hardware/error-correction model.
Symmetric/hash algorithm approval is application- and standard-specific;
ChaCha20 and BLAKE are not automatically NIST-approved because they are widely used.
PQC key/signature sizes vary by parameter set (for example ML-KEM-1024 has a
1568-byte public key); a single size must not be assigned to an entire family.