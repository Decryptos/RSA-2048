# Private Railway RSA runtime — Decrypto

This deployment serves only an HTTP readiness endpoint at `/healthz`.
It contains the real offline RSA factorisation engine (`Main`), the
interactive Decrypto workbench, and its existing offline laboratory modules.

- The startup checks factorisation of the known small control 3233,
  an ephemeral RSA-2048 OAEP round trip, and rejection of modified ciphertext.
  They are functional checks, **not** private-key recovery from an ordinary RSA-2048 key.
- Only `GET /healthz` and `HEAD /healthz` return 200; this is **not** a
  remotely callable factorisation or decryption API.
- Keep Railway service domains and TCP proxies **disabled**. Access labs over
  Railway's authenticated SSH facility:
  `python /app/decrypto.py`
  or `python /app/Main 3233 --seconds 2`.
- Never enter private keys or recovered private material into CI logs or
  public issues. Do not enable an external scanning task from this container.
- Runtime dependencies are pinned in `requirements-cloud.txt`. Upgrading
  requires CI and private deployment verification.
- The application container is ephemeral; its normal output should contain
  no private-key or plaintext material. It exposes no results storage.
- Local validation: `python -m unittest discover -v` and
  `python -m unittest -v test_railway_health.py`.
