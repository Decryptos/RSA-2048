#!/usr/bin/env python3
"""Private health-only service for Decrypto's offline RSA workbench.

The HTTP handler never accepts keys, ciphertexts, targets, or commands.
Run the interactive labs separately over an authenticated Railway SSH session.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib
import json
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from decrypto_crypto import decrypt_oaep, oaep
from factor_engine import load_engine


def run_checks():
    """Check that the actual workbench and crypto engine are installed and usable."""
    for module in ("decrypto", "rsa_public_key_menu", "rsa_recovery",
                   "crt_fault_lab", "oracle_comparison_lab", "nonce_reuse_lab"):
        importlib.import_module(module)

    engine = load_engine()
    factors = engine.factor(3233, seconds=2, seed=42)
    if factors != [53, 61]:
        raise RuntimeError("RSA factorisation self-check failed")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    message = b"Decrypto private startup self-test"
    encrypted = key.public_key().encrypt(message, oaep())
    if decrypt_oaep(key, encrypted) != message:
        raise RuntimeError("RSA OAEP self-check failed")
    damaged = bytearray(encrypted)
    damaged[0] ^= 1
    try:
        decrypt_oaep(key, bytes(damaged))
    except ValueError:
        pass
    else:
        raise RuntimeError("Tampered RSA OAEP ciphertext was accepted")

    return {"status": "ok", "scope": "offline RSA laboratory", "tests": 3}


class HealthHandler(BaseHTTPRequestHandler):
    """Minimal status surface: no crypto operations are exposed over HTTP."""
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        payload = json.dumps({"status": "ok"}).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, *_args):
        pass  # Do not log untrusted paths or request metadata.


def main():
    status = run_checks()  # Crash loudly rather than falsely appearing healthy.
    port = int(os.environ.get("PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid PORT")
    print("Decrypto RSA local checks passed: factorisation, OAEP, tamper rejection.", flush=True)
    print("Private health service ready; no crypto API or automated scanning enabled.", flush=True)
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
