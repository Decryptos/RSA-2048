#!/usr/bin/env python3
"""Interactive offline cryptography workbench. Run: python decrypto.py"""
import argparse
import getpass
import json
import math
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
LABS = {
    "broadcast": ("Main", "--broadcast-lab"),
    "wiener": ("Main", "--wiener-lab"),
    "oracle": ("chosen_ciphertext_lab.py",),
    "fault": ("crt_fault_lab.py",),
    "comparison": ("oracle_comparison_lab.py",),
    "integrity": ("aes_integrity_lab.py",),
    "nonce": ("nonce_reuse_lab.py",),
    "aead": ("aead_validation_lab.py",),
}


def integer(prompt, default=None, low=2, high_bits=8192):
    raw = input(prompt).strip()
    value = default if not raw and default is not None else int(raw)
    if value < low or value.bit_length() > high_bits:
        raise ValueError(f"Require integer >= {low}, at most {high_bits} bits")
    return value


def budget():
    value = float(input("Time budget in seconds [5], maximum 60: ").strip() or "5")
    if not math.isfinite(value) or not 0 < value <= 60:
        raise ValueError("Time budget must be finite and between 0 and 60 seconds")
    return value


def run_lab(name):
    if name == "oaep":
        from decrypto_crypto import known_key_demo
        print(json.dumps(known_key_demo(), indent=2))
        return 0
    try:
        result = subprocess.run([sys.executable, str(ROOT / LABS[name][0]), *LABS[name][1:]],
                                cwd=ROOT, timeout=120, check=False)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("Experiment stopped after 120 seconds; result is inconclusive.")
        return 2


def write_new(data):
    path = input("New output file path (blank cancels): ").strip()
    if path:
        with Path(path).expanduser().open("xb") as output:
            output.write(data)
        print("Saved:", path)


def decrypt_with_key():
    from cryptography.hazmat.primitives import serialization
    from decrypto_crypto import decrypt_oaep
    data = Path(input("Local private-key PEM path: ").strip()).expanduser().read_bytes()
    password = getpass.getpass("Key passphrase (blank for unencrypted key): ")
    key = serialization.load_pem_private_key(data, password.encode() if password else None)
    ciphertext = Path(input("Ciphertext file path (raw binary): ").strip()).expanduser().read_bytes()
    plaintext = decrypt_oaep(key, ciphertext)
    print(f"OAEP-SHA256 decryption succeeded: {len(plaintext)} bytes. Label: empty.")
    write_new(plaintext)


def inspect_key():
    from decrypto_crypto import parse_rsa_public
    from rsa_recovery import roca_fingerprint
    key = parse_rsa_public(Path(input("RSA public key or certificate path (PEM/DER): ").strip()).expanduser().read_bytes())
    values = key.public_numbers()
    print(f"RSA modulus: {key.key_size} bits\nExponent: {values.e}\nModulus n: {values.n}")
    print("Parsing a certificate does not validate its issuer, trust chain or expiration.")
    print("ROCA subgroup fingerprint:", "MATCH (screening only)" if roca_fingerprint(values.n) else "no match")
    print("A fingerprint match needs confirmation with the vendor's official detector; no ROCA factoring is performed.")


def recovery():
    from rsa_recovery import recover
    path = input("Public key/certificate path, or blank to enter decimal n/e: ").strip()
    if path:
        from decrypto_crypto import parse_rsa_public
        numbers = parse_rsa_public(Path(path).expanduser().read_bytes()).public_numbers()
        n, e = numbers.n, numbers.e
    else:
        n = integer("RSA modulus n [3233]: ", 3233)
        e = integer("Public exponent e [17]: ", 17)
    peer = input("Optional peer modulus for shared-prime GCD (decimal, blank skips): ").strip()
    peer_n = int(peer) if peer else None
    if peer_n is not None and (peer_n < 4 or peer_n.bit_length() > 8192):
        raise ValueError("Peer modulus must be >=4 and <=8192 bits")
    result = recover(n, e, budget(), peer_n)
    print("Result:", result["status"], "| Method:", result["method"])
    if result["status"] != "recovered":
        print(result["reason"], "A miss is inconclusive.")
        return
    print("Two distinct factors and private operation verified. Secret numbers remain in memory.")
    action = input("Decrypt [1] textbook integer, [2] OAEP-SHA256 binary file, [Enter] return: ").strip()
    if action == "1":
        ciphertext = integer("Ciphertext integer: ", low=0)
        if ciphertext >= n:
            raise ValueError("Ciphertext integer must be less than n")
        message = pow(ciphertext, result["d"], n)
        if pow(message, e, n) != ciphertext:
            raise ValueError("Plaintext failed re-encryption check")
        print("Verified plaintext integer:", message)
        print("Textbook RSA only; no padding was removed.")
    elif action == "2":
        from decrypto_crypto import recovered_key, decrypt_oaep
        ciphertext = Path(input("Ciphertext binary file: ").strip()).expanduser().read_bytes()
        plaintext = decrypt_oaep(recovered_key(result), ciphertext)
        print(f"Decrypted {len(plaintext)} bytes with the recovered key.")
        write_new(plaintext)
    elif action:
        raise ValueError("Choose 1, 2 or Enter")


def factor_number():
    from factor_engine import load_engine
    n = integer("Integer to factor [3233]: ", 3233)
    seconds = budget()
    engine = load_engine()
    try:
        parts = engine.factor(n, seconds=seconds, max_bits=8192)
    except engine.FactorisationTimeout:
        print("Budget exhausted: inconclusive.")
        return
    if math.prod(parts) != n:
        raise ValueError("Factor product verification failed")
    print("Factors:", " * ".join(str(v) for v in parts))
    print("Product verified. Factors above 64 bits have probable-prime checks only.")


def menu():
    actions = {
        "1": ("Factor an integer with a bounded budget", factor_number),
        "2": ("Recover a weak RSA key and decrypt", recovery),
        "3": ("Decrypt RSA-OAEP with your private key", decrypt_with_key),
        "4": ("Inspect an RSA key or X.509 certificate", inspect_key),
        "5": ("RSA-OAEP local key round trip", lambda: run_lab("oaep")),
        "6": ("Small-d Wiener lab", lambda: run_lab("wiener")),
        "7": ("Unpadded broadcast lab", lambda: run_lab("broadcast")),
        "8": ("Raw RSA oracle lab", lambda: run_lab("oracle")),
        "9": ("Synthetic CRT fault and defensive check", lambda: run_lab("fault")),
        "10": ("Raw oracle / boundary leak / OAEP comparison", lambda: run_lab("comparison")),
        "11": ("AES-CTR malleability / GCM integrity", lambda: run_lab("integrity")),
        "12": ("AES-CTR and ChaCha20 nonce reuse", lambda: run_lab("nonce")),
        "13": ("AEAD empty-message and invalid-tag controls", lambda: run_lab("aead")),
        "14": ("Read methods and prerequisites", lambda: print((ROOT / "DECRYPTION_METHODS.md").read_text(encoding="utf-8"))),
        "15": ("Read verified research and implementation status", lambda: print((ROOT / "RESEARCH_STATUS.md").read_text(encoding="utf-8"))),
    }
    print("DECRYPTO | Offline cryptography workbench")
    print("Use your own keys or explicitly authorised lab inputs. No network operations.")
    while True:
        print()
        for number, (label, _) in actions.items():
            print(f"{number:>2}. {label}")
        print(" 0. Exit")
        try:
            choice = input("Choice: ").strip().lower()
            if choice in ("0", "q", "quit", "exit"):
                return 0
            if choice not in actions:
                print("Choose a listed number.")
                continue
            actions[choice][1]()
        except (EOFError, KeyboardInterrupt):
            print("\nReturned from workbench.")
            return 0
        except ImportError as exc:
            print(f"Missing dependency: {exc}. Install: python -m pip install -r requirements.txt")
        except (ValueError, OSError) as exc:
            print(f"Operation failed: {exc}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", choices=tuple(LABS) + ("oaep",), help="Run a named local lab without the menu")
    args = parser.parse_args(argv)
    return run_lab(args.lab) if args.lab else menu()


if __name__ == "__main__":
    raise SystemExit(main())
