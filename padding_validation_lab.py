"""Local PKCS#7 validation and error-disclosure experiment.

Requires the cryptography package. Run: python padding_validation_lab.py
All examples use fixed, locally constructed input; no network or oracle attack.
"""
from cryptography.hazmat.primitives import padding


def validate(payload):
    unpadder = padding.PKCS7(128).unpadder()
    try:
        message = unpadder.update(payload) + unpadder.finalize()
    except ValueError:
        return "padding_error"
    if message != b"HELLO":
        return "message_error"
    return "accepted"


def uniform(payload):
    return "accepted" if validate(payload) == "accepted" else "invalid"


def main():
    valid = b"HELLO" + bytes([11]) * 11
    bad_padding = b"HELLO" + bytes([11]) * 10 + bytes([0])
    bad_message = b"WORLD" + bytes([11]) * 11
    assert validate(valid) == "accepted"
    assert validate(bad_padding) == "padding_error"
    assert validate(bad_message) == "message_error"
    assert uniform(valid) == "accepted"
    assert uniform(bad_padding) == uniform(bad_message) == "invalid"
    print("Real PKCS#7 validation: valid input accepted")
    print("Distinct error messages distinguish padding and message failures")
    print("Uniform error messages match for both invalid inputs")
    print("Local illustration only: no timing analysis or live-service test")
    print("Uniform error text alone does not prove absence of an oracle.")


if __name__ == "__main__":
    main()
