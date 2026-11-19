"""Offline RSA-OAEP validation controls.

Requires cryptography. Run: python -m unittest -v test_rsa_oaep_lab
Uses a newly generated local key. No network calls or external inputs.
"""
import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def oaep(label):
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=label
    )


class RSAOAEPControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.label = b"local-lab"
        cls.message = b"local RSA-OAEP control"
        cls.ciphertext = cls.key.public_key().encrypt(cls.message, oaep(cls.label))

    def test_valid_round_trip(self):
        self.assertEqual(self.key.decrypt(self.ciphertext, oaep(self.label)), self.message)

    def test_modified_ciphertext_rejected(self):
        altered = bytearray(self.ciphertext)
        altered[len(altered) // 2] ^= 1
        with self.assertRaises(ValueError):
            self.key.decrypt(bytes(altered), oaep(self.label))

    def test_wrong_label_rejected(self):
        with self.assertRaises(ValueError):
            self.key.decrypt(self.ciphertext, oaep(b"wrong-label"))

    def test_truncated_ciphertext_rejected(self):
        with self.assertRaises(ValueError):
            self.key.decrypt(self.ciphertext[:-1], oaep(self.label))


if __name__ == "__main__":
    unittest.main(verbosity=2)
