"""Tests for the interactive public-key laboratory (local keys only)."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SPEC = importlib.util.spec_from_file_location("public_key_lab", Path(__file__).with_name("public_key_lab.py"))
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)

class PublicKeyLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_pem = cls.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def test_parse_public_pem(self):
        n, e = lab.parse_public_key(self.public_pem)
        self.assertEqual(n, self.private.public_key().public_numbers().n)
        self.assertEqual(e, 65537)

    def test_reject_non_pem_input(self):
        with self.assertRaises(ValueError):
            lab.parse_public_key(b"not a PEM key")

    def test_reconstruct_from_known_lab_factors(self):
        engine = lab.load_factoriser()
        private = self.private.private_numbers()
        recovered = lab.reconstruct_private_numbers(
            private.public_numbers.n, private.public_numbers.e, [private.p, private.q], engine)
        self.assertEqual(recovered.public_numbers.n, private.public_numbers.n)
        self.assertEqual(recovered.d * private.public_numbers.e % __import__("math").lcm(private.p-1, private.q-1), 1)

    def test_reject_incorrect_factors(self):
        engine = lab.load_factoriser()
        private = self.private.private_numbers()
        with self.assertRaises(ValueError):
            lab.reconstruct_private_numbers(private.public_numbers.n, 65537, [3, 7], engine)

    def test_skips_recovery_when_declined(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            key_path = Path(folder) / "public.pem"
            key_path.write_bytes(self.public_pem)
            p = self.private.private_numbers().p
            q = self.private.private_numbers().q
            with patch.object(lab, "load_factoriser") as mocked:
                mocked.return_value.factor.return_value = [p, q]
                self.assertEqual(lab.main(["--public-key", str(key_path)], input_fn=lambda _: "n"), 0)
                mocked.return_value.factor.assert_called_once()

if __name__ == "__main__":
    unittest.main()
