"""Offline tests for Buchanan-style configurable RSA generation."""
import contextlib
import io
import unittest
from unittest.mock import patch

import rsa_keygen_lab as lab


class RSAKeyGenerationLabTests(unittest.TestCase):
    def test_supported_sizes(self):
        self.assertEqual(lab.SUPPORTED_SIZES, (2048, 3072, 4096))
        for bits in lab.SUPPORTED_SIZES:
            self.assertEqual(lab.generate_key_numbers.__name__, "generate_key_numbers")
            self.assertEqual(bits // 2 * 2, bits)

    def test_rejects_unapproved_bits(self):
        with self.assertRaises(ValueError):
            lab.generate_key_numbers(1024)

    def test_roundtrip_and_message_bound(self):
        # Small, known RSA example exercises the textbook arithmetic only.
        p, q, e = 61, 53, 17
        n = p * q
        d = pow(e, -1, (p - 1) * (q - 1))
        ciphertext, plain = lab.textbook_roundtrip("A", n, e, d)
        self.assertEqual(plain, "A")
        self.assertEqual(pow(ciphertext, d, n), ord("A"))
        with self.assertRaises(ValueError):
            lab.textbook_roundtrip("Hello", n, e, d)

    def test_key_generation_default_2048(self):
        p, q, n, e, d = lab.generate_key_numbers(2048)
        self.assertNotEqual(p, q)
        self.assertEqual(p.bit_length(), 1024)
        self.assertEqual(q.bit_length(), 1024)
        self.assertEqual(n.bit_length(), 2048)
        self.assertEqual(p * q, n)
        self.assertEqual((e * d) % ((p-1)*(q-1)), 1)
        self.assertEqual(lab.textbook_roundtrip("Hello", n, e, d)[1], "Hello")

    def test_command_line_defaults_and_hide_private(self):
        numbers = (61, 53, 3233, 17, 2753)
        with patch.object(lab, "generate_key_numbers", return_value=numbers), contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(lab.main(["A", "2048"]), 0)
        output = stream.getvalue()
        self.assertIn("Verified: True", output)
        self.assertNotIn("Private exponent d: ", output)
        self.assertIn("hidden", output)

    def test_print_private_only_when_requested(self):
        numbers = (61, 53, 3233, 17, 2753)
        with patch.object(lab, "generate_key_numbers", return_value=numbers), contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(lab.main(["A", "2048", "--show-private"]), 0)
        self.assertIn("Private exponent d: 2753", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
