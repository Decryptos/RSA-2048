import unittest
from nonce_reuse_lab import run_lab, xor_equal, encrypt


class NonceReuseTests(unittest.TestCase):
    def test_recovery_requires_repeated_keystream(self):
        for kind in ("aes-ctr", "chacha20"):
            with self.subTest(kind=kind):
                result = run_lab(kind)
                self.assertTrue(result["reused_nonce_recovery"])
                self.assertFalse(result["fresh_nonce_recovery"])
                self.assertFalse(result["key_recovered"])
                self.assertEqual(result["recovered_plaintext"], "other message 02")

    def test_rejects_truncated_evidence(self):
        with self.assertRaises(ValueError):
            xor_equal(b"a", b"ab")

    def test_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            encrypt("unknown", bytes(32), bytes(16), b"message")
