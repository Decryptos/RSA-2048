import unittest
from rsa_recovery import recover, wiener, shared_factor, roca_fingerprint


class RecoveryTests(unittest.TestCase):
    def test_roca_subgroup_screen_is_not_factorisation(self):
        # Algebraic positive: power of 65537, intentionally NOT an RSA key.
        self.assertTrue(roca_fingerprint(65537 ** 17))
        self.assertFalse(roca_fingerprint(3 * 5))
    def test_wiener_factors_verified(self):
        p, q, d = 1009, 1013, 5
        e = pow(d, -1, (p - 1) * (q - 1))
        self.assertEqual(set(wiener(p * q, e)), {p, q})

    def test_normal_public_exponent_is_not_a_small_d_result(self):
        self.assertIsNone(wiener(1009 * 1013, 65537))

    def test_shared_factor_and_negative_controls(self):
        self.assertEqual(shared_factor(53 * 61, 53 * 71), (53, 61))
        self.assertIsNone(shared_factor(53 * 61, 67 * 71))
        self.assertIsNone(shared_factor(53 * 61, 53 * 61))

    def test_real_integer_decryption_after_recovery(self):
        key = recover(3233, 17, seconds=1, peer_n=53 * 71)
        self.assertEqual(key["status"], "recovered")
        self.assertEqual(pow(2790, key["d"], key["n"]), 65)

    def test_rejects_invalid_budgets_and_exponent(self):
        for seconds in (0, -1, float("nan"), float("inf"), 61):
            with self.assertRaises(ValueError):
                recover(3233, 17, seconds)
        with self.assertRaises(ValueError):
            wiener(3233, 1)
