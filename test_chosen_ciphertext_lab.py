"""Regression tests for synthetic textbook RSA chosen-ciphertext lab."""
import unittest

import chosen_ciphertext_lab as lab


class ChosenCiphertextLabTests(unittest.TestCase):
    def test_exact_known_vectors(self):
        result = lab.run_demo()
        self.assertEqual(result["ciphertext"], 2790)
        self.assertEqual(result["modified_ciphertext"], 1258)
        self.assertEqual(result["oracle_response"], 455)
        self.assertEqual(result["recovered_plaintext"], 65)
        self.assertTrue(result["verified"])

    def test_invertible_blinding_required(self):
        ciphertext = pow(65, lab.E, lab.N)
        with self.assertRaises(ValueError):
            lab.recover_plaintext_from_oracle(
                ciphertext, lab.N, lab.E, lab.simulated_raw_rsa_oracle, 53
            )

    def test_oracle_must_return_raw_integer(self):
        ciphertext = pow(65, lab.E, lab.N)
        with self.assertRaises(ValueError):
            lab.recover_plaintext_from_oracle(
                ciphertext, lab.N, lab.E, lambda _: None, lab.R
            )

    def test_incorrect_oracle_response_is_rejected(self):
        ciphertext = pow(65, lab.E, lab.N)
        with self.assertRaises(ValueError):
            lab.recover_plaintext_from_oracle(
                ciphertext, lab.N, lab.E, lambda _: 1, lab.R
            )


if __name__ == "__main__":
    unittest.main()
