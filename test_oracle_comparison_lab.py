"""Regression tests for the offline RSA oracle comparison."""
import unittest
from oracle_comparison_lab import run_comparison


class OracleComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_comparison(2048, trials=8)

    def test_raw_oracle_plaintext_recovery(self):
        self.assertTrue(self.result["raw_plaintext_recovered"])
        self.assertEqual(self.result["raw_oracle_queries"], 1)

    def test_synthetic_boundary_oracle(self):
        self.assertTrue(self.result["boundary_below"])
        self.assertFalse(self.result["boundary_at"])
        self.assertTrue(self.result["boundary_distinguishable"])
        self.assertFalse(self.result["manger_plaintext_recovered"])

    def test_oaep_rejects_modified_ciphertexts(self):
        self.assertTrue(self.result["oaep_valid_decryption"])
        self.assertEqual(self.result["oaep_modified_rejected"], 8)
        self.assertEqual(self.result["oaep_modified_total"], 8)
        self.assertFalse(self.result["timing_resistance_tested"])

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            run_comparison(1024)
        with self.assertRaises(ValueError):
            run_comparison(2048, trials=0)


if __name__ == "__main__":
    unittest.main()
