"""Safe tests for the factorisation CLI and its bounded algorithms."""
import importlib.machinery
import importlib.util
import math
import random
import sys
import time
import unittest
from pathlib import Path

main_path = Path(__file__).with_name("Main")
loader = importlib.machinery.SourceFileLoader("factorisation_main", str(main_path))
spec = importlib.util.spec_from_loader(loader.name, loader)
main = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = main
loader.exec_module(main)


class Synthetic2048BitBoundaryTests(unittest.TestCase):
    def test_accepts_2048_bit_input_and_preserves_product(self):
        # Synthetic boundary case with trivial factors; not a real RSA modulus.
        number = 1 << 2047
        self.assertEqual(number.bit_length(), 2048)

        factors = main.factor(number, seconds=2, max_bits=2056)

        self.assertEqual(factors, [2] * 2047)
        self.assertEqual(math.prod(factors), number)

    def test_rejects_input_above_configured_bit_limit(self):
        number = 1 << 2047
        with self.assertRaises(ValueError):
            main.factor(number, seconds=2, max_bits=2047)


class FactorFindingMethodTests(unittest.TestCase):
    def assert_nontrivial_factor(self, number, divisor):
        self.assertIsNotNone(divisor)
        self.assertGreater(divisor, 1)
        self.assertLess(divisor, number)
        self.assertEqual(number % divisor, 0)

    def test_miller_rabin_accepts_large_probable_prime_and_rejects_composite(self):
        self.assertTrue(main.is_probable_prime(2**127 - 1, rng=random.Random(1234)))
        self.assertFalse(main.is_probable_prime(1009 * 1013))

    def test_fermat_finds_close_factors(self):
        number = 101 * 103
        divisor = main.fermat_factor(number, 10, time.monotonic() + 5)
        self.assert_nontrivial_factor(number, divisor)

    def test_pollard_pm1_finds_factor_with_smooth_predecessor(self):
        number = 101 * 227
        divisor = main.pollard_pm1(number, 100, time.monotonic() + 5)
        self.assert_nontrivial_factor(number, divisor)

    def test_ecm_stage_one_finds_small_factor(self):
        number = 101 * 227
        divisor = main.ecm_stage1(
            number, 200, 100, time.monotonic() + 5, random.Random(1234)
        )
        self.assert_nontrivial_factor(number, divisor)

    def test_pollard_brent_finds_factor(self):
        number = 1009 * 1013
        divisor = main.pollard_brent(
            number, time.monotonic() + 5, random.Random(42)
        )
        self.assert_nontrivial_factor(number, divisor)


if __name__ == "__main__":
    unittest.main()
