"""Offline Fermat controls; run: python -m unittest -v test_fermat_controls

Requires cryptography. A bounded miss is inconclusive, not proof of security.
"""
import importlib.machinery
import math
from pathlib import Path
import time
import unittest
from cryptography.hazmat.primitives.asymmetric import rsa

from factor_engine import load_engine
main = load_engine()


class FermatControls(unittest.TestCase):
    def test_close_prime_positive_control(self):
        n = 1009 * 1013
        factor = main.fermat_factor(n, 1000, time.monotonic() + 5)
        self.assertTrue(factor and 1 < factor < n and n % factor == 0)

    def test_normal_rsa_bounded_observation(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = key.public_key().public_numbers().n
        result = main.fermat_factor(n, 1000, time.monotonic() + 5)
        if result is not None:
            self.assertTrue(1 < result < n and n % result == 0)
            print("Normal-key control: factor verified within 1,000 steps.")
        else:
            print("Normal-key control: no factor in 1,000 steps; inconclusive.")
        self.assertEqual(n.bit_length(), 2048)


if __name__ == "__main__":
    unittest.main(verbosity=2)
