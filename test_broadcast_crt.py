"""Regression test for the fixed offline RSA broadcast demonstration."""
import contextlib
import importlib.machinery
import io
import math
from pathlib import Path
import unittest

main = importlib.machinery.SourceFileLoader(
    "rsa_lab_main", str(Path(__file__).with_name("Main"))
).load_module()


class BroadcastCRTTests(unittest.TestCase):
    def test_fixed_broadcast_demonstration(self):
        moduli = (101 * 113, 107 * 131, 137 * 149)
        ciphertexts = (5610, 4003, 12849)
        self.assertTrue(all(
            math.gcd(moduli[i], moduli[j]) == 1
            for i in range(3) for j in range(i + 1, 3)
        ))
        combined = 74088
        self.assertTrue(all(combined % n == c for n, c in zip(moduli, ciphertexts)))
        self.assertEqual(combined, 42 ** 3)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(main.broadcast_lab_demo())


if __name__ == "__main__":
    unittest.main()
