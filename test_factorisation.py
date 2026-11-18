"""Safe boundary tests for the factorisation CLI."""
import importlib.machinery
import importlib.util
import math
import sys
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


if __name__ == "__main__":
    unittest.main()
