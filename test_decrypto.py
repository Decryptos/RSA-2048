import contextlib
import io
import unittest
from unittest.mock import patch
import decrypto


class InteractiveTests(unittest.TestCase):
    def run_menu(self, answers):
        output = io.StringIO()
        with patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(output):
            self.assertEqual(decrypto.main([]), 0)
        return output.getvalue()

    def test_invalid_selection_then_exit(self):
        self.assertIn("Choose a listed number", self.run_menu(["invalid", "0"]))

    def test_factor_then_continue(self):
        text = self.run_menu(["1", "3233", "1", "0"])
        self.assertIn("Product verified", text)
        self.assertIn("53 * 61", text)

    def test_recover_and_decrypt_then_continue(self):
        text = self.run_menu(["2", "", "3233", "17", "3763", "1", "1", "2790", "0"])
        self.assertIn("Verified plaintext integer: 65", text)

    def test_bad_budget_returns_to_menu(self):
        self.assertIn("Operation failed", self.run_menu(["1", "3233", "nan", "0"]))

    def test_end_of_input_exits_cleanly(self):
        output = io.StringIO()
        with patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(output):
            self.assertEqual(decrypto.main([]), 0)
        self.assertIn("Returned from workbench", output.getvalue())

    def test_saving_does_not_overwrite(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.bin"
            path.write_bytes(b"original")
            with patch("builtins.input", return_value=str(path)), self.assertRaises(FileExistsError):
                decrypto.write_new(b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
