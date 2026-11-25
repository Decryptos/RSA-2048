import datetime
import unittest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from decrypto_crypto import parse_rsa_public, decrypt_oaep, oaep, recovered_key
from aead_validation_lab import run_lab


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_key_and_certificate_pem_der(self):
        public = self.key.public_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline lab")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(public).serial_number(1).not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1)).sign(self.key, hashes.SHA256()))
        for encoding in (serialization.Encoding.PEM, serialization.Encoding.DER):
            for blob in (public.public_bytes(encoding, serialization.PublicFormat.SubjectPublicKeyInfo),
                         cert.public_bytes(encoding)):
                self.assertEqual(parse_rsa_public(blob).public_numbers(), public.public_numbers())

    def test_oaep_decrypt_wrong_key_and_modified_ciphertext(self):
        ciphertext = self.key.public_key().encrypt(b"actual message", oaep())
        self.assertEqual(decrypt_oaep(self.key, ciphertext), b"actual message")
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for key, data in ((other, ciphertext), (self.key, ciphertext[:-1]),
                          (self.key, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))):
            with self.assertRaises(ValueError):
                decrypt_oaep(key, data)

    def test_recovered_private_key_decrypts_oaep(self):
        # Test reconstruction using known local factors, not an attack claim.
        private = self.key.private_numbers()
        result = dict(status="recovered", p=private.p, q=private.q, d=private.d,
                      n=private.public_numbers.n, e=private.public_numbers.e)
        ciphertext = self.key.public_key().encrypt(b"recovered key path", oaep())
        self.assertEqual(decrypt_oaep(recovered_key(result), ciphertext), b"recovered key path")

    def test_rejects_invalid_and_non_rsa_keys(self):
        with self.assertRaises(ValueError):
            parse_rsa_public(b"invalid")
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(ValueError):
            parse_rsa_public(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def test_empty_and_nonempty_aead_controls(self):
        rows = run_lab()
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertTrue(row["roundtrip"])
            self.assertTrue(row["altered_tag_rejected"])
            self.assertTrue(row["wrong_aad_rejected"])
