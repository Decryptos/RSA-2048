"""Decrypto: isolated RSA-CRT fault to RSA-PSS authentication regression.

No network activity. Uses freshly generated local keys and an injected synthetic fault.
"""
import unittest
from math import gcd, lcm
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

class CRTAuthenticationTests(unittest.TestCase):
    def test_crt_recovery_and_pss_authentication(self):
        original = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        values = original.private_numbers()
        p, q, d = values.p, values.q, values.d
        n, e = values.public_numbers.n, values.public_numbers.e
        m = int.from_bytes(b'Decrypto isolated CRT fault lab', 'big')
        sp, sq = pow(m, d % (p-1), p), pow(m, d % (q-1), q)
        def combine(a,b):
            return (b + q * (((a-b) * pow(q,-1,p)) % p)) % n
        good, bad = combine(sp,sq), combine((sp+1)%p,sq)
        self.assertEqual(pow(good,e,n),m)
        self.assertNotEqual(pow(bad,e,n),m)
        factor = gcd((pow(bad,e,n)-m)%n,n)
        self.assertIn(factor,(p,q))
        other = n//factor
        self.assertEqual(factor*other,n)
        recovered_d = pow(e,-1,lcm(factor-1,other-1))
        rp,rq = max(factor,other),min(factor,other)
        reconstructed = rsa.RSAPrivateNumbers(
            p=rp,q=rq,d=recovered_d,dmp1=recovered_d%(rp-1),
            dmq1=recovered_d%(rq-1),iqmp=pow(rq,-1,rp),
            public_numbers=rsa.RSAPublicNumbers(e,n)).private_key()
        # Offline confidentiality impact: only the recovered key can decrypt OAEP.
        secret = b'Decrypto locally generated OAEP fixture'
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ciphertext = original.public_key().encrypt(secret, oaep)
        self.assertEqual(reconstructed.decrypt(ciphertext, oaep), secret)
        unrelated_decryptor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(ValueError):
            unrelated_decryptor.decrypt(ciphertext, oaep)
        challenge = b'local-auth-challenge:decrypto:nonce-0001'
        scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH)
        signature = reconstructed.sign(challenge,scheme,hashes.SHA256())
        original.public_key().verify(signature,challenge,scheme,hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            original.public_key().verify(signature,challenge+b'tampered',scheme,hashes.SHA256())
        unrelated = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with self.assertRaises(InvalidSignature):
            unrelated.public_key().verify(signature,challenge,scheme,hashes.SHA256())
        def guarded_output(a,b):
            s=combine(a,b)
            if pow(s,e,n)!=m:
                raise ValueError('fault detected before release')
            return s
        self.assertEqual(guarded_output(sp,sq),good)
        with self.assertRaises(ValueError):
            guarded_output((sp+1)%p,sq)

if __name__=='__main__':
    unittest.main(verbosity=2)
