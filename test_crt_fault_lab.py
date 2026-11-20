import unittest
from crt_fault_lab import experiment

class CRTFaultTests(unittest.TestCase):
    def test_2048(self):
        result = experiment(2048)
        for field in ('valid_signature_verified', 'faulty_signature_failed_verification',
                      'factor_recovered', 'factor_product_verified',
                      'private_exponent_reconstructed', 'recovered_key_decryption_verified',
                      'defensive_fault_rejected'):
            self.assertTrue(result[field], field)

if __name__ == '__main__':
    unittest.main()
