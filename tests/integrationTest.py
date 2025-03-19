import os
import sys
import logging
from datetime import datetime
from indiaMethodCipher import EnhancedIndiaMethodCipher, CipherType, KeyRotationPolicy, SecurityLevel

class CryptoPerformanceAnalysis:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='crypto_performance.log'
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        self.test_data_dir = "test_data"
        os.makedirs(self.test_data_dir, exist_ok=True)

    def generate_test_scenarios(self):
        return [
            {"name": "Small Compressed", "size": 1024, "cipher_type": CipherType.CHACHA20, "compress": True},
            {"name": "Medium Parallel", "size": 5 * 1024 * 1024, "cipher_type": CipherType.AES_GCM, "chunk_size": 1024*1024},
            {"name": "Large Adaptive", "size": 10 * 1024 * 1024, "cipher_type": CipherType.CHACHA20, "adaptive_security": True},
            {"name": "PQ Compressed", "size": 2048, "cipher_type": CipherType.KYBER, "pq_enabled": True, "compress": True},
            {"name": "HSM Large", "size": 2 * 1024 * 1024, "cipher_type": CipherType.AES_GCM, "hsm_enabled": True},
            {"name": "Ultra Security", "size": 1024 * 1024, "cipher_type": CipherType.CHACHA20, "security_level": SecurityLevel.ULTRA},
            {"name": "HSM PKCS#11", "size": 1024, "cipher_type": CipherType.AES_GCM, "hsm_enabled": True},
            {"name": "Dilithium Signed", "size": 2048, "cipher_type": CipherType.CHACHA20, "security_level": SecurityLevel.ULTRA}
        ]

    def run_comprehensive_test(self):
        self.logger.info("Starting Comprehensive Crypto Test Suite")
        test_scenarios = self.generate_test_scenarios()
        for scenario in test_scenarios:
            try:
                self.logger.info(f"Testing Scenario: {scenario['name']}")
                key = os.urandom(32)
                test_data = os.urandom(scenario['size']) if "Compressed" not in scenario['name'] else b"Repeat " * (scenario['size'] // 7)
                cipher = EnhancedIndiaMethodCipher(
                    key,
                    cipher_type=scenario['cipher_type'],
                    key_rotation_policy=KeyRotationPolicy.FIXED_INTERVAL if "Large" in scenario['name'] else None,
                    security_level=scenario.get('security_level', SecurityLevel.MEDIUM),
                    adaptive_security=scenario.get('adaptive_security', False),
                    pq_enabled=scenario.get('pq_enabled', False),
                    hsm_enabled=scenario.get('hsm_enabled', False),
                    hsm_config={"lib_path": "/usr/lib/softhsm/libsofthsm2.so", "pin": "1234"} if scenario.get('hsm_enabled') else None
                )
                input_file = os.path.join(self.test_data_dir, f"{scenario['name']}_input.bin")
                encrypted_file = os.path.join(self.test_data_dir, f"{scenario['name']}_encrypted.bin")
                decrypted_file = os.path.join(self.test_data_dir, f"{scenario['name']}_decrypted.bin")
                with open(input_file, 'wb') as f:
                    f.write(test_data)
                cipher.encrypt_file(input_file, encrypted_file, chunk_size=scenario.get('chunk_size', 1024*1024),
                                   compress=scenario.get('compress', False))
                cipher.decrypt_file(encrypted_file, decrypted_file)
                with open(decrypted_file, 'rb') as f:
                    decrypted_data = f.read()
                assert decrypted_data == test_data, f"Data mismatch in {scenario['name']}"
                self.logger.info(f"✓ Scenario {scenario['name']} Passed Successfully")
                # Additional Verifications
                assert cipher.verify_correctness(), f"Z3 verification failed for {scenario['name']}"
                assert cipher.verify_with_tla(), f"TLA+ verification failed for {scenario['name']}"
                if scenario['size'] >= 125000:  # 1M bits for NIST
                    with open(encrypted_file, 'rb') as f:
                        encrypted_data = f.read()
                    assert cipher.nist_suite.run_tests(encrypted_data), f"NIST suite failed for {scenario['name']}"
            except Exception as e:
                self.logger.error(f"Test Scenario Failed: {scenario['name']} - {str(e)}")
                raise

    def performance_benchmark(self):
        self.logger.info("Starting Performance Benchmarking")
        scenarios = self.generate_test_scenarios()
        results = []
        for scenario in scenarios:
            key = os.urandom(32)
            test_data = os.urandom(scenario['size']) if "Compressed" not in scenario['name'] else b"Repeat " * (scenario['size'] // 7)
            cipher = EnhancedIndiaMethodCipher(
                key,
                cipher_type=scenario['cipher_type'],
                security_level=scenario.get('security_level', SecurityLevel.MEDIUM),
                adaptive_security=scenario.get('adaptive_security', False),
                pq_enabled=scenario.get('pq_enabled', False),
                hsm_enabled=scenario.get('hsm_enabled', False),
                hsm_config={"lib_path": "/usr/lib/softhsm/libsofthsm2.so", "pin": "1234"} if scenario.get('hsm_enabled') else None
            )
            # In-memory benchmark
            start_time = datetime.now()
            encrypted_data = cipher.encrypt(test_data, compress=scenario.get('compress', False))
            encryption_time = datetime.now() - start_time
            start_time = datetime.now()
            decrypted_data = cipher.decrypt(encrypted_data)
            decryption_time = datetime.now() - start_time
            assert decrypted_data == test_data, f"In-memory mismatch in {scenario['name']}"
            # File-based benchmark
            input_file = os.path.join(self.test_data_dir, f"{scenario['name']}_perf_input.bin")
            encrypted_file = os.path.join(self.test_data_dir, f"{scenario['name']}_perf_encrypted.bin")
            with open(input_file, 'wb') as f:
                f.write(test_data)
            start_time = datetime.now()
            cipher.encrypt_file(input_file, encrypted_file, chunk_size=scenario.get('chunk_size', 1024*1024),
                               compress=scenario.get('compress', False))
            file_encryption_time = datetime.now() - start_time
            results.append({
                "scenario": scenario['name'],
                "data_size": scenario['size'],
                "encryption_time": encryption_time.total_seconds(),
                "decryption_time": decryption_time.total_seconds(),
                "file_encryption_time": file_encryption_time.total_seconds()
            })
        for result in results:
            self.logger.info(
                f"Scenario: {result['scenario']} | Size: {result['data_size']} bytes | "
                f"Enc Time: {result['encryption_time']:.4f}s | Dec Time: {result['decryption_time']:.4f}s | "
                f"File Enc Time: {result['file_encryption_time']:.4f}s"
            )
        return results

    def stress_test(self):
        self.logger.info("Starting Stress Test")
        key = os.urandom(32)
        cipher = EnhancedIndiaMethodCipher(key, cipher_type=CipherType.CHACHA20, adaptive_security=True)
        large_data = os.urandom(50 * 1024 * 1024)  # 50MB
        input_file = os.path.join(self.test_data_dir, "stress_input.bin")
        encrypted_file = os.path.join(self.test_data_dir, "stress_encrypted.bin")
        decrypted_file = os.path.join(self.test_data_dir, "stress_decrypted.bin")
        with open(input_file, 'wb') as f:
            f.write(large_data)
        cipher.encrypt_file(input_file, encrypted_file, chunk_size=5*1024*1024, compress=True)
        cipher.decrypt_file(encrypted_file, decrypted_file)
        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, large_data)
        self.logger.info("✓ Stress Test Passed Successfully")
        # Additional verification
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        assert cipher.nist_suite.run_tests(encrypted_data), "NIST suite failed in stress test"
        assert cipher.verify_correctness(), "Z3 verification failed in stress test"
        assert cipher.verify_with_tla(), "TLA+ verification failed in stress test"

    def assertEqual(self, a, b):
        if a != b:
            raise AssertionError(f"Values not equal: {a} != {b}")

def main():
    crypto_test = CryptoPerformanceAnalysis()
    try:
        crypto_test.run_comprehensive_test()
        crypto_test.performance_benchmark()
        crypto_test.stress_test()
        print("All tests completed successfully")
    except Exception as e:
        print(f"Test Suite Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
