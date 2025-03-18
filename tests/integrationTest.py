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
            {"name": "Large Adaptive", "size": 10 * 1024 * 1024, "cipher_type": CipherType.CHACHA20, "adaptive_security": True}
        ]

    def run_comprehensive_test(self):
        self.logger.info("Starting Comprehensive Crypto Test Suite")
        test_scenarios = self.generate_test_scenarios()
        for scenario in test_scenarios:
            try:
                self.logger.info(f"Testing Scenario: {scenario['name']}")
                key = os.urandom(32)
                test_data = os.urandom(scenario['size'])
                cipher = EnhancedIndiaMethodCipher(
                    key,
                    cipher_type=scenario['cipher_type'],
                    adaptive_security=scenario.get('adaptive_security', False)
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
            except Exception as e:
                self.logger.error(f"Test Scenario Failed: {scenario['name']} - {str(e)}")
                raise

    def performance_benchmark(self):
        self.logger.info("Starting Performance Benchmarking")
        scenarios = self.generate_test_scenarios()
        results = []
        for scenario in test_scenarios:
            key = os.urandom(32)
            test_data = os.urandom(scenario['size'])
            cipher = EnhancedIndiaMethodCipher(
                key,
                cipher_type=scenario['cipher_type'],
                adaptive_security=scenario.get('adaptive_security', False)
            )
            start_time = datetime.now()
            encrypted_data = cipher.encrypt(test_data, compress=scenario.get('compress', False))
            encryption_time = datetime.now() - start_time
            start_time = datetime.now()
            cipher.decrypt(encrypted_data)
            decryption_time = datetime.now() - start_time
            results.append({
                "scenario": scenario['name'],
                "data_size": scenario['size'],
                "encryption_time": encryption_time.total_seconds(),
                "decryption_time": decryption_time.total_seconds()
            })
        for result in results:
            self.logger.info(
                f"Scenario: {result['scenario']} | Size: {result['data_size']} bytes | "
                f"Enc Time: {result['encryption_time']:.4f}s | Dec Time: {result['decryption_time']:.4f}s"
            )
        return results

def main():
    crypto_test = CryptoPerformanceAnalysis()
    try:
        crypto_test.run_comprehensive_test()
        crypto_test.performance_benchmark()
    except Exception as e:
        print(f"Test Suite Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
