import os
import sys
import logging
from datetime import datetime, timedelta

# Add parent directory to path to import the cipher
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from improved_india_method_cipher import (
    EnhancedIndiaMethodCipher, 
    CipherType, 
    KeyRotationPolicy
)

class CryptoPerformanceAnalysis:
    """
    Comprehensive performance and integration analysis for India Method Cipher
    """
    def __init__(self):
        """
        Initialize logging and test parameters
        """
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='crypto_performance.log'
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Ensure test data directory exists
        self.test_data_dir = "test_data"
        os.makedirs(self.test_data_dir, exist_ok=True)

    def generate_test_scenarios(self):
        """
        Generate diverse test scenarios
        
        Returns:
            List of test scenario configurations
        """
        return [
            {
                "name": "Small Document",
                "size": 1024,  # 1 KB
                "cipher_type": CipherType.CHACHA20,
                "rotation_policy": KeyRotationPolicy.FIXED_INTERVAL
            },
            {
                "name": "Medium Research Paper",
                "size": 1024 * 1024,  # 1 MB
                "cipher_type": CipherType.AES_GCM,
                "rotation_policy": KeyRotationPolicy.TIME_BASED
            },
            {
                "name": "Large Dataset",
                "size": 10 * 1024 * 1024,  # 10 MB
                "cipher_type": CipherType.CHACHA20,
                "rotation_policy": None
            }
        ]

    def run_comprehensive_test(self):
        """
        Execute comprehensive encryption-decryption tests
        """
        self.logger.info("Starting Comprehensive Crypto Test Suite")
        
        test_scenarios = self.generate_test_scenarios()
        
        for scenario in test_scenarios:
            try:
                self.logger.info(f"Testing Scenario: {scenario['name']}")
                
                # Generate random key and data
                key = os.urandom(32)
                test_data = os.urandom(scenario['size'])
                
                # Initialize cipher
                cipher = EnhancedIndiaMethodCipher(
                    key, 
                    cipher_type=scenario['cipher_type'],
                    key_rotation_policy=scenario['rotation_policy']
                )
                
                # Input file paths
                input_file = os.path.join(self.test_data_dir, f"{scenario['name']}_input.bin")
                encrypted_file = os.path.join(self.test_data_dir, f"{scenario['name']}_encrypted.bin")
                decrypted_file = os.path.join(self.test_data_dir, f"{scenario['name']}_decrypted.bin")
                
                # Write test data
                with open(input_file, 'wb') as f:
                    f.write(test_data)
                
                # Perform file encryption
                cipher.encrypt_file(input_file, encrypted_file)
                
                # Perform file decryption
                cipher.decrypt_file(encrypted_file, decrypted_file)
                
                # Verify data integrity
                with open(decrypted_file, 'rb') as f:
                    decrypted_data = f.read()
                
                assert decrypted_data == test_data, f"Data mismatch in {scenario['name']}"
                self.logger.info(f"✓ Scenario {scenario['name']} Passed Successfully")
            
            except Exception as e:
                self.logger.error(f"Test Scenario Failed: {scenario['name']}")
                self.logger.error(f"Error Details: {str(e)}")
                raise

    def performance_benchmark(self):
        """
        Measure encryption and decryption performance
        """
        self.logger.info("Starting Performance Benchmarking")
        
        scenarios = self.generate_test_scenarios()
        results = []
        
        for scenario in scenarios:
            key = os.urandom(32)
            test_data = os.urandom(scenario['size'])
            
            cipher = EnhancedIndiaMethodCipher(key)
            
            # Encryption performance
            start_time = datetime.now()
            encrypted_data = cipher.encrypt(test_data)
            encryption_time = datetime.now() - start_time
            
            # Decryption performance
            start_time = datetime.now()
            cipher.decrypt(encrypted_data)
            decryption_time = datetime.now() - start_time
            
            results.append({
                "scenario": scenario['name'],
                "data_size": scenario['size'],
                "encryption_time": encryption_time.total_seconds(),
                "decryption_time": decryption_time.total_seconds()
            })
        
        # Log performance results
        for result in results:
            self.logger.info(
                f"Scenario: {result['scenario']} | "
                f"Size: {result['data_size']} bytes | "
                f"Encryption Time: {result['encryption_time']:.4f}s | "
                f"Decryption Time: {result['decryption_time']:.4f}s"
            )
        
        return results

def main():
    crypto_test = CryptoPerformanceAnalysis()
    
    try:
        # Run comprehensive tests
        crypto_test.run_comprehensive_test()
        
        # Perform performance benchmarking
        performance_results = crypto_test.performance_benchmark()
    
    except Exception as e:
        print(f"Test Suite Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()