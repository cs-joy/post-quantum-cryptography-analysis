from web3 import Web3
import json
import time
from pathlib import Path
import statistics
from typing import Dict, Any
import numpy as np
from schemes import dilithium, falcon, sphincs

class BlockchainPQCBenchmark:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
        
        with open('build/contracts/PQCVerifier.json') as f:
            contract_json = json.load(f)
            self.contract_address = contract_json['networks']['1337']['address']
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_json['abi']
            )
        
        self.account = self.w3.eth.accounts[0]

    def measure_pure_crypto(self, scheme, message: bytes):
        """Measure pure cryptographic operations without blockchain"""
        start_time = time.time()
        pub_key, priv_key = scheme.keygen()
        keygen_time = (time.time() - start_time) * 1000
        
        start_time = time.time()
        signature = scheme.sign(message, priv_key)
        sign_time = (time.time() - start_time) * 1000
        
        start_time = time.time()
        scheme.verify(message, signature, pub_key)
        verify_time = (time.time() - start_time) * 1000
        
        return {
            'key_generation_time_ms': keygen_time,
            'signing_time_ms': sign_time,
            'pure_verification_time_ms': verify_time,
            'public_key_size': len(pub_key),
            'private_key_size': len(priv_key),
            'signature_size': len(signature),
            'keys': (pub_key, priv_key),
            'signature': signature
        }
    
    def measure_blockchain_overhead(self, scheme, message: bytes, keys, signature):
        """
        Measure blockchain-specific overheads using placeholder verification.
        NOTE: The contract functions only simulate the transaction cost of sending
              PQC data, they DO NOT perform actual PQC verification on-chain.
        """
        pub_key, priv_key = keys
        
        # Measure base transaction (simple value transfer) to estimate baseline gas/time
        start_time = time.time()
        tx_hash = self.w3.eth.send_transaction({
            'from': self.account,
            'to': self.contract_address,
            'value': 0,
            'gas': 21000
        })
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        base_tx_time = (time.time() - start_time) * 1000
        base_gas = receipt['gasUsed']
        
        # Measure verification transaction on blockchain (calling placeholder function)
        scheme_name = scheme.get_name().lower()
        # Select the corresponding placeholder function in the contract
        if 'mldsa' in scheme_name or 'dilithium' in scheme_name: # Match ML-DSA name
            verify_func = self.contract.functions.verifyDilithium
        elif 'falcon' in scheme_name:
            verify_func = self.contract.functions.verifyFalconPadded
        elif 'sphincs' in scheme_name: # Match SPHINCS+ name
            verify_func = self.contract.functions.verifySphincsPlus
        else:
             raise ValueError(f"Unknown scheme name for contract function mapping: {scheme.get_name()}")
            
        start_time = time.time()
        
        # Estimate gas with a safety margin.
        # This is necessary because exact gas cost can vary slightly, and complex
        # operations (even placeholders here) might exceed default block gas limits
        # without an explicit higher limit. The multiplier (e.g., 1.5 or 2) helps
        # prevent out-of-gas errors during benchmarking, but might overestimate slightly.
        # Actual on-chain PQC verification would likely require much higher gas limits.
        try:
            gas_estimate = verify_func(
                message,
                signature,
                pub_key
            ).estimate_gas({'from': self.account}) * 2 # Using a multiplier as safety margin
        except Exception as e:
             print(f"Gas estimation failed for {scheme.get_name()} (size {len(message)}): {e}. Using fallback high gas limit.")
             # Fallback to a very high limit if estimation fails (adjust as needed)
             gas_estimate = 80_000_000 

        # Ensure gas estimate doesn't exceed Ganache's block limit (set in launch_ganache.sh)
        block_gas_limit = 100_000_000 # Match Ganache config or query w3.eth.getBlock('latest').gasLimit
        if gas_estimate > block_gas_limit:
             print(f"Warning: Estimated gas {gas_estimate} exceeds block limit {block_gas_limit}. Capping at limit.")
             gas_estimate = block_gas_limit

        tx_hash = verify_func(
            message,
            signature,
            pub_key
        ).transact({
            'from': self.account,
            'gas': gas_estimate # Use estimated gas with margin
        })
        
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        blockchain_verify_time = (time.time() - start_time) * 1000
        
        # Calculate verification-specific gas (total gas - base gas)
        # Note: This is an approximation, as the base transaction is simpler.
        verification_gas = receipt['gasUsed'] - base_gas
        if verification_gas < 0: # Ensure non-negative gas
             verification_gas = 0 
        
        sig_data_size = len(signature) + len(pub_key) # Size of data relevant to verification tx

        return {
            'base_transaction_time_ms': base_tx_time,
            'base_transaction_gas': base_gas,
            'blockchain_verification_time_ms': blockchain_verify_time,
            'verification_gas': verification_gas, # Gas attributed specifically to the verify call
            'signature_data_size': sig_data_size, # Size of signature + pubkey
            'total_gas': receipt['gasUsed'] # Total gas for the verification transaction
        }

    def benchmark_scheme(self, scheme, message_sizes=[32, 1024, 32*1024, 128*1024, 1024*1024], iterations=50):
        """Run comprehensive benchmarks for a scheme"""
        results = {
            'scheme': scheme.get_name(),
            'scheme_params': scheme.get_params(),
            'measurements': {}
        }
        
        for size in message_sizes:
            print(f"\nTesting with message size: {size} bytes")
            message = b'A' * size
            
            crypto_metrics = []
            blockchain_metrics = []
            
            for i in range(iterations):
                if i % 10 == 0:
                    print(f"Progress: {i}/{iterations}")
                
                try:
                    crypto_result = self.measure_pure_crypto(scheme, message)
                    crypto_metrics.append(crypto_result)
                    
                    blockchain_result = self.measure_blockchain_overhead(
                        scheme, 
                        message, 
                        crypto_result['keys'],
                        crypto_result['signature']
                    )
                    blockchain_metrics.append(blockchain_result)
                    
                except Exception as e:
                    print(f"Error in iteration {i}: {str(e)}")
                    continue
            
            if crypto_metrics and blockchain_metrics:
                results['measurements'][f'message_size_{size}'] = {
                    'pure_crypto': {
                        'key_generation_time_ms': statistics.mean(m['key_generation_time_ms'] for m in crypto_metrics),
                        'signing_time_ms': statistics.mean(m['signing_time_ms'] for m in crypto_metrics),
                        'pure_verification_time_ms': statistics.mean(m['pure_verification_time_ms'] for m in crypto_metrics),
                        'public_key_size': crypto_metrics[0]['public_key_size'],
                        'private_key_size': crypto_metrics[0]['private_key_size'],
                        'signature_size': crypto_metrics[0]['signature_size']
                    },
                    'blockchain_overhead': {
                        'base_transaction_gas': statistics.mean(m['base_transaction_gas'] for m in blockchain_metrics),
                        'verification_gas': statistics.mean(m['verification_gas'] for m in blockchain_metrics),
                        'total_gas': statistics.mean(m['total_gas'] for m in blockchain_metrics),
                        'blockchain_verification_time_ms': statistics.mean(m['blockchain_verification_time_ms'] for m in blockchain_metrics),
                        'verification_overhead_ratio': statistics.mean(m['blockchain_verification_time_ms'] for m in blockchain_metrics) / 
                                                    statistics.mean(m['pure_verification_time_ms'] for m in crypto_metrics),
                        'gas_per_byte': statistics.mean(m['total_gas'] for m in blockchain_metrics) / 
                                      crypto_metrics[0]['signature_size']
                    }
                }
            
        return results

    def run_all_benchmarks(self):
        # Use singleton instances
        schemes = [
            dilithium,
            falcon,
            sphincs
        ]
        
        all_results = {}
        for scheme in schemes:
            try:
                print(f"\nBenchmarking {scheme.get_name()}...")
                results = self.benchmark_scheme(scheme)
                all_results[scheme.get_name()] = results
            except Exception as e:
                print(f"Error benchmarking {scheme.get_name()}: {str(e)}")
                import traceback
                traceback.print_exc()
        
        Path('results').mkdir(exist_ok=True)
        with open('results/pqc_blockchain_benchmarks.json', 'w') as f:
            json.dump(all_results, f, indent=2)

if __name__ == "__main__":
    benchmark = BlockchainPQCBenchmark()
    benchmark.run_all_benchmarks()