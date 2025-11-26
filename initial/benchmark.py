# benchmark.py
from pathlib import Path
import time
import json
import statistics
import pandas as pd
from typing import List, Dict, Any
import psutil
import os

class Benchmark:
    def __init__(self, num_iterations: int = 100, warmup_iterations: int = 10):
        self.num_iterations = num_iterations
        self.warmup_iterations = warmup_iterations
        self.results_dir = Path('results')
        self.results_dir.mkdir(exist_ok=True)

    def measure_operation(self, operation_name: str, func, *args) -> Dict[str, float]:
        """Measure execution time of a function with warmup"""
        print(f"\nMeasuring {operation_name}...")
        
        # Warmup
        print(f"Warming up ({self.warmup_iterations} iterations)...")
        for _ in range(self.warmup_iterations):
            func(*args)
        
        # Actual measurements
        print(f"Running benchmark ({self.num_iterations} iterations)...")
        times = []
        for i in range(self.num_iterations):
            if i % (self.num_iterations // 10) == 0:  # Progress every 10%
                print(f"Progress: {i}/{self.num_iterations}")
                
            start = time.perf_counter()
            func(*args)
            end = time.perf_counter()
            times.append(end - start)
        
        results = {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'std': statistics.stdev(times),
            'min': min(times),
            'max': max(times),
            'iterations': self.num_iterations
        }
        
        print(f"Results for {operation_name}:")
        print(f"  Mean: {results['mean']*1000:.2f} ms")
        print(f"  Median: {results['median']*1000:.2f} ms")
        print(f"  Std Dev: {results['std']*1000:.2f} ms")
        
        return results

    def measure_memory(self, operation_name: str, func, *args) -> Dict[str, int]:
        """Measure memory usage of a function"""
        process = psutil.Process(os.getpid())
        
        # Get baseline
        baseline = process.memory_info().rss
        
        # Run function
        func(*args)
        
        # Get peak
        peak = process.memory_info().rss
        memory_used = peak - baseline
        
        print(f"Memory usage for {operation_name}: {memory_used / 1024 / 1024:.2f} MB")
        
        return {
            'baseline_mb': baseline / 1024 / 1024,
            'peak_mb': peak / 1024 / 1024,
            'used_mb': memory_used / 1024 / 1024
        }

    def benchmark_scheme(self, scheme, message_sizes: List[int] = None) -> Dict[str, Any]:
        """Run comprehensive benchmark for a scheme"""
        if message_sizes is None:
            message_sizes = [32, 1024, 1024*1024]  # Default sizes: 32B, 1KB, 1MB
            
        print(f"\nBenchmarking {scheme.get_name()}")
        print("=" * 50)
        
        results = {
            'scheme': scheme.get_name(),
            'parameters': scheme.get_params(),
            'measurements': {}
        }
        
        # Measure key generation
        pub_key, priv_key = scheme.keygen()
        results['measurements']['keygen'] = {
            'timing': self.measure_operation('Key Generation', scheme.keygen),
            'memory': self.measure_memory('Key Generation', scheme.keygen),
            'public_key_size': len(pub_key),
            'private_key_size': len(priv_key)
        }
        
        # Test with different message sizes
        for size in message_sizes:
            print(f"\nTesting with message size: {size} bytes")
            message = b'A' * size
            signature = scheme.sign(message, priv_key)
            
            size_results = {
                'timing': {
                    'sign': self.measure_operation(f'Signing ({size} bytes)', 
                                                 scheme.sign, message, priv_key),
                    'verify': self.measure_operation(f'Verification ({size} bytes)', 
                                                   scheme.verify, message, signature, pub_key)
                },
                'memory': {
                    'sign': self.measure_memory(f'Signing ({size} bytes)', 
                                              scheme.sign, message, priv_key),
                    'verify': self.measure_memory(f'Verification ({size} bytes)', 
                                                scheme.verify, message, signature, pub_key)
                },
                'sizes': {
                    'message': size,
                    'signature': len(signature)
                }
            }
            
            results['measurements'][f'message_size_{size}'] = size_results
            
        return results

    def run_benchmarks(self, schemes: List, message_sizes: List[int] = None) -> Dict[str, Any]:
        """Run benchmarks for multiple schemes and save results"""
        all_results = {}
        
        for scheme in schemes:
            try:
                results = self.benchmark_scheme(scheme, message_sizes)
                all_results[scheme.get_name()] = results
            except Exception as e:
                print(f"Error benchmarking {scheme.get_name()}: {str(e)}")
                import traceback
                traceback.print_exc()
        
        # Save detailed results
        with open(self.results_dir / 'detailed_measurements.json', 'w') as f:
            json.dump(all_results, f, indent=2)
        
        # Create and save summary
        self._save_summary(all_results)
        
        return all_results

    def _save_summary(self, results: Dict[str, Any]):
        """Create and save summary DataFrame"""
        summary_rows = []
        
        for scheme_name, scheme_data in results.items():
            measurements = scheme_data['measurements']
            
            # Basic info
            base_row = {
                'Scheme': scheme_name,
                'Key Gen Time (ms)': measurements['keygen']['timing']['mean'] * 1000,
                'Key Gen Memory (MB)': measurements['keygen']['memory']['used_mb'],
                'Public Key Size (bytes)': measurements['keygen']['public_key_size'],
                'Private Key Size (bytes)': measurements['keygen']['private_key_size']
            }
            
            # Add data for each message size
            for key, data in measurements.items():
                if key.startswith('message_size_'):
                    size = data['sizes']['message']
                    row = base_row.copy()
                    row.update({
                        'Message Size (bytes)': size,
                        'Sign Time (ms)': data['timing']['sign']['mean'] * 1000,
                        'Verify Time (ms)': data['timing']['verify']['mean'] * 1000,
                        'Sign Memory (MB)': data['memory']['sign']['used_mb'],
                        'Verify Memory (MB)': data['memory']['verify']['used_mb'],
                        'Signature Size (bytes)': data['sizes']['signature']
                    })
                    summary_rows.append(row)
        
        df = pd.DataFrame(summary_rows)
        df.to_csv(self.results_dir / 'summary.csv', index=False)
        print("\nSummary of results:")
        print(df.to_string())