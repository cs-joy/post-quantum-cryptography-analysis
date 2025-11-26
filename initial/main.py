# main.py
from benchmark import Benchmark
from schemes import dilithium, falcon, sphincs

def main():
    # Initialize benchmark with desired parameters
    benchmark = Benchmark(
        num_iterations=100,  # Number of iterations for timing measurements
        warmup_iterations=10  # Number of warmup iterations
    )
    
    # List of schemes to test
    schemes = [
        dilithium,
        falcon,
        sphincs
    ]
    
    # Define message sizes to test (in bytes)
    message_sizes = [
        32,          # Small messages
        1024,        # 1KB
        1024*1024    # 1MB
    ]
    
    # Run benchmarks
    results = benchmark.run_benchmarks(schemes, message_sizes)
    
    print("\nBenchmarking complete. Results saved to results/")
    print("- Detailed results: results/detailed_measurements.json")
    print("- Summary: results/summary.csv")

if __name__ == "__main__":
    main()