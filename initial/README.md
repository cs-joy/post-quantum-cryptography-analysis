# Post-Quantum Signature Benchmarking for Blockchain Integration

This project benchmarks selected post-quantum digital signature schemes (ML-DSA/Dilithium, Falcon, SPHINCS+) using a custom wrapper around `liboqs`. It measures core cryptographic performance (key generation, signing, verification times, and artifact sizes) and simulates blockchain integration overhead.

## Schemes Compared

Based on `liboqs` implementations:
- **ML-DSA-65** (Dilithium Level 2)
- **Falcon-padded-512** (Falcon Level 1+)
- **SPHINCS+-SHA2-128s-simple** (SPHINCS+ Level 2)

## Benchmarking Details

**Core Crypto Performance:**
- Execution time (ms) for key generation, signing, and verification (measured off-chain using Python).
- Signature, public key, and private key sizes (bytes).

**Simulated Blockchain Integration Overhead:**
- Base transaction time and gas cost on a local Ganache instance.
- Time and gas cost for calling placeholder verification functions with PQC artifacts.
- Calculation of gas-per-byte for signature data.
- Verification overhead ratio (blockchain time vs. pure crypto time).

Results are saved in the `results/` directory (ensure this directory is in `.gitignore`):
- `pqc_blockchain_benchmarks.json`: Combined raw data.
- `verification_comparison.pdf`: Plot comparing pure vs. blockchain verification times.
- `gas_analysis.pdf`: Plot comparing gas usage and signature sizes.
- `tables.tex`: LaTeX tables summarizing core crypto and blockchain overhead metrics.

## Citation

If you use this work, please cite:
D. Commey, S. G. Hounsinou and G. V. Crosby, "Post-Quantum Secure Blockchain-Based Federated Learning Framework for Healthcare Analytics," in *IEEE Networking Letters*, doi: 10.1109/LNET.2025.3563434.

**Keywords:** Blockchains; Medical services; Security; Costs; Training; Data models; Cryptography; Smart contracts; Federated learning; NIST; Post-quantum cryptography; blockchain; federated learning; healthcare analytics; digital signatures; lattice-based cryptography; hash-based signatures.

## Setup Instructions

1.  **Build `liboqs`:** Clone and build the `liboqs` library ([https://github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)). Ensure the required signature schemes (ML-DSA, Falcon, SPHINCS+) are enabled during the build.
2.  **Set Library Path:** Make sure the compiled `liboqs.so` (or equivalent dynamic library for your OS) is findable by the system's dynamic linker. The code currently expects it at `~/liboqs/build/lib/liboqs.so`. You might need to adjust the path in `schemes/base.py` or set the `LD_LIBRARY_PATH` environment variable (Linux/macOS):
    ```bash
    export LD_LIBRARY_PATH=~/liboqs/build/lib:$LD_LIBRARY_PATH
    ```
3.  **Python Environment:** Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate # or venv\Scripts\activate on Windows
    ```
4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
5.  **Setup Blockchain Environment (for blockchain benchmarks):**
    *   Install Node.js and npm.
    *   Install Truffle and Ganache CLI globally: `npm install -g truffle ganache`
    *   Launch Ganache in a separate terminal using the provided script:
        ```bash
        chmod +x launch_ganache.sh
        ./launch_ganache.sh
        ```
        This script also generates `keys.json`.
    *   Compile and deploy the placeholder contract:
        ```bash
        truffle compile
        truffle migrate --network development
        ```
        This will create the `build/` directory.
6.  **Run Benchmarks:**
    ```bash
    python blockchain_benchmark.py # Runs both crypto and blockchain benchmarks
    python visualization.py        # Generates plots and tables from results
    ```
    *(Note: `main.py` and `benchmark.py` contain earlier versions of the benchmarking logic focused only on pure crypto performance and memory, without blockchain integration. `blockchain_benchmark.py` is the primary script for the combined results.)*

## License

MIT License
