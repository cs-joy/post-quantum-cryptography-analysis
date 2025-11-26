# test_schemes.py
from schemes import dilithium, falcon, sphincs

def print_separator():
    print("\n" + "="*50 + "\n")

def test_scheme(scheme_wrapper):
    name = scheme_wrapper.get_name()
    print(f"Testing {name}:")
    print("-" * (len(name) + 8))
    
    try:
        # Generate keys
        print("Generating keypair...")
        public_key, private_key = scheme_wrapper.keygen()
        print(f"✓ Public key size: {len(public_key)} bytes")
        print(f"✓ Private key size: {len(private_key)} bytes")
        
        # Sign message
        message = b"Hello, Post-Quantum World!"
        print("\nSigning message...")
        signature = scheme_wrapper.sign(message, private_key)
        print(f"✓ Signature size: {len(signature)} bytes")
        
        # Verify signature
        print("\nVerifying signature...")
        valid = scheme_wrapper.verify(message, signature, public_key)
        if valid:
            print("✓ Signature verification successful")
        else:
            print("✗ Signature verification failed")
            return False
        
        # Test with modified message
        print("\nTesting tamper detection...")
        modified_message = b"Hello, Post-Quantum World?"
        valid = scheme_wrapper.verify(modified_message, signature, public_key)
        if not valid:
            print("✓ Tampered message correctly rejected")
        else:
            print("✗ WARNING: Tampered message incorrectly accepted")
            return False
        
        return True
        
    except Exception as e:
        print(f"\n✗ Error occurred during {name} testing:")
        print(f"  {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    schemes = [
        dilithium,
        falcon,
        sphincs
    ]
    
    print_separator()
    print("Post-Quantum Signature Scheme Testing")
    print_separator()
    
    results = []
    for scheme in schemes:
        success = test_scheme(scheme)
        results.append((scheme.get_name(), success))
        print_separator()
    
    # Print summary
    print("Testing Summary:")
    print("--------------")
    successes = sum(1 for _, success in results if success)
    
    for name, success in results:
        status = "✓ Passed" if success else "✗ Failed"
        print(f"{name}: {status}")
    
    print(f"\nSuccessfully tested {successes} out of {len(schemes)} schemes")
    
    return 0 if successes == len(schemes) else 1

if __name__ == "__main__":
    exit(main())