# schemes/dilithium.py
from .base import OQSSignature

class DilithiumWrapper:
    def __init__(self):
        self.sig = OQSSignature("ML-DSA-65")
        
    def keygen(self):
        return self.sig.keypair()
        
    def sign(self, message, private_key):
        return self.sig.sign(message, private_key)
        
    def verify(self, message, signature, public_key):
        return self.sig.verify(message, signature, public_key)
        
    def get_name(self):
        return "ML-DSA-65"
        
    def get_params(self):
        return {
            "version": "ML-DSA-65",
            "security_level": "NIST Level 2",
            "claimed_classical_security": 125,
            "claimed_quantum_security": 64
        }