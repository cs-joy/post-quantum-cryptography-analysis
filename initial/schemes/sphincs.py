# schemes/sphincs.py
from .base import OQSSignature

class SphincsWrapper:
    def __init__(self):
        self.sig = OQSSignature("SPHINCS+-SHA2-128s-simple")
        
    def keygen(self):
        return self.sig.keypair()
        
    def sign(self, message, private_key):
        return self.sig.sign(message, private_key)
        
    def verify(self, message, signature, public_key):
        return self.sig.verify(message, signature, public_key)
        
    def get_name(self):
        return "SPHINCS+-SHA2-128s-simple"
        
    def get_params(self):
        return {
            "version": "SPHINCS+-SHA2-128s-simple",
            "security_level": "NIST Level 2",
            "claimed_classical_security": 133,
            "claimed_quantum_security": 66
        }