# schemes/falcon.py
from .base import OQSSignature

class FalconWrapper:
    def __init__(self):
        self.sig = OQSSignature("Falcon-padded-512")
        
    def keygen(self):
        return self.sig.keypair()
        
    def sign(self, message, private_key):
        return self.sig.sign(message, private_key)
        
    def verify(self, message, signature, public_key):
        return self.sig.verify(message, signature, public_key)
        
    def get_name(self):
        return "Falcon-padded-512"
        
    def get_params(self):
        return {
            "version": "Falcon-padded-512",
            "security_level": "NIST Level 1+",
            "claimed_classical_security": 118,
            "claimed_quantum_security": 58
        }