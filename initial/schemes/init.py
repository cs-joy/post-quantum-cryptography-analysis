# schemes/__init__.py
from .dilithium import DilithiumWrapper
from .falcon import FalconWrapper
from .sphincs import SphincsWrapper

# Create singleton instances
__dilithium = DilithiumWrapper()
__falcon = FalconWrapper()
__sphincs = SphincsWrapper()

# Export the instances for direct use
dilithium = __dilithium
falcon = __falcon
sphincs = __sphincs

# Also export the classes if needed
__all__ = ['dilithium', 'falcon', 'sphincs', 
           'DilithiumWrapper', 'FalconWrapper', 'SphincsWrapper']