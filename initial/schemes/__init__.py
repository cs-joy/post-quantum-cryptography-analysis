# schemes/__init__.py
from .dilithium import DilithiumWrapper
from .falcon import FalconWrapper
from .sphincs import SphincsWrapper

# Create and export the instances directly
dilithium = DilithiumWrapper()
falcon = FalconWrapper()
sphincs = SphincsWrapper()