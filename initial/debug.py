# Debug script to list available functions
import ctypes
from ctypes.util import find_library
import os

lib_path = os.path.expanduser("~/liboqs/build/lib/liboqs.so")
lib = ctypes.CDLL(lib_path)

# Print available functions
print("Available functions:")
for name in dir(lib):
    if name.startswith('OQS_'):
        print(f"  {name}")