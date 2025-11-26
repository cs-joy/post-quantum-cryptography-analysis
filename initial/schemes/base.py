import os
import ctypes
from ctypes import c_int, c_uint8, c_size_t, POINTER, c_char_p, c_void_p
import atexit

class OQS_STATUS(c_int):
    SUCCESS = 0
    ERROR = -1

_lib = None

def load_liboqs():
    global _lib
    if (_lib is None):
        lib_path = os.path.expanduser("~/liboqs/build/lib/liboqs.so")
        if not os.path.exists(lib_path):
            raise RuntimeError(f"liboqs library not found at {lib_path}")
        _lib = ctypes.CDLL(lib_path)
        if hasattr(_lib, 'OQS_init'):
            _lib.OQS_init()
            atexit.register(lambda: _lib.OQS_destroy())
    return _lib

class OQSSignature:
    def __init__(self, name):
        self.lib = load_liboqs()
        self.lib.OQS_SIG_new.argtypes = [c_char_p]
        self.lib.OQS_SIG_new.restype = c_void_p
        self.sig = self.lib.OQS_SIG_new(name.encode())
        if not self.sig:
            raise RuntimeError(f"Failed to initialize {name}")

        self.lib.OQS_SIG_keypair.argtypes = [c_void_p, POINTER(c_uint8), POINTER(c_uint8)]
        self.lib.OQS_SIG_keypair.restype = c_int
        self.lib.OQS_SIG_sign.argtypes = [c_void_p, POINTER(c_uint8), POINTER(c_size_t),
                                          POINTER(c_uint8), c_size_t, POINTER(c_uint8)]
        self.lib.OQS_SIG_sign.restype = c_int
        self.lib.OQS_SIG_verify.argtypes = [c_void_p, POINTER(c_uint8), c_size_t,
                                            POINTER(c_uint8), c_size_t, POINTER(c_uint8)]
        self.lib.OQS_SIG_verify.restype = c_int

        class SIG_STRUCT(ctypes.Structure):
            _fields_ = [
                ("method_name", c_char_p),
                ("alg_version", c_char_p),
                ("claimed_nist_level", c_uint8),
                ("euf_cma", c_uint8),
                ("length_public_key", c_size_t),
                ("length_secret_key", c_size_t),
                ("length_signature", c_size_t)
            ]
        sig_struct = ctypes.cast(self.sig, POINTER(SIG_STRUCT)).contents
        self.length_public_key = sig_struct.length_public_key
        self.length_secret_key = sig_struct.length_secret_key
        self.length_signature = sig_struct.length_signature

    def keypair(self):
        public_key = (c_uint8 * self.length_public_key)()
        secret_key = (c_uint8 * self.length_secret_key)()
        ret = self.lib.OQS_SIG_keypair(self.sig, public_key, secret_key)
        if ret != 0:
            raise RuntimeError("Key generation failed")
        return bytes(public_key), bytes(secret_key)

    def sign(self, message, secret_key):
        if isinstance(message, str):
            message = message.encode()
        signature = (c_uint8 * self.length_signature)()
        sig_len = c_size_t(self.length_signature)
        msg_array = (c_uint8 * len(message))(*message)
        secret_array = (c_uint8 * len(secret_key))(*secret_key)
        ret = self.lib.OQS_SIG_sign(self.sig, signature, ctypes.byref(sig_len),
                                    msg_array, len(message), secret_array)
        if ret != 0:
            raise RuntimeError("Signing failed")
        return bytes(signature[:sig_len.value])

    def verify(self, message, signature, public_key):
        if isinstance(message, str):
            message = message.encode()
        msg_array = (c_uint8 * len(message))(*message)
        sig_array = (c_uint8 * len(signature))(*signature)
        pub_array = (c_uint8 * len(public_key))(*public_key)
        ret = self.lib.OQS_SIG_verify(self.sig, msg_array, len(message),
                                      sig_array, len(signature), pub_array)
        return ret == 0

    def __del__(self):
        if hasattr(self, 'sig') and self.sig:
            self.lib.OQS_SIG_free(self.sig)