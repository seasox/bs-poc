import ctypes
import os

lib_path = os.path.abspath("../victims/sphincsplus/shake-avx2/libsphincsp.so")
lib = ctypes.CDLL(lib_path)

SPX_N = 32

# --- 3. Define the spx_ctx struct in Python ---
class SPXCtx(ctypes.Structure):
    _fields_ = [
        ("pub_seed", ctypes.c_ubyte * SPX_N),
        ("sk_seed",  ctypes.c_ubyte * SPX_N),
    ]

# void merkle_sign(uint8_t *sig, unsigned char *root,
#        const spx_ctx* ctx,
#        uint32_t wots_addr[8], uint32_t tree_addr[8],
#        uint32_t idx_leaf);
lib.SPX_merkle_sign.argtypes = (
    ctypes.POINTER(ctypes.c_ubyte),    # uint8_t *sig
    ctypes.POINTER(ctypes.c_ubyte),    # unsigned char *root
    ctypes.POINTER(SPXCtx),            # const spx_ctx* ctx
    ctypes.POINTER(ctypes.c_uint32),   # uint32_t wots_addr[8]
    ctypes.POINTER(ctypes.c_uint32),   # uint32_t tree_addr[8]
    ctypes.c_uint32,                   # uint32_t idx_leaf
)
lib.SPX_merkle_sign.restype = None