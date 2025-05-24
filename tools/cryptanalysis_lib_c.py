import ctypes
import os

# --- 1. Load your shared library ---
# e.g. libspx.so built from your C code
lib_path = os.path.abspath("../victims/sphincsplus/ref/libspincsp.so")
lib = ctypes.CDLL(lib_path)

# --- 2. Define constants ---
SPX_N = 32   # for example; set to your actual N

# --- 3. Define the spx_ctx struct in Python ---
class SPXCtx(ctypes.Structure):
    _fields_ = [
        ("pub_seed", ctypes.c_ubyte * SPX_N),
        ("sk_seed",  ctypes.c_ubyte * SPX_N),
        # add any other fields in spx_ctx here, in the correct order...
    ]

# --- 4. Tell ctypes about the C function signature ---
# void merkle_gen_root(unsigned char *root, const spx_ctx *ctx)
lib.merkle_gen_root.argtypes = (
    ctypes.POINTER(ctypes.c_ubyte),   # unsigned char *root
    ctypes.POINTER(SPXCtx),           # const spx_ctx *ctx
)
lib.merkle_gen_root.restype = None
