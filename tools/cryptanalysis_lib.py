import fips205
from os import cpu_count
import random
import os

# extract WOTS keys from a signature
def process_sig(args):
    params, pk, sig_idx, sig, sig_len = args
    slh = fips205.SLH_DSA(params)
    m = sig[sig_len:]
    sig = sig[:sig_len]
    valid = slh.slh_verify_internal(m, sig, pk)
    for adrs, keys in slh.wots_keys.items():
        chain_adrs = adrs.copy()
        chain_adrs.set_type_and_clear(fips205.ADRS.WOTS_HASH)
        chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
        for key in keys:
            key.valid = valid
            key.sig_idx = sig_idx
    return slh.wots_keys

def sign_worker(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    num_msgs, adrs, key, pk_seed, params = args
    msg_len = 32
    batch_size = 10000
    success = 0
    for start in range(0, num_msgs, batch_size):
        end = min(start + batch_size, num_msgs)
        batch_length = end - start
        # Generate random bytes for the entire batch
        batch_data = random.randbytes(batch_length * msg_len)
        for j in range(batch_length):
            msg = batch_data[j * msg_len:(j + 1) * msg_len]
            if key.try_sign(msg, adrs, pk_seed, params):
                # print(f"Signed msg {msg.hex()} with key {key}")
                success += 1
    return success

def sign_worker_xmss(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    num_msgs, adrs, key, pk_seed, params = args
    slh = fips205.SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # this is probably wrong, double-check this from valid sig verification
    i_tree = adrs.get_tree_index()
    i_tree = i_tree << slh.hp
    i_leaf = i_tree & hp_m
    
    x_adrs: fips205.ADRS = adrs.copy()
    x_adrs.set_layer_address(i_leaf)
    x_adrs.set_tree_address(i_tree)
    
    for _ in range(num_msgs):
        # generate a random SK seed
        sk_seed = random.randbytes(slh.n)
        xmss = slh.xmss_node(sk_seed, i_leaf, slh.hp, pk_seed, adrs)
        # sign the root node of the tree
        if key.try_sign(xmss, adrs, pk_seed, params):
            # print(f"Signed XMSS tree from seed {sk_seed.hex()} and x_adrs {x_adrs} with key {key}")
            return (xmss, x_adrs, sk_seed, pk_seed, key)
    return None

def sign_worker_xmss_c(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    import cryptanalysis_lib_c as clc
    num_msgs, adrs, key, pk_seed, params = args
    slh = fips205.SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # this is probably wrong, double-check this
    i_tree = adrs.get_tree_address()
    i_tree = i_tree << slh.hp
    i_leaf = i_tree & hp_m
    
    x_adrs: fips205.ADRS = adrs.copy()
    x_adrs.set_layer_address(i_leaf)
    x_adrs.set_tree_address(i_tree)

    ctx = clc.SPXCtx()
    sig_buf = (clc.ctypes.c_ubyte * slh.sig_sz)()
    root_buf = (clc.ctypes.c_ubyte * slh.n)()
    wots_adrs = (clc.ctypes.c_uint32 * 8)()
    tree_adrs = (clc.ctypes.c_uint32 * 8)()
    
    for i in range(8):
        wots_adrs[i] = x_adrs.a[i]
        tree_adrs[i] = x_adrs.a[i]

    for _ in range(num_msgs):
        # Generate a random SK seed in ctx.sk_seed
        for i in range(clc.SPX_N):
            ctx.sk_seed[i] = random.randint(0, 255)
            ctx.pub_seed[i] = pk_seed[i]
        # --- 7. Generate tree ---
        clc.lib.SPX_merkle_sign(sig_buf, root_buf, clc.ctypes.byref(ctx), wots_adrs, tree_adrs, ~0)
        # Sign the root node of the tree
        if key.try_sign(bytes(root_buf), x_adrs, pk_seed, params):
            # print(f"Signed XMSS tree from seed {ctx.sk_seed[:]} and x_adrs {x_adrs} with key {key}")
            return (bytes(root_buf), bytes(ctx.sk_seed), key)
        
    return None

def extract_wots_keys(pk: bytes, sigs: list[bytes], params) -> dict[fips205.ADRS, set[fips205.WOTSKeyData]]:
    import multiprocessing
    slh = fips205.SLH_DSA(params)
    wots_bytes = slh.len * slh.n
    xmss_bytes = slh.hp * slh.n
    fors_bytes = slh.k * (slh.n + slh.a * slh.n)
    sig_len = slh.n + fors_bytes + slh.d * (wots_bytes + xmss_bytes)

    with multiprocessing.Pool(processes=cpu_count()-1) as pool:
        args = [(params, pk, sig_idx, sig, sig_len) for sig_idx, sig in enumerate(sigs)]
        results = pool.map(process_sig, args)
    
    # Merge results
    merged = {}
    for item in results:
        merged = merge_groups(merged, item)
    return merged

def merge_groups(left: dict[fips205.ADRS, set], right: dict[fips205.ADRS, set]) -> dict[fips205.ADRS, set]:
    for key, items in right.items():
        if key not in left:
            left[key] = set()
        left[key] = left[key] | items
    return left

use_pickle = True

def pickle_load(filename: str, or_else):
    if use_pickle:
        import pickle
        if os.path.exists(filename):
            print(f"Loading pickle from {filename}.")
            with open(filename, 'rb') as f:
                return pickle.load(f)
        else:
            print(f"File {filename} not found, creating new one.")
            return pickle_store(filename, or_else)
    else:
        print(f"Pickle loading is disabled, using fallback.")
        return or_else()
    
def pickle_store(filename: str, fn):
    if use_pickle:
        import pickle
        value = fn()
        with open(filename, 'wb') as f:
            pickle.dump(value, f)
        return value
    else:
        print(f"Pickle storing is disabled, not saving {filename}.")
        value = fn()
        return value
    
def print_adrs(adrs: fips205.ADRS, end='\n', verbose=False):
    hex = adrs.adrs().hex()
    if verbose:
        print('LAYER' + ' ' * 4 + 
                'TREE ADDR' + ' ' * 18 +
                'TYP' + ' ' * 6 +
                'KADR' + ' ' * 5 +
                'PADD = 0')
    print(' '.join([hex[i:i+8] for i in range(0, len(hex), 8)]), end=' ')
    print(end=end)
    
def find_collisions(wots_sigs: dict[fips205.ADRS, set[fips205.WOTSKeyData]]) -> dict[fips205.ADRS, set[fips205.WOTSKeyData]]:
    return {adrs: keys for adrs, keys in wots_sigs.items() if len(keys) > 1 and any(v.valid for v in keys)}  # if any(v.valid for v in keys) and not all(v.valid for v in keys)}
