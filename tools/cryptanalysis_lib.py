import fips205
import random

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
                print(f"Signed msg {msg.hex()} with key {key}")
                success += 1
    return success

def sign_worker_xmss(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    num_msgs, adrs, key, pk_seed, params = args
    slh = fips205.SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # this is probably wrong, double-check this
    i_tree = adrs.get_tree_index()
    i_tree = i_tree << slh.hp
    i_leaf = i_tree & hp_m
    
    x_adrs: fips205.ADRS = adrs.copy()
    x_adrs.set_layer_address(i_leaf)
    x_adrs.set_tree_address(i_tree)
    
    success = 0
    for _ in range(num_msgs):
        # generate a random SK seed
        sk_seed = random.randbytes(slh.n)
        xmss = slh.xmss_node(sk_seed, i_leaf, slh.hp, pk_seed, adrs)
        # sign the root node of the tree
        if key.try_sign(xmss, adrs, pk_seed, params):
            print(f"Signed XMSS tree from seed {sk_seed.hex()} and x_adrs {x_adrs} with key {key}")
            success += 1
    return success

def sign_worker_xmss_c(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    import cryptanalysis_lib_c as clc
    num_msgs, adrs, key, pk_seed, params = args
    slh = fips205.SLH_DSA(params)
    hp_m    = ((1 << slh.hp) - 1)
    
    # this is probably wrong, double-check this
    i_tree = adrs.get_tree_index()
    i_tree = i_tree << slh.hp
    i_leaf = i_tree & hp_m
    
    x_adrs: fips205.ADRS = adrs.copy()
    x_adrs.set_layer_address(i_leaf)
    x_adrs.set_tree_address(i_tree)

    # Create and populate the context
    ctx = clc.SPXCtx()
    # Copy pk into ctx.pub_seed
    for i in range(clc.SPX_N):
        ctx.pub_seed[i] = pk_seed[i]

    # --- 6. Allocate output buffer for root ---
    root_buf = (clc.ctypes.c_ubyte * clc.SPX_N)()

    # --- 8. Retrieve the result as Python bytes ---
    root = bytes(root_buf[:])
    print("Computed Merkle root:", root.hex())

    
    success = 0
    for _ in range(num_msgs):
        # generate a random SK seed
        sk_seed = random.randbytes(slh.n)
        # Copy sk into ctx.sk_seed
        for i in range(clc.SPX_N):
            ctx.sk_seed[i] = random.randint(0, 255)
        # --- 7. Call the C function ---
        clc.lib.merkle_gen_root(root_buf, clc.ctypes.byref(ctx))

        
    return success