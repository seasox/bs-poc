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

# Post-process all WOTS keys for a given address
def process_wots_keys(args):
    params, adrs, keys, pk_seed = args
    c_adrs = adrs.copy()
    c_adrs.set_type_and_clear(fips205.ADRS.WOTS_HASH)
    c_adrs.set_key_pair_address(adrs.get_key_pair_address())
    print("Post-processing " + str(len(keys)) + " WOTS keys")
    for key in keys:
        key.calculate_intermediates(params, c_adrs, pk_seed)
    return key

def sign_worker(args):
    """Sign `num_msgs` messages for a single (adrs, key)."""
    num_msgs, msg_len, adrs, key, pk_seed, params = args
    success = 0
    msgs = [random.randint(0, 15) for _ in range(num_msgs*msg_len)]
    # msgs = random.randbytes(num_msgs * 32)
    for i in range(num_msgs):
        if key.try_sign(msgs[i*msg_len:(i+1)*msg_len], adrs, pk_seed, params):
            success += 1
    return success
