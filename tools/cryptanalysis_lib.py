import fips205
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