import fips205
def process_sig(args):
    params, pk, sig, sig_len = args
    slh = fips205.SLH_DSA(params)
    pk_seed = pk[:slh.n]
    m = sig[sig_len:]
    sig = sig[:sig_len]
    valid = slh.slh_verify_internal(m, sig, pk)
    for adrs, keys in slh.wots_keys.items():
        for key in keys:
            chain_adrs = adrs.copy()
            chain_adrs.set_type_and_clear(fips205.ADRS.WOTS_HASH)
            chain_adrs.set_key_pair_address(adrs.get_key_pair_address())
            key.calculate_intermediates(params, chain_adrs, pk_seed)
            key.valid = valid
    return slh.wots_keys
