

def is_exploitable(sig_correct, sig_faulted, secrets_path):
    if len(sig_correct) != len(sig_faulted):
        print("The two signatures do not have the same length")
        return False
    with open(secrets_path, "r") as file:
        lines = file.readlines()
    
    w = 16
    d = 8
    p = 67

    nb_secrets_found_in_correct = 0

    for wots_idx in range(d * p):
        secret_lines = lines[wots_idx * w:(wots_idx + 1) * w]
        
        for intra_idx in range(len(secret_lines)):
            secret = secret_lines[intra_idx].strip()
            if secret in sig_correct:
                nb_secrets_found_in_correct += 1
                break
            if secret in sig_faulted:
                return True

    if nb_secrets_found_in_correct != d * p:
        print("The first signature does not appear to be correct "\
              "given the secrets.txt file")
        assert(False)
    
    return False

def prefix(s1, s2):
    for i in range(min(len(s1), len(s2))):
        if s1[i] != s2[i]:
            return i

def process_experiment(sig_correct_path, sigs_path, secrets_path, logfile, keys_path = "keys.txt", out_dir = "results"):
    from os import path, makedirs
    import zipfile
    import tempfile
    import hashlib
        
    with open(sigs_path, "r") as file:
        sigs = file.readlines()

    with open(sig_correct_path, "r") as file:
        sig_correct = file.readline().strip()
        
    makedirs(out_dir, exist_ok=True)

    sigs_faulted = set([sig.strip() for sig in sigs if sig.strip() != sig_correct])
    print(f"Correct signature: {sig_correct[:100]}")
    print(f"Correct signature length: {len(sig_correct)}")
    print(f"{len(sigs_faulted)} faulted signatures")
    for i, sig in enumerate(sigs_faulted):
        print(f"Faulted signature length: {len(sig)}")
        if len(sig) != len(sig_correct):
            print(f"Signature {i} has a different length than the correct signature.")
            continue
        common_prefix_length = prefix(sig_correct, sig)
        print(f"Length of common prefix between sig and sig_correct: {common_prefix_length}")
        exploitable = is_exploitable(sig_correct, sig, secrets_path)
        print(f"Signature {i} is {'NOT ' if not exploitable else ''}exploitable.")
        with tempfile.NamedTemporaryFile(delete=True, mode='w') as tmpfile_sig_faulty, tempfile.NamedTemporaryFile(delete=True, mode='w') as tmpfile_sig_correct:
            tmpfile_sig_faulty.write(f"{sig}")
            tmpfile_sig_correct.write(f"{sig_correct}")
            shasum = hashlib.sha256(sig.encode()).hexdigest()
            zip_filename = f"exploitable_{shasum}.zip" if exploitable else f"nonexploitable_{shasum}.zip"
            zip_filename = path.join(out_dir, zip_filename)
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                zipf.write(tmpfile_sig_faulty.name, arcname='sig_faulty.txt')
                zipf.write(tmpfile_sig_correct.name, arcname='sig_correct.txt')
                zipf.write(logfile)
                zipf.write(keys_path)
                zipf.write(secrets_path)
            print(f"Wrote zip file {zip_filename}")

if __name__ == '__main__':
    sig_correct_path = "sig_correct.txt"
    sigs_path = "sigs.txt"
    secrets_path = "secrets.txt"
    logfile = "hammer.log"
    process_experiment(sig_correct_path, sigs_path, secrets_path, logfile)