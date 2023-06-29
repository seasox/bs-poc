use rand::rngs::ThreadRng;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, Verifier};
use rsa::RsaPrivateKey;

use crate::memory::Memory;

pub struct RsaCrt<'a> {
    rng: &'a mut ThreadRng,
    signing_key: &'a SigningKey<Sha256>,
    verifying_key: VerifyingKey<Sha256>,
}

impl<'a> RsaCrt<'a> {
    pub fn new(
        mem: &'a Memory,
        rng: &'a mut ThreadRng,
    ) -> Result<RsaCrt<'a>, Box<dyn std::error::Error>> {
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(rng, bits).expect("failed to generate a key");
        let mut sk = SigningKey::<Sha256>::new(priv_key);
        // move signing key to mem
        let signing_key = mem.move_object(&mut sk, 0).expect("mem move failed");
        let verifying_key: VerifyingKey<Sha256> = signing_key.verifying_key();
        Ok(RsaCrt {
            rng,
            signing_key,
            verifying_key,
        })
    }

    pub fn sign(&mut self, msg: &[u8]) -> Signature {
        self.signing_key.sign_with_rng(self.rng, msg)
    }

    pub fn verify(&mut self, msg: &[u8], sig: &Signature) -> bool {
        match self.verifying_key.verify(msg, sig) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
