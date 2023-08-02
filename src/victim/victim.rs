use std::pin::Pin;

use rand::rngs::ThreadRng;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, Verifier};
use rsa::RsaPrivateKey;

use crate::memory::Memory;

#[derive(Debug)]
pub struct RsaCrt {
    rng: ThreadRng,
    signing_key: SigningKey<Sha256>,
    verifying_key: VerifyingKey<Sha256>,
}

impl RsaCrt {
    pub fn new(
        mut rng: ThreadRng,
        mem: &Memory,
        offset: usize,
    ) -> Result<Pin<&mut RsaCrt>, Box<dyn std::error::Error>> {
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let verifying_key = signing_key.verifying_key();
        let rsa = RsaCrt {
            rng,
            signing_key,
            verifying_key,
        };
        // move RSA struct to mem
        let rsa_p = unsafe { mem.move_object(rsa, offset) };
        Ok(rsa_p)
    }

    pub fn sign(&mut self, msg: &[u8]) -> Result<Signature, rsa::signature::Error> {
        self.signing_key.try_sign_with_rng(&mut self.rng, msg)
    }

    pub fn verify(&mut self, msg: &[u8], sig: &Signature) -> bool {
        match self.verifying_key.verify(msg, sig) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
