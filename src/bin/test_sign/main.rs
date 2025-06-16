use swage::{crypto_sign_open, victim::sphincs_plus::ReadLine};

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut child = std::process::Command::new("victims/sphincsplus/ref/test/server")
        .arg("keys.txt")
        .arg("7")
        .env_clear()
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut stdout = child.stdout.take().unwrap();

    loop {
        let sig = stdout.read_line()?;
        println!("sig: {} [...]", &sig[..50]);

        unsafe {
            let sm = hex::decode(sig)?;
            let smlen = sm.len() as u64;
            let keys_content = std::fs::read_to_string("keys.txt")?;
            let pk_hex = keys_content
                .lines()
                .find(|line| line.starts_with("pk:"))
                .ok_or_else(|| anyhow::anyhow!("Public key not found in keys.txt"))?
                .trim_start_matches("pk:")
                .trim();
            let pk = hex::decode(pk_hex)?;
            let mut m = sm.clone();
            let mut mlen = smlen;
            let ret = crypto_sign_open(m.as_mut_ptr(), &mut mlen, sm.as_ptr(), smlen, pk.as_ptr());
            assert_eq!(ret, 0);
            println!(
                "msg = {}",
                String::from_utf8(m[..mlen as usize].to_vec()).expect("Failed to convert to UTF-8")
            );
        }
    }
}
