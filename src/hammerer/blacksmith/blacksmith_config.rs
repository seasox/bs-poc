use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum BitDef {
    Single(u64),
    Multi(Vec<u64>),
}

impl BitDef {
    pub fn to_bitstr(&self) -> usize {
        let mut res: usize = 0;
        match self {
            BitDef::Single(bit) => {
                res |= 1 << bit;
            }
            BitDef::Multi(bits) => {
                bits.iter().for_each(|bit| {
                    res |= 1 << bit;
                });
            }
        }
        res
    }
}

#[derive(Deserialize)]
pub struct BlacksmithConfig {
    //name: String,
    //channels: u64,
    //dimms: u64,
    //ranks: u64,
    //total_banks: u64,
    //max_rows: u64,
    pub threshold: u64,
    //hammer_rounds: usize,
    //drama_rounds: usize,
    //acts_per_trefi: u64,
    pub row_bits: Vec<BitDef>,
    pub col_bits: Vec<BitDef>,
    pub bank_bits: Vec<BitDef>,
}

impl BlacksmithConfig {
    pub fn from_jsonfile(filepath: &str) -> anyhow::Result<BlacksmithConfig> {
        let mut file = File::open(Path::new(filepath))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: BlacksmithConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }
}

mod test {
    #[test]
    fn test_bank_function_period() {
        use crate::hammerer::blacksmith::blacksmith_config::BlacksmithConfig;
        use crate::memory::mem_configuration::MemConfiguration;
        let config = BlacksmithConfig::from_jsonfile("config/bs-config.json")
            .expect("failed to read config file");
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        assert_eq!(mem_config.bank_function_period(), 512);
    }
}
