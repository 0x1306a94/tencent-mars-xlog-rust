use std::{fmt::Write, num::ParseIntError};

use micro_uecc_safe;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub struct UEcckeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn gen_key_pair() -> Option<UEcckeyPair> {
    match micro_uecc_safe::uecc_mkae_key_with_secp2561k1() {
        None => None,
        Some((private_key, public_key)) => Some(UEcckeyPair {
            private_key,
            public_key,
        }),
    }
}
