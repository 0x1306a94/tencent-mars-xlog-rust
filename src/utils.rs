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

pub fn gen_key_pair() {
    match micro_uecc_safe::uecc_mkae_key_with_secp2561() {
        None => println!("生成失败"),
        Some((private_key, public_key)) => {
            println!("private_key: {}", private_key);
            println!("public_key: {}", public_key);
        }
    };
}
