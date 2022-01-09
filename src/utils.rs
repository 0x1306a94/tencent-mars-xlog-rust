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

pub fn tea_decrypt(v: &mut [u32], k: &mut [u32]) {
    let mut v0 = v[0];
    let mut v1 = v[1];
    let mut sum: u32 = 0;
    let delta: u32 = 0x9e3779b9;
    let totalSum: u32 = 0x9e3779b9 << 4;

    sum = totalSum;
    let k0 = k[0];
    let k1 = k[1];
    let k2 = k[2];
    let k3 = k[3];
    for _ in 0..16 {
        let t1 =
            ((v0 << 4).wrapping_add(k2)) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(k3));
        v1 = v1.wrapping_sub(t1);

        let t0 =
            ((v1 << 4).wrapping_add(k0)) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(k1));
        v0 = v0.wrapping_sub(t0);

        sum = sum.wrapping_sub(delta);
    }
    v[0] = v0;
    v[1] = v1;
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
