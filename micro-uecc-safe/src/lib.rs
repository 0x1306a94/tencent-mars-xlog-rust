use micro_uecc_sys;

pub fn uecc_mkae_key_with_secp2561k1() -> Option<(String, String)> {
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256k1();
        let prlen = micro_uecc_sys::uECC_curve_private_key_size(curve) as usize;
        let plen = micro_uecc_sys::uECC_curve_public_key_size(curve) as usize;
        let mut private_key_buf = vec![0; prlen];
        let mut public_key_buf = vec![0; plen];
        let ret =
            micro_uecc_sys::uECC_make_key(&mut public_key_buf[0], &mut private_key_buf[0], curve);
        if ret != 1 {
            assert!(false, "生成失败");
            return None;
        }
        let private_key = private_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)?;

        let public_key = public_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)?;

        assert!(private_key.len() > 0, "生成失败");
        assert!(public_key.len() > 0, "生成失败");
        Some((private_key, public_key))
    }
}

pub fn ucc_shared_secret_whith_secp2561k1(
    pub_key_buf: &mut [u8],
    priv_key_buf: &mut [u8],
    ecdh_buf: &mut [u8],
) -> Option<()> {
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256k1();
        let ret = micro_uecc_sys::uECC_shared_secret(
            &mut pub_key_buf[0],
            &mut priv_key_buf[0],
            &mut ecdh_buf[0],
            curve,
        );
        if ret == 1 {
            Some(())
        } else {
            None
        }
    }
}

pub struct UEcckeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn gen_secp2561k1_key_pair() -> Option<UEcckeyPair> {
    match uecc_mkae_key_with_secp2561k1() {
        None => None,
        Some((private_key, public_key)) => Some(UEcckeyPair {
            private_key,
            public_key,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gen_secp2561k1_key_pair() {
        match uecc_mkae_key_with_secp2561k1() {
            None => println!("生成失败"),
            Some((private_key, public_key)) => {
                println!("private_key: {}", private_key);
                println!("public_key: {}", public_key);
            }
        };
    }
}
