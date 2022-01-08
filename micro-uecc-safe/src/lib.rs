use micro_uecc_sys;

pub fn uecc_mkae_key_with_secp2561() -> Option<(String, String)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gen_key_pair() {
        match uecc_mkae_key_with_secp2561() {
            None => println!("生成失败"),
            Some((private_key, public_key)) => {
                println!("private_key: {}", private_key);
                println!("public_key: {}", public_key);
            }
        };
    }
}
