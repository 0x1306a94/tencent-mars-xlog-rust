use flate2::bufread;
use memmap::Mmap;
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::io::Write;

mod utils {
    use std::{fmt::Write, num::ParseIntError};

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
        let delta: u32 = 0x9e3779b9;
        let total_sum: u32 = 0x9e3779b9 << 4;

        let mut sum: u32 = total_sum;
        let k0 = k[0];
        let k1 = k[1];
        let k2 = k[2];
        let k3 = k[3];
        for _ in 0..16 {
            let t1 = ((v0 << 4).wrapping_add(k2))
                ^ (v0.wrapping_add(sum))
                ^ ((v0 >> 5).wrapping_add(k3));
            v1 = v1.wrapping_sub(t1);

            let t0 = ((v1 << 4).wrapping_add(k0))
                ^ (v1.wrapping_add(sum))
                ^ ((v1 >> 5).wrapping_add(k1));
            v0 = v0.wrapping_sub(t0);

            sum = sum.wrapping_sub(delta);
        }
        v[0] = v0;
        v[1] = v1;
    }
}

pub trait ReadInteger<T> {
    fn from_le_bytes(data: &[u8]) -> T;
    fn from_be_bytes(data: &[u8]) -> T;
}

macro_rules! impl_read_integer {
    ($($t:ty),+) => {
        $(impl ReadInteger<$t> for $t {
            fn from_le_bytes(data: &[u8]) -> $t {
                <$t>::from_le_bytes(data.try_into().unwrap())
            }
            fn from_be_bytes(data: &[u8]) -> $t {
                <$t>::from_be_bytes(data.try_into().unwrap())
            }
        })+
    }
}

impl_read_integer!(u8, i16, u16, i32, u32, i64);

fn read_integer<T: ReadInteger<T>>(data: &[u8]) -> T {
    T::from_le_bytes(&data[..std::mem::size_of::<T>()])
}

mod magic {
    pub const CRYPT_START: u8 = 0x01;
    pub const COMPRESS_CRYPT_START: u8 = 0x02;
    pub const NO_COMPRESS_START: u8 = 0x03;
    pub const NO_COMPRESS_START1: u8 = 0x06;
    pub const NO_COMPRESS_NO_CRYPT_START: u8 = 0x08;
    pub const COMPRESS_START: u8 = 0x04;
    pub const COMPRESS_START1: u8 = 0x05;
    pub const COMPRESS_START2: u8 = 0x07;
    pub const COMPRESS_NO_CRYPT_START: u8 = 0x09;

    pub const SYNC_ZLIB_START: u8 = 0x06;
    pub const SYNC_NO_CRYPT_ZLIB_START: u8 = 0x08;
    pub const SYNC_ZSTD_START: u8 = 0x0A;
    pub const SYNC_NO_CRYPT_ZSTD_START: u8 = 0x0B;
    pub const ASYNC_ZSTD_START: u8 = 0x0C;
    pub const ASYNC_NO_CRYPT_ZSTD_START: u8 = 0x0D;

    pub const END: u8 = 0x00;
}

const BASE_KEY: u8 = 0xcc;
const TEA_BLOCK_LEN: u8 = 8;

pub struct Context {
    input: String,
    output: String,
    private_key: String,
    last_seq: i16,
}

struct InputBuffer {
    mmap: Mmap,
    file_len: usize,
    pos: usize,
}

impl InputBuffer {
    fn new(path: &str) -> anyhow::Result<InputBuffer> {
        let in_file = File::open(path)?;
        let in_file_len = in_file.metadata()?.len() as usize;
        let in_mmap = unsafe { Mmap::map(&in_file)? };

        let buf = InputBuffer {
            mmap: in_mmap,
            file_len: in_file_len,
            pos: 0,
        };

        return Ok(buf);
    }

    fn len(&self) -> usize {
        self.file_len
    }

    fn cur_pos(&self) -> usize {
        self.pos
    }

    fn all_bytes(&self) -> &[u8] {
        &self.mmap[0..self.file_len]
    }

    fn bytes(&self) -> &[u8] {
        &self.mmap[self.pos..]
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos
    }

    fn bytes_at(&self, pos: usize) -> &[u8] {
        &self.mmap[pos..]
    }

    fn range_bytes(&self, pos: usize, len: usize) -> &[u8] {
        if (pos + len) > self.file_len {
            panic!("越界");
        }
        &self.mmap[pos..pos + len]
    }
}

struct OutputBufFile {
    file: File,
    write_pos: usize,
}

impl OutputBufFile {
    fn new(path: &str) -> anyhow::Result<OutputBufFile> {
        let out_file = OpenOptions::new()
            .write(true)
            // .read(true)
            // .append(true)
            .truncate(true)
            .create(true)
            .open(&path)?;

        // out_file.write_all([0x0]);

        let buf = OutputBufFile {
            file: out_file,
            write_pos: 0,
        };

        return Ok(buf);
    }

    fn appen_str(&mut self, str: &str) -> Result<(), io::Error> {
        if str.len() == 0 {
            return Ok(());
        }
        let bytes = str.as_bytes();
        if let Err(e) = self.file.write_all(bytes) {
            return Err(e);
        } else {
            self.write_pos = bytes.len();
            return Ok(());
        }
    }

    fn appen_bytes(&mut self, bytes: &[u8]) -> Result<(), io::Error> {
        if bytes.len() == 0 {
            return Ok(());
        }
        if let Err(e) = self.file.write_all(bytes) {
            return Err(e);
        } else {
            self.write_pos = bytes.len();
            return Ok(());
        }
    }

    fn flush(&mut self) {
        self.file.flush();
    }
}

impl Context {
    fn decode_buf(
        &mut self,
        input_buf_file: &mut InputBuffer,
        offset: &mut usize,
        output_buf_file: &mut OutputBufFile,
    ) -> anyhow::Result<usize> {
        let in_buf_len = input_buf_file.len();
        if *offset >= in_buf_len {
            let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer");
            return Err(anyhow::Error::new(eof));
        }
        let in_buf = input_buf_file.bytes();
        if !is_good_log_buf(in_buf, *offset, 1) {
            let bytes = input_buf_file.bytes_at(*offset);
            if let Some(fixpos) = get_log_start_pos(bytes, 1) {
                output_buf_file.appen_str(&format!(
                    "[F]decode_log_file.py decode err|| len= {:?}\n",
                    fixpos
                ))?;
                *offset += fixpos;
            } else {
                return Err(anyhow::anyhow!("无法获取 log start pos"));
            }
        }

        let mut crypt_key_len: usize = 0;
        let magic_value = input_buf_file.bytes_at(*offset)[0];
        if magic::NO_COMPRESS_START == magic_value
            || magic::COMPRESS_START == magic_value
            || magic::COMPRESS_START1 == magic_value
        {
            crypt_key_len = 4
        } else if magic::COMPRESS_START2 == magic_value
            || magic::NO_COMPRESS_START1 == magic_value
            || magic::NO_COMPRESS_NO_CRYPT_START == magic_value
            || magic::COMPRESS_NO_CRYPT_START == magic_value
            || magic::SYNC_ZSTD_START == magic_value
            || magic::SYNC_NO_CRYPT_ZSTD_START == magic_value
            || magic::ASYNC_ZSTD_START == magic_value
            || magic::ASYNC_NO_CRYPT_ZSTD_START == magic_value
        {
            crypt_key_len = 64
        } else {
            output_buf_file.appen_str(&format!(
                "in DecodeBuffer _buffer[{:?}]:{:?} != NUM_START\n",
                *offset, magic_value
            ))?;
            return Err(anyhow::anyhow!("无法获取 log start pos"));
        }

        let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
        let start = *offset + header_len - 4 - crypt_key_len;
        let len_bytes = input_buf_file.bytes_at(start);
        let length = read_integer::<u32>(len_bytes) as usize;

        let pos = *offset + header_len - 4 - crypt_key_len - 2 - 2;
        let sqe_bytes = input_buf_file.bytes_at(pos);
        let seq = read_integer::<i16>(sqe_bytes);

        if seq != 0 && seq != 1 && self.last_seq != 0 && seq != (self.last_seq + 1) {
            output_buf_file.appen_str(&format!(
                "[F]decode_log_file.py log seq:{:?}-{:?} is missing\n",
                self.last_seq + 1,
                seq - 1
            ))?;
        }

        if seq != 0 {
            self.last_seq = seq;
        }

        let pos = *offset + header_len;
        let data = input_buf_file.range_bytes(pos, length);
        let mut content_buf: Vec<u8> = Vec::with_capacity(length);
        content_buf.extend_from_slice(data);

        let input_buf = input_buf_file.all_bytes();
        let magic_value = input_buf[*offset];

        let is_crypt = self.private_key.len() > 0;
        if is_crypt
            && (magic::SYNC_ZLIB_START == magic_value
                || magic::SYNC_NO_CRYPT_ZLIB_START == magic_value
                || magic::SYNC_ZSTD_START == magic_value
                || magic::SYNC_NO_CRYPT_ZSTD_START == magic_value)
        {
            output_buf_file.appen_bytes(data)?;
        } else if !is_crypt
            && (magic::NO_COMPRESS_START1 == magic_value
                || magic::COMPRESS_START2 == magic_value
                || magic::SYNC_ZSTD_START == magic_value
                || magic::ASYNC_ZSTD_START == magic_value)
        {
            output_buf_file.appen_str("use wrong decode script\n")?;
        } else if is_crypt
            && (magic::COMPRESS_START2 == magic_value || magic::ASYNC_ZSTD_START == magic_value)
        {
            // 解密

            let mut client_pub_key: Vec<u8> = vec![0; crypt_key_len];
            let pos = *offset + header_len - crypt_key_len;
            let len = crypt_key_len;
            let data = input_buf_file.range_bytes(pos, len);
            client_pub_key.copy_from_slice(data);

            let mut svr_priate_key: Vec<u8> = vec![0];
            if let Ok(decode) = utils::decode_hex(&self.private_key) {
                svr_priate_key = decode;
            } else {
                return Err(anyhow::anyhow!("Get ECDH key error"));
            }

            let mut ecdh_buf = vec![0; 32];
            if let None = micro_uecc_safe::ucc_shared_secret_whith_secp2561k1(
                &mut client_pub_key,
                &mut svr_priate_key,
                &mut ecdh_buf,
            ) {
                return Err(anyhow::anyhow!("Get ECDH key error"));
            }

            let mut tea_key = vec![0; 4];
            for i in 0..4 {
                let start = i * 4;
                let end = start + 4;
                let bytes = &ecdh_buf[start..end];
                let t1 = read_integer::<u32>(bytes);
                tea_key[i] = t1;
            }

            let tea_block_len = TEA_BLOCK_LEN as usize;
            let cnt = length / tea_block_len;
            for i in 0..cnt {
                let start = i * tea_block_len;
                let end = start + tea_block_len;

                let bytes = &content_buf[start..end - 4];
                let t1 = read_integer::<u32>(bytes);
                let bytes = &content_buf[start + 4..end];
                let t2 = read_integer::<u32>(bytes);
                let mut tmp = vec![t1, t2];

                utils::tea_decrypt(&mut tmp, &mut tea_key);

                for i in 0..2 {
                    let x = tmp[i];
                    let b1: u8 = ((x >> 24) & 0xff) as u8;
                    let b2: u8 = ((x >> 16) & 0xff) as u8;
                    let b3: u8 = ((x >> 8) & 0xff) as u8;
                    let b4: u8 = (x & 0xff) as u8;
                    content_buf[start + i * 4] = b4;
                    content_buf[start + i * 4 + 1] = b3;
                    content_buf[start + i * 4 + 2] = b2;
                    content_buf[start + i * 4 + 3] = b1;
                }
                // output_buf_file.appen_str(&format!("0x{:08X} 0x{:08X}\n", tmp[0], tmp[1]));
                // println!("0x{:08X} 0x{:08X}", tmp[0], tmp[1]);
            }

            if magic::COMPRESS_START2 == magic_value {
                // zlib
                self.zlib_decompress(output_buf_file, &content_buf)?;
            } else {
                // zstd
                self.zstd_decompress(output_buf_file, &content_buf)?;
            }
        } else if magic::ASYNC_NO_CRYPT_ZSTD_START == magic_value {
            // zstd
            self.zstd_decompress(output_buf_file, &content_buf)?;
        } else if magic::COMPRESS_START == magic_value
            || magic::COMPRESS_NO_CRYPT_START == magic_value
        {
            // zlib
            self.zlib_decompress(output_buf_file, &content_buf)?;
        } else if magic::COMPRESS_START1 == magic_value {
            let mut decompress_buf: Vec<u8> = Vec::with_capacity(1024);

            let mut tmpbuffer = &content_buf[0..];
            while tmpbuffer.len() > 0 {
                let single_log_len = read_integer::<u16>(&tmpbuffer[0..2]) as usize;
                decompress_buf.extend_from_slice(&tmpbuffer[2..single_log_len + 2]);
                tmpbuffer = &tmpbuffer[single_log_len + 2..];
            }
            // zlib
            self.zlib_decompress(output_buf_file, &decompress_buf)?;
        } else {
            output_buf_file.appen_bytes(&content_buf)?;
        }

        // TODO: 暂时中断
        return Ok(*offset + header_len + length + 1);
    }

    fn zlib_decompress(
        &self,
        output_buf_file: &mut OutputBufFile,
        content_buf: &[u8],
    ) -> anyhow::Result<()> {
        if content_buf.len() == 0 {
            return Ok(());
        }
        let mut gz = bufread::DeflateDecoder::new(content_buf);
        let mut s = Vec::new();
        // if let Err(err) = gz.read_to_end(&mut s) {
        //     return Err(anyhow::Error::new(err));
        // } else {
        //     output_buf_file.appen_bytes(&s)?;
        // };

        match gz.read_to_end(&mut s) {
            Ok(_) => {
                output_buf_file.appen_bytes(&s)?;
            }
            Err(err) => {
                return Err(anyhow::Error::new(err));
            }
        }

        Ok(())
    }

    fn zstd_decompress(
        &self,
        output_buf_file: &mut OutputBufFile,
        content_buf: &[u8],
    ) -> anyhow::Result<()> {
        if content_buf.len() == 0 {
            return Ok(());
        }
        match zstd::stream::decode_all(content_buf) {
            Ok(decompress) => {
                output_buf_file.appen_bytes(&decompress)?;
            }
            Err(e) => {
                return Err(anyhow::Error::new(e));
            }
        }

        Ok(())
    }
}

impl Context {
    pub fn new(input: String, output: String, private_key: String) -> Context {
        Context {
            input,
            output,
            private_key,
            last_seq: 0,
        }
    }

    pub fn decode(&mut self) -> anyhow::Result<()> {
        let mut input_buf_file = InputBuffer::new(&self.input)?;
        let in_buf_bytes = input_buf_file.bytes();

        let mut start_pos: usize = 0;
        match get_log_start_pos(in_buf_bytes, 2) {
            Some(it) => start_pos = it,
            None => return Err(anyhow::anyhow!("无效 Xlog 文件")),
        };

        let mut output_buf_file = OutputBufFile::new(&self.output)?;
        loop {
            match self.decode_buf(&mut input_buf_file, &mut start_pos, &mut output_buf_file) {
                Ok(pos) => {
                    start_pos = pos;
                }
                Err(e) => {
                    let root_cause = e.root_cause();
                    if let Some(io_error) = root_cause.downcast_ref::<io::Error>() {
                        if io_error.kind() == io::ErrorKind::UnexpectedEof {
                            return Ok(());
                        }
                    }
                    return Err(e);
                }
            }
        }
    }
}

fn is_good_log_buf(buf: &[u8], offset: usize, count: i8) -> bool {
    if offset == buf.len() {
        return true;
    }
    let mut crypt_key_len: usize = 0;
    let magic_value = buf[offset];
    if magic::NO_COMPRESS_START == magic_value
        || magic::COMPRESS_START == magic_value
        || magic::COMPRESS_START1 == magic_value
    {
        crypt_key_len = 4;
    } else if magic::COMPRESS_START2 == magic_value
        || magic::NO_COMPRESS_START1 == magic_value
        || magic::NO_COMPRESS_NO_CRYPT_START == magic_value
        || magic::COMPRESS_NO_CRYPT_START == magic_value
        || magic::SYNC_ZSTD_START == magic_value
        || magic::SYNC_NO_CRYPT_ZSTD_START == magic_value
        || magic::ASYNC_ZSTD_START == magic_value
        || magic::ASYNC_NO_CRYPT_ZSTD_START == magic_value
    {
        crypt_key_len = 64;
    } else {
        return false;
    }

    let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
    if (offset + header_len + 1 + 1) > buf.len() {
        return false;
    }

    let start = offset + header_len - crypt_key_len - 4;
    let end = start + 4;
    let bytes = &buf[start..end];
    let length = read_integer::<u32>(bytes) as usize;
    if (offset + header_len + length + 1) > buf.len() {
        return false;
    }
    if magic::END != buf[offset + header_len + length] {
        return false;
    }
    if count >= 1 {
        return true;
    }
    return is_good_log_buf(buf, offset + header_len + length + 1, count - 1);
}

fn get_log_start_pos(buf: &[u8], count: i8) -> Option<usize> {
    let mut offset: usize = 0;
    loop {
        if offset >= buf.len() {
            break;
        }
        let magic_value = buf[offset];
        if magic::NO_COMPRESS_START == magic_value
            || magic::NO_COMPRESS_START1 == magic_value
            || magic::COMPRESS_START == magic_value
            || magic::COMPRESS_START1 == magic_value
            || magic::COMPRESS_START2 == magic_value
            || magic::COMPRESS_NO_CRYPT_START == magic_value
            || magic::NO_COMPRESS_NO_CRYPT_START == magic_value
            || magic::SYNC_ZSTD_START == magic_value
            || magic::SYNC_NO_CRYPT_ZSTD_START == magic_value
            || magic::ASYNC_ZSTD_START == magic_value
            || magic::ASYNC_NO_CRYPT_ZSTD_START == magic_value
        {
            if is_good_log_buf(buf, offset, count) {
                return Some(offset);
            }
        }
        offset += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use walkdir::WalkDir;

    #[test]
    fn decode_test() {
        let pwd = std::env::var("PWD").unwrap();
        println!("pwd: {:?}", pwd);
        let sample_data_path = PathBuf::from(pwd).join("sample_data");
        println!("sample_data_path: {:?}", sample_data_path);

        let input = sample_data_path.join("encrypt_sample_data.xlog");

        let output = sample_data_path.join("encrypt_sample_data.xlog.log");

        let env_path = sample_data_path.join("custom.env");
        println!("env_path: {:?}", env_path);
        dotenv::from_path(env_path.as_path()).ok().unwrap();

        let private_key = std::env::var("TEST_XLOG_PRIVATE_KEY").unwrap_or("".to_string());
        println!("private_key: {:?}", private_key);

        let input_path = String::from(input.to_str().unwrap());
        let output_path = String::from(output.to_str().unwrap());
        let mut ctx = Context::new(input_path, output_path, private_key);
        match ctx.decode() {
            Ok(_) => println!("成功"),
            Err(e) => {
                assert!(false, "{:?}", e.root_cause());
            }
        }
    }

    #[test]
    fn decode_all_test() {
        let pwd = std::env::var("PWD").unwrap();
        println!("pwd: {:?}", pwd);
        let sample_data_path = PathBuf::from(pwd).join("sample_data");
        println!("sample_data_path: {:?}", sample_data_path);

        let env_path = sample_data_path.join("custom.env");
        println!("env_path: {:?}", env_path);
        dotenv::from_path(env_path.as_path()).ok().unwrap();

        for entry in WalkDir::new(sample_data_path) {
            let entry = entry.unwrap();
            if entry.path().is_dir() {
                continue;
            }

            let file_name = entry.file_name().to_str().unwrap();

            let extension = entry.path().extension().unwrap().to_str();

            if !file_name.starts_with("z") || extension != Some("xlog") {
                continue;
            }

            let pwd = std::env::var("PWD").unwrap();
            let sample_data_path = PathBuf::from(pwd).join("sample_data");
            let mut output = sample_data_path.join(file_name);
            output.set_extension("xlog.log");

            let input_path = String::from(entry.path().to_str().unwrap());
            let output_path = String::from(output.to_str().unwrap());

            println!("input_path: {:?}", input_path);
            println!("output_path: {:?}", output_path);
            if file_name.contains("_crypt_") {
                // 加密日志
                let private_key = std::env::var("TEST_XLOG_PRIVATE_KEY").unwrap_or("".to_string());
                println!("private_key: {:?}", private_key);
                let mut ctx = Context::new(input_path, output_path, private_key);
                match ctx.decode() {
                    Ok(_) => println!("成功"),
                    Err(e) => {
                        assert!(false, "{:?}", e.root_cause());
                    }
                }
            } else {
                // 未加密日志
                let mut ctx = Context::new(input_path, output_path, String::new());
                match ctx.decode() {
                    Ok(_) => println!("成功"),
                    Err(e) => {
                        assert!(false, "{:?}", e.root_cause());
                    }
                }
            }
        }
    }
}
