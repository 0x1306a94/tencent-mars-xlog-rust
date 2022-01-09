use anyhow::{Error, Result};
use memmap::Mmap;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::PathBuf;

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

    pub const SYNC_ZSTD_START: u8 = 0x0A;
    pub const SYNC_NO_CRYPT_ZSTD_START: u8 = 0x0B;
    pub const ASYNC_ZSTD_START: u8 = 0x0C;
    pub const ASYNC_NO_CRYPT_ZSTD_START: u8 = 0x0D;

    pub const END: u8 = 0x00;
}

const BASE_KEY: u8 = 0xcc;

pub struct Context {
    input: String,
    output: String,
    encrypted: bool,
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

    fn read_range_bytes(&self, pos: usize, len: usize) -> &[u8] {
        if (pos + len) > self.file_len {
            println!("越界");
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
            .create(true)
            .open(&path)?;

        // out_file.write_all([0x0]);

        let buf = OutputBufFile {
            file: out_file,
            write_pos: 0,
        };

        return Ok(buf);
    }

    fn appen_str(&mut self, str: &str) {
        if str.len() == 0 {
            return;
        }
        self.file.write_all(str.as_bytes());
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
        if !is_good_log_buf(in_buf, in_buf_len, *offset, 1) {
            let buf_len = in_buf_len - *offset;
            let bytes = input_buf_file.read_range_bytes(*offset, buf_len);
            match get_log_start_pos(bytes, buf_len, 1) {
                Some(pos) => {
                    output_buf_file.appen_str(&format!(
                        "[F]decode_log_file.py decode err|| len= {:?}\n",
                        pos
                    ));
                    *offset += pos;
                }
                None => {
                    return Err(anyhow::anyhow!("无法获取 log start pos"));
                }
            }
        }

        let mut crypt_key_len: usize = 0;
        let value = input_buf_file.bytes()[0];
        if magic::NO_COMPRESS_START == value
            || magic::COMPRESS_START == value
            || magic::COMPRESS_START1 == value
        {
            crypt_key_len = 4
        } else if magic::COMPRESS_START2 == value
            || magic::NO_COMPRESS_START1 == value
            || magic::NO_COMPRESS_NO_CRYPT_START == value
            || magic::COMPRESS_NO_CRYPT_START == value
            || magic::SYNC_ZSTD_START == value
            || magic::SYNC_NO_CRYPT_ZSTD_START == value
            || magic::ASYNC_ZSTD_START == value
            || magic::ASYNC_NO_CRYPT_ZSTD_START == value
        {
            crypt_key_len = 64
        } else {
            output_buf_file.appen_str(&format!(
                "in DecodeBuffer _buffer[{:?}]:{:?} != NUM_START\n",
                *offset, value
            ));
            return Err(anyhow::anyhow!("无法获取 log start pos"));
        }

        let header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
        let start = *offset + header_len - crypt_key_len - 4;
        let len_bytes = input_buf_file.read_range_bytes(start, 4);
        let length = read_integer::<u32>(len_bytes) as usize;

        let pos = *offset + header_len - crypt_key_len - 4 - 2 - 2;
        let sqe_bytes = input_buf_file.read_range_bytes(pos, 2);
        let seq = read_integer::<i16>(sqe_bytes);
        let pos = *offset + header_len - crypt_key_len - 4 - 1 - 1;
        let begin_hour = input_buf_file.read_range_bytes(pos, 1)[0];
        let pos = *offset + header_len - crypt_key_len - 4 - 1;
        let end_hour = input_buf_file.read_range_bytes(pos, 1)[0];
        let v = input_buf_file.all_bytes()[*offset] as i32;
        let key = ((BASE_KEY as i32) ^ (0xff & (seq as i32)) ^ v);

        if seq != 0 && seq != 1 && self.last_seq != 0 && seq != (self.last_seq + 1) {
            output_buf_file.appen_str(&format!(
                "[F]decode_log_file.py log seq:{:?}-{:?} is missing\n",
                self.last_seq + 1,
                seq - 1
            ));
        }

        if seq != 0 {
            self.last_seq = seq;
        }

        let pos = *offset + header_len;
        let len = length;
        let temp_bytes = input_buf_file.read_range_bytes(pos, len);
        let value = input_buf_file.all_bytes()[*offset];

        if self.encrypted {
            if magic::NO_COMPRESS_START1 == value || magic::SYNC_ZSTD_START == value {
                // pass
                output_buf_file.appen_str("pass\n");
            } else if magic::COMPRESS_START2 == value || magic::ASYNC_ZSTD_START == value {
                // 加密
            } else if magic::ASYNC_NO_CRYPT_ZSTD_START == value {
            }
        } else {
            if magic::NO_COMPRESS_START1 == value
                || magic::COMPRESS_START2 == value
                || magic::SYNC_ZSTD_START == value
                || magic::ASYNC_ZSTD_START == value
            {
                println!("use wrong decode script");
                output_buf_file.appen_str("use wrong decode script\n");
            }
        }
        // TODO: 暂时中断
        output_buf_file.appen_str(&format!("pos: {:?}\n", *offset + header_len + length + 1));
        return Ok(*offset + header_len + length + 1);
    }
}

impl Context {
    pub fn new(input: String, output: String, encrypted: bool) -> Context {
        Context {
            input,
            output,
            encrypted,
            last_seq: 0,
        }
    }

    pub fn decode(&mut self) -> anyhow::Result<()> {
        let mut input_buf_file = InputBuffer::new(&self.input)?;
        let in_buf_bytes = input_buf_file.bytes();
        let in_buf_len = input_buf_file.len();

        let mut start_pos: usize = 0;
        match get_log_start_pos(in_buf_bytes, in_buf_len, 2) {
            Some(it) => start_pos = it,
            None => return Err(anyhow::anyhow!("无效 Xlog 文件")),
        };
        println!("start_pos: {:?}", start_pos);

        let mut output_buf_file = OutputBufFile::new(&self.output)?;
        loop {
            match self.decode_buf(&mut input_buf_file, &mut start_pos, &mut output_buf_file) {
                Ok(pos) => {
                    start_pos = pos;
                    println!("start_pos: {:?}", start_pos);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

fn is_good_log_buf(buf: &[u8], buf_len: usize, offset: usize, count: i8) -> bool {
    if offset == buf_len {
        return true;
    }
    let mut crypt_key_len: usize = 0;
    let mut header_len: usize = 0;
    let value = buf[offset];
    if magic::NO_COMPRESS_START == value
        || magic::COMPRESS_START == value
        || magic::COMPRESS_START1 == value
    {
        crypt_key_len = 4;
    } else if magic::COMPRESS_START2 == value
        || magic::NO_COMPRESS_START1 == value
        || magic::NO_COMPRESS_NO_CRYPT_START == value
        || magic::COMPRESS_NO_CRYPT_START == value
        || magic::SYNC_ZSTD_START == value
        || magic::SYNC_NO_CRYPT_ZSTD_START == value
        || magic::ASYNC_ZSTD_START == value
        || magic::ASYNC_NO_CRYPT_ZSTD_START == value
    {
        crypt_key_len = 64;
    } else {
        return false;
    }

    header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len;
    if (offset + header_len + 1 + 1) > buf_len {
        return false;
    }

    let start = offset + header_len - crypt_key_len - 4;
    let end = start + 4;
    let bytes = &buf[start..end];
    let length = read_integer::<u32>(bytes) as usize;
    if (offset + header_len + length + 1) > buf_len {
        return false;
    }
    if magic::END != buf[offset + header_len + length] {
        return false;
    }
    if count >= 1 {
        return true;
    }
    return is_good_log_buf(buf, buf_len, offset + header_len + length + 1, count - 1);
}

fn get_log_start_pos(buf: &[u8], buf_len: usize, count: i8) -> Option<usize> {
    let mut offset: usize = 0;
    loop {
        if offset >= buf_len {
            break;
        }
        let value = buf[offset];
        if magic::NO_COMPRESS_START == value
            || magic::NO_COMPRESS_START1 == value
            || magic::COMPRESS_START == value
            || magic::COMPRESS_START1 == value
            || magic::COMPRESS_START2 == value
            || magic::COMPRESS_NO_CRYPT_START == value
            || magic::NO_COMPRESS_NO_CRYPT_START == value
            || magic::SYNC_ZSTD_START == value
            || magic::SYNC_NO_CRYPT_ZSTD_START == value
            || magic::ASYNC_ZSTD_START == value
            || magic::ASYNC_NO_CRYPT_ZSTD_START == value
        {
            if is_good_log_buf(buf, buf_len, offset, count) {
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
    #[test]
    fn get_log_start_pos_test() {
        let path = "/Users/king/Documents/test/imsdk_C_20220107.xlog";
        let input_buf = InputBuffer::new(path).unwrap();
        let bytes = input_buf.bytes();
        let buf_len = input_buf.len();
        let pos = get_log_start_pos(bytes, buf_len, 2).unwrap();
        assert_eq!(pos, 0, "失败了");
    }

    #[test]
    fn decode_test() {
        let input = String::from("/Users/king/Documents/test/common_20220108.xlog");
        let output = String::from("/Users/king/Documents/test/common_20220108.xlog.log");
        let encrypted = true;
        let mut ctx = Context::new(input, output, encrypted);
        match ctx.decode() {
            Ok(_) => println!("成功"),
            Err(e) => {
                for cause in e.chain() {
                    if let Some(io_error) = cause.downcast_ref::<io::Error>() {
                        if io_error.kind() == io::ErrorKind::UnexpectedEof {
                            return;
                        }
                    }
                }
                assert!(false, "{:?}", e.root_cause());
            }
        }
    }
}
