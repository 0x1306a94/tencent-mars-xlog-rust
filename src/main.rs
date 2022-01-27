use clap::{AppSettings, Parser, Subcommand};
use path_absolutize::*;
use std::io;
use std::path::PathBuf;
use walkdir::WalkDir;

use micro_uecc_safe;
mod decode;
/// tencent-mars-xlog-util CLI
#[derive(Parser)]
#[clap(name = "tencent-mars-xlog-util")]
#[clap(about = "tencent-mars-xlog-util")]
#[clap(author, version, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate the key
    #[clap(setting(AppSettings::AllArgsOverrideSelf))]
    GenKey,

    /// Decode Xlog
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Decode {
        /// Input file or Input dir
        #[clap(short, long, required = true, parse(from_os_str))]
        input: PathBuf,

        /// Output file or Output dif
        #[clap(short, long, required = true, parse(from_os_str))]
        output: PathBuf,

        /// Private Key
        #[clap(short, long)]
        privateKey: Option<String>,
    },
}

impl Cli {
    fn decode_single_file(&self, input: &PathBuf, output: &PathBuf, private_key: String) {
        let input_path = String::from(input.to_str().unwrap());
        let mut output_path = String::from(output.to_str().unwrap());
        if output.is_dir() {
            let file_name = input.file_name().unwrap();
            let mut path = PathBuf::from(output.to_str().unwrap()).join(file_name);
            path.set_extension("xlog.log");
            output_path = String::from(path.to_str().unwrap());
        }
        let mut ctx = decode::Context::new(input_path, output_path, private_key);
        let e = match ctx.decode() {
            Err(it) => it,
            _ => return,
        };
        let root_cause = e.root_cause();
        if let Some(io_error) = root_cause.downcast_ref::<io::Error>() {
            if io_error.kind() == io::ErrorKind::UnexpectedEof {
                return;
            }
        }
        for cause in e.chain() {
            if let Some(io_error) = cause.downcast_ref::<io::Error>() {
                if io_error.kind() == io::ErrorKind::UnexpectedEof {
                    return;
                }
            }
        }
        // std::panic::panic_any(e);
        println!("{:?}", e);
    }
}

impl Cli {
    pub fn execute(&self) {
        match &self.command {
            Commands::GenKey => {
                if let Some(pair) = micro_uecc_safe::gen_secp2561k1_key_pair() {
                    println!("private_key: {}", pair.private_key);
                    println!("public_key: {}", pair.public_key);
                } else {
                    println!("生成失败")
                }
            }
            Commands::Decode {
                input,
                output,
                privateKey,
            } => {
                let input_path_buf = input.absolutize().unwrap().to_path_buf();
                let out_path_buf = output.absolutize().unwrap().to_path_buf();
                println!("input: {:?}", input_path_buf);
                println!("output: {:?}", out_path_buf);

                if input_path_buf.is_file() {
                    let mut private_key = String::new();
                    if let Some(key) = privateKey {
                        private_key.push_str(key);
                    }

                    self.decode_single_file(&input_path_buf, &out_path_buf, private_key);
                    return;
                } else {
                    for entry in WalkDir::new(input_path_buf.as_path()) {
                        let entry = entry.unwrap();
                        let input_path = PathBuf::from(entry.path());
                        println!("input: {:?}", input_path);
                        let mut private_key = String::new();
                        if let Some(key) = privateKey {
                            private_key.push_str(key);
                        }

                        self.decode_single_file(&input_path, &out_path_buf, private_key);
                    }
                }
            }
        }
    }
}
fn main() {
    let args = Cli::parse();
    args.execute();
}
