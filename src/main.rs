use clap::{AppSettings, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

pub mod decode;
mod utils;

/// A fictional versioning CLI
#[derive(Parser)]
#[clap(name = "tencent-mars-xlog")]
#[clap(about = "tencent-mars-xlog CLI")]
struct Cli {
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

fn main() {
    // let input = "bab6138191e72d9792adaddb9ada2df9ceb91f896fbe5b738835c2caaa659c83";
    // println!("input: {:?}", input);
    // let decode = utils::decode_hex(input).expect("Decoding failed");
    // println!("decode: {:?}", decode);
    // let ecnode = utils::encode_hex(&decode);
    // println!("ecnode: {:?}", ecnode);
    // assert_eq!(ecnode, input, "失败");

    // gen_key_pair();

    let args = Cli::parse();

    match &args.command {
        Commands::GenKey => {
            if let Some(pair) = utils::gen_key_pair() {
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
            println!("input: {:?}", input);
            println!("output: {:?}", output);

            match privateKey {
                Some(key) => println!("privateKey: {:?}", key),
                None => println!("None"),
            }
        }
    }
}
