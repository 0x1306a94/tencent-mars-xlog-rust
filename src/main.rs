use clap::{AppSettings, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

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
            utils::gen_key_pair();
        }
    }
}
