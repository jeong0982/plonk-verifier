mod accumulation;
use clap::Parser;

use halo2_curves::bn256::Bn256;
use halo2_kzg_srs::{Srs, SrsFormat};

use std::fs::File;

#[derive(Parser, Debug)]
#[clap(about = "Circom-PLONK verifier")]
struct Cli {
    #[clap(short, long)]
    vkey: String,
    #[clap(short)]
    public_signals: Vec<String>,
    #[clap(long = "proof")]
    proofs: Vec<String>,
    #[clap(short, long = "setup")]
    trusted_setup: String,
}

pub fn main() {
    let args = Cli::parse();
    let acc =
        accumulation::Accumulation::new_from_path(&args.vkey, args.public_signals.clone(), args.proofs.clone());
    
    let srs = Srs::<Bn256>::read(
        &mut File::open(args.trusted_setup.clone()).unwrap(),
        SrsFormat::SnarkJs,
    );

}
