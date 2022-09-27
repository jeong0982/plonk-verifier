use clap::Parser;
use plonk_verifier::util::accumulation::Accumulation;

#[derive(Parser, Debug)]
#[clap(about = "Circom-PLONK verifier")]
struct Cli {
    #[clap(short, long)]
    vkey: String,
    #[clap(short)]
    public_signals: Vec<String>,
    #[clap(long = "proof")]
    proofs: Vec<String>,
}

pub fn main() {
    let args = Cli::parse();
    let acc = Accumulation::new_from_path(&args.vkey, args.public_signals.clone(), args.proofs.clone());
}
