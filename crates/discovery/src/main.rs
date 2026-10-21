mod cli;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    if let Err(e) = cli::run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
