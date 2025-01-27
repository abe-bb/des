mod key;

use clap::Parser;

fn main() {
    let args = Args::parse();
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    block: String,
    #[arg(short, long)]
    key: String,
}
