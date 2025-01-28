mod block;
mod key;
mod permutation;
mod substitution;

use block::Block;
use clap::Parser;
use key::Key;

fn main() {
    let args = Args::parse();

    let block = Block::try_from(args.block.as_ref())
        .expect("Invalid input block. Check length and formatting");
    let key = Key::try_from(args.key.as_ref())
        .expect("Invalid key. Check parity, length, and formatting");

    println!("{}", block.encrypt(key));
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    block: String,
    #[arg(short, long)]
    key: String,
}
