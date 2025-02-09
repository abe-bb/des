mod block;
mod key;
mod permutation;
mod substitution;

use block::Block;
use clap::Parser;
use key::Key;

fn main() {
    let args = Args::parse();

    let mut key = Key::try_from(args.key.as_ref())
        .expect("Invalid key. Check parity, length, and formatting");

    if let Some(plaintext) = args.plaintext {
        let plainblock = Block::try_from(plaintext.as_ref())
            .expect("Invalid plaintext. Check length and formatting");

        println!("Encrypted block: {}", plainblock.encrypt(&mut key));
    }

    if let Some(ciphertext) = args.ciphertext {
        let cipherblock = Block::try_from(ciphertext.as_ref())
            .expect("Invalid ciphertext. Check length and formatting");

        println!("Decrypted block: {}", cipherblock.decrypt(&mut key));
    }
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    plaintext: Option<String>,
    #[arg(short, long)]
    ciphertext: Option<String>,
    #[arg(short, long)]
    key: String,
}
