use bitvec::{array::BitArray, order::Msb0, vec::BitVec};
use hex::FromHexError;

use crate::permutation::{permute, IP};

#[derive(Debug)]
struct Block {
    left: BitVec,
    right: BitVec,
    plaintext: bool,
}

impl TryFrom<&str> for Block {
    type Error = FromHexError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        assert_eq!(8, bytes.len(), "data block must be 64 bits");

        let bits: [u8; 8] = bytes.try_into().unwrap();
        let array: BitArray<[u8; 8], Msb0> = BitArray::from(bits);
        let raw_block = BitVec::from_iter(array.iter());
        let ip_block = permute(&raw_block, &IP);

        unimplemented!();
    }
}
