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
        let mut ip_block = permute(&raw_block, &IP);

        let right = ip_block[32..].to_bitvec();
        ip_block.resize(32, false);
        let left = ip_block;

        Ok(Block {
            left,
            right,
            plaintext: true,
        })
    }
}

#[cfg(test)]
mod test {
    use bitvec::{bitvec, order::Lsb0};

    use super::*;

    #[test]
    #[should_panic]
    fn block_too_long() {
        let _block: Result<Block, _> = "0123456789ABCDEFEF".try_into();
    }
    #[test]
    #[should_panic]
    fn block_too_short() {
        let _block: Result<Block, _> = "0123456789ABCD".try_into();
    }
    #[test]
    fn invalid_hex_string() {
        let block: Result<Block, _> = "HI0123456789ABCDEF".try_into();
        assert!(block.is_err());
    }
    #[test]
    fn block_halves_permuted_and_stored_correctly() {
        let block: Block = "0123456789ABCDEF".try_into().unwrap(); // binary 0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
        let expected_left = bitvec![
            1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1,
            1, 1, 1
        ];
        let expected_right = bitvec![
            1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1,
            0, 1, 0
        ];

        assert_eq!(expected_left, block.left);
        assert_eq!(expected_right, block.right);
    }
}
