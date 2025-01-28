use bitvec::{array::BitArray, order::Msb0, slice::BitSlice, vec::BitVec};
use hex::FromHexError;

use crate::{
    key::Key,
    permutation::{permute, E_TABLE, IP, IP_INVERSE, P_TABLE},
    substitution::s_boxes,
};

#[derive(Debug)]
struct Block {
    left: BitVec,
    right: BitVec,
    round: u8,
}

impl Block {
    pub fn encrypt(mut self, mut key: Key) -> BitVec {
        for _ in 0..16 {
            key.advance_round();
            let round_key = key.get_round_key();
            self.advance_round(&round_key);
        }
        let combined = BitVec::from_iter(self.right.iter().chain(self.left.iter()));
        permute(&combined, &IP_INVERSE)
    }

    fn advance_round(&mut self, round_key: &BitSlice) {
        self.round = self.round + 1 % 16;
        // f function output XOR'd with previous left
        let mut new_right = self.f_function(round_key);
        new_right ^= &self.left;

        // set round keys
        std::mem::swap(&mut new_right, &mut self.right);
        std::mem::swap(&mut new_right, &mut self.left);
    }

    fn f_function(&mut self, round_key: &BitSlice) -> BitVec {
        // Expand previous right block and XOR with key
        let mut new_right = permute(&self.right, &E_TABLE);
        new_right ^= round_key;
        let s_boxed_right = s_boxes(new_right);
        let permuted_right = permute(&s_boxed_right, &P_TABLE);

        permuted_right
    }
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
            round: 0,
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
    #[test]
    fn test_f_function() {
        let subkey = bitvec![
            0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0
        ];

        let expected_f_function_output = bitvec![
            0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1,
            0, 1, 1
        ];
        let mut block = Block::try_from("0123456789ABCDEF").unwrap();

        assert_eq!(expected_f_function_output, block.f_function(&subkey));
    }
    #[test]
    fn test_round_advance() {
        let mut block = Block::try_from("0123456789ABCDEF").unwrap();

        let expected_right = bitvec![
            1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 0, 0
        ];
        let expected_left = bitvec![
            1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1,
            0, 1, 0
        ];
        let subkey = bitvec![
            0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0
        ];

        block.advance_round(&subkey);
        assert_eq!(expected_left, block.left);
        assert_eq!(expected_right, block.right);
    }

    #[test]
    fn test_encryption() {
        let block = Block::try_from("0123456789ABCDEF").unwrap();
        let key: Key = "133457799BBCDFF1".try_into().unwrap();
        let expected_ciphertext = bitvec![
            1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0,
            1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 1
        ];

        assert_eq!(expected_ciphertext, block.encrypt(key));
    }
}
