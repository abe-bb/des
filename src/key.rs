use bitvec::{array::BitArray, order::Msb0, vec::BitVec};
use hex::{decode, FromHexError};

use crate::permutation::{permute, PC_1};

#[derive(Debug)]
pub struct Key {
    left: BitVec<u8, Msb0>,
    right: BitVec<u8, Msb0>,
    round: u8,
}

impl Key {
    pub fn advance_round(&mut self) {
        self.round = self.round + 1 % 16;
        if self.round == 0 || self.round == 1 || self.round == 2 || self.round == 9 {
            self.left.rotate_left(1);
            self.right.rotate_left(1);
        } else {
            self.left.rotate_left(2);
            self.right.rotate_left(2);
        }
    }

    pub fn get_left(&self) -> &BitVec<u8, Msb0> {
        &self.left
    }

    pub fn get_right(&self) -> &BitVec<u8, Msb0> {
        &self.right
    }
}

impl TryFrom<&str> for Key {
    type Error = FromHexError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = decode(value)?;
        assert_eq!(bytes.len(), 8, "provided key must be 64 bits");
        for byte in bytes.iter() {
            // check parity
            assert!(byte.count_ones() & 0b1 == 0b1, "key parity check failed");
        }

        let bits: [u8; 8] = bytes.try_into().unwrap();
        let raw_key: BitArray<[u8; 8], Msb0> = BitArray::new(bits);
        let permuted_key = permute::<8, 56, 7>(raw_key, &PC_1);
        let left = permuted_key[0..28].to_bitvec();
        let right = permuted_key[28..].to_bitvec();

        Ok(Key {
            left,
            right,
            round: 0,
        })
    }
}

#[cfg(test)]
mod test {
    use bitvec::bitvec;
    use bitvec::prelude::*;

    use super::*;
    #[test]
    #[should_panic]
    fn key_too_long() {
        let _key: Result<Key, _> = "133457799BBCDFF1F1".try_into();
    }
    #[test]
    #[should_panic]
    fn key_too_short() {
        let _key: Result<Key, _> = "133457799BBCDF".try_into();
    }
    #[test]
    #[should_panic]
    fn key_fails_parity_check() {
        let _key: Result<Key, _> = "133457799BBDDFF1".try_into();
    }
    #[test]
    fn invalid_hex_string() {
        let key: Result<Key, _> = "HI133457799BBCDF".try_into();
        assert!(key.is_err());
    }
    #[test]
    fn left_key_stored_correctly() {
        let key: Key = "133457799BBCDFF1".try_into().unwrap(); // binary 00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001
        let left = bitvec![
            1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1
        ];
        let right = bitvec![
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1
        ];

        assert_eq!(left, key.left);
        assert_eq!(right, key.right);
    }
}
