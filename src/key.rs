use bitvec::{array::BitArray, order::Msb0, vec::BitVec};
use hex::FromHexError;

use crate::permutation::{permute, PC_1, PC_2};

#[derive(Debug)]
pub struct Key {
    left: BitVec,
    right: BitVec,
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

    pub fn get_permuted_subkey(&self) -> BitVec {
        let combined: BitVec = BitVec::from_iter(self.left.iter().chain(self.right.iter()));
        permute(&combined, &PC_2)
    }
}

impl TryFrom<&str> for Key {
    type Error = FromHexError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        assert_eq!(8, bytes.len(), "provided key must be 64 bits");

        // check parity bits
        for byte in bytes.iter() {
            assert!(byte.count_ones() & 0b1 == 0b1, "key parity check failed");
        }

        let bits: [u8; 8] = bytes.try_into().unwrap();
        let array: BitArray<[u8; 8], Msb0> = BitArray::from(bits);
        let raw_key = BitVec::from_iter(array.iter());
        let mut permuted_key = permute(&raw_key, &PC_1);
        let right = permuted_key[28..].to_bitvec();
        permuted_key.resize(28, false);
        let left = permuted_key;

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
    fn key_halves_permuted_and_stored_correctly() {
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
    #[test]
    fn subkey_permuation() {
        let left = bitvec![
            1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1
        ];
        let right = bitvec![
            1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0
        ];

        let key = Key {
            left,
            right,
            round: 1,
        };

        let permuted_subkey = key.get_permuted_subkey();
        let expected_permuted_subkey = bitvec![
            0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0
        ];

        assert_eq!(expected_permuted_subkey, permuted_subkey);
    }
    #[test]
    fn round_advance() {
        let left = bitvec![
            1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1
        ];
        let right = bitvec![
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1
        ];
        let expected_left = bitvec![
            1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1
        ];
        let expected_right = bitvec![
            1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0
        ];

        let mut key = Key {
            left,
            right,
            round: 0,
        };

        key.advance_round();
        assert_eq!(expected_left, key.left);
        assert_eq!(expected_right, key.right);
        assert_eq!(1, key.round);
    }
}
