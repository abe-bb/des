use bitvec::{array::BitArray, order::Msb0};

pub fn permute<const INPUT: usize, const PERM_LENGTH: usize, const OUTPUT: usize>(
    input: BitArray<[u8; INPUT], Msb0>,
    permutation: &[usize; PERM_LENGTH],
) -> BitArray<[u8; OUTPUT], Msb0> {
    let mut output: BitArray<[u8; OUTPUT], Msb0> = BitArray::new([0; OUTPUT]);

    for i in 0..permutation.len() {
        output.set(i, input[permutation[i] - 1]);
    }
    output
}

pub const PC_1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pc_1_permuatation() {
        let key: BitArray<[u8; 8], Msb0> =
            BitArray::new([0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
        let expected_permuted_key: BitArray<[u8; 7], Msb0> =
            BitArray::new([0xF0, 0xCC, 0xAA, 0xF5, 0x56, 0x67, 0x8F]);
        println!("{:?}", key);

        assert_eq!(expected_permuted_key, permute::<8, 56, 7>(key, &PC_1));
    }
}
