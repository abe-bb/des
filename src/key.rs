use bitvec::array::BitArray;

struct Key {
    left: BitArray,
    right: BitArray,
}

impl TryFrom<&str> for Key {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}
