use crate::types::Type;

pub struct UInt64 {
    data: [u8; Self::SIZE],
}

impl Type for UInt64 {
    const SIZE: usize = 8;

    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<u64> for UInt64 {
    fn from(value: u64) -> Self {
        UInt64 {
            data: value.to_be_bytes(),
        }
    }
}

impl From<UInt64> for u64 {
    fn from(value: UInt64) -> Self {
        u64::from_be_bytes(value.data)
    }
}
