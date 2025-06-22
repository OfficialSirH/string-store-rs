use crate::types::Type;

pub struct Bit {
    data: [u8; Self::SIZE],
}

impl Type for Bit {
    const SIZE: usize = 1;

    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
