use crate::types::Type;

pub struct Boolean {
    data: [u8; Self::SIZE],
}

impl Type for Boolean {
    const SIZE: usize = 1;

    fn data(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<bool> for Boolean {
    fn from(value: bool) -> Self {
        Boolean {
            data: [value as u8],
        }
    }
}

impl From<Boolean> for bool {
    fn from(value: Boolean) -> Self {
        value.data[0] == 1
    }
}
