pub use crate::types::{bit::Bit, boolean::Boolean, uint64::UInt64};

mod bit;
mod boolean;
mod uint16;
mod uint2;
mod uint32;
mod uint4;
mod uint64;
mod uint8;

pub trait Type {
    const SIZE: usize;

    fn data(&mut self) -> &mut [u8];

    fn add_bit(&mut self, bit: u8, ptr_idx: usize) -> bool {
        if ptr_idx >= self.data().len() {
            return false;
        }
        unsafe {
            self.add_bit_unchecked(bit, ptr_idx);
        }
        return true;
    }

    /// # Safety
    ///
    /// ptr_idx is checked if it's within the bounds of the ptr in [`add_bit`](crate::types::TypeSize::add_bit)
    unsafe fn add_bit_unchecked(&mut self, bit: u8, ptr_idx: usize) -> () {
        unsafe {
            *self.data().as_mut_ptr().add(ptr_idx) |= bit;
        }
    }
}

pub enum Types {
    Bit(Bit),
    Boolean(Boolean),
    Int64(UInt64),
}
