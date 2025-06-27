/// 20 subtracting one bit to ensure the character is within the valid range
pub const CHAR_BIT_SPACE: usize = 19;
/// The amount of available bit space in a continuation byte
pub const BITS_IN_CONTINUATION_BYTES: usize = 6;
/// The assumed size for all generated characters in this library
pub const CHAR_SIZE: usize = 4;
