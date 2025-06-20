#![feature(pattern)]
// NOTE: The order for packing the bits depends entirely on the given schema
// ^NOTE: This is probably unnecessary to worry about if we always assume that we're filling 4 byte characters

/// 20 subtracting one bit to ensure the character is within the valid range
const CHAR_BIT_SPACE: usize = 19;
const BITS_IN_BYTE: usize = 8;
const BITS_IN_CONTINUATION_BYTES: usize = 6;
const CHAR_SIZE: usize = 4;

/// Assuming the max length bytes, 4, UTF-8 will allow:
///     - at minimum, **1** bit at the 5th low bit on the second byte (`0b1111 0000 1001 0000 1000 0000 1000 0000`)
///     - at maximum, **17** bits at the 3rd low bit on the first byte, the 4 low bits on the second byte, and all
/// the leftover bits on the 3rd and 4th bytes (`0b1111 0100 1000 1111 1011 1111 1011 1111`)
///     - at (flippable bits) maximum, **21** bits at the 2 low bits on the first byte and the rest of the bits on
/// the leftover 3 bytes (`0b1111 0011 1011 1111 1011 1111 1011 1111`)
///
/// **Important Note:** at least *one* of the first 4 bits need to be flipped or the character will be invalid.<br>
/// Current solution(s):
///     - flip the first available bit by default so the character will always be valid but reducing max available
///  bits from 20 -> 19.
///
/// <br>
///
/// # [Valid Encodings](https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c)
///
/// ## 1-byte (U+0000 - U+007F)
/// Valid ASCII encoding (0x00 - 0x7F)
///
/// ## 2-bytes (U+0080 - U+07FF)
/// Correct encodings for U+0080 is 0xC280, for U+07FF is 0xDFBF and all the in-between codepoints.
///
/// ## 3-bytes (U+0800 - U+FFFF)
/// Correct encodings for U+0800 is 0xE0A080, for U+FFFF is 0xEFBFBF and all the in-between codepoints.
///
/// ## 4-bytes (U+010000 - U+10FFFF)
/// Correct encodings for U+010000 is 0xF0908080, for U+10FFFF is 0xF48FBFBF and all the in-between codepoints.
/// - Min 4-bytes value: `0b1111 0000 1001 0000 1000 0000 1000 0000`
/// - Max 4-bytes value: `0b1111 0100 1000 1111 1011 1111 1011 1111`
///
/// <br>
///
/// # [Invalid Encodings](https://stackoverflow.com/questions/66715611/check-for-valid-utf-8-encoding-in-c)
///
/// ## Non ASCII single byte value (0x80 - 0xFF)
/// - Possible stray continuation byte (0x80 - 0xBF)
/// - Invalid start byte (0xC0-0xC1, 0xF5-0xFF) ->
///     - Minimum start byte for 2 bytes: `0b11000010`
///     - Maximum start byte for 4 bytes: `0b11110100`
/// - Valid starting byte (0xC2-0xF4) not followed by a continuation byte
///
/// ## Missing continuation bytes
/// One or more continuation bytes are missing
///
/// ## Invalid "continuation" byte
/// If a byte is outside the valid range (0x80 - 0xBF)
///
/// <br>
///
/// # TypeScript Example:
/// ```ts
/// // Total size in bits: 69 (nice)
/// // Total size in bits(with id): 77
/// interface GameStats {
///     // u4 size
///     level: number;
///     // u8 size
///     x: number;
///     // u8 size
///     y: number;
///     // u16 size
///     coins: number;
///     // 1 bit size
///     hard: boolean;
///     // u32 size
///     kills: number;
/// }
/// ```
pub fn serialize_u8_slice_to_utf8<const N: usize>(
    value: [u8; N],
) -> Result<String, std::string::FromUtf8Error> {
    // Example: a single u8 element should set needed_bits to 8
    let needed_bits = BITS_IN_BYTE * value.len();
    println!("needed_bits: {needed_bits}");
    // Example: one byte should only require 1 char
    let needed_chars = needed_bits / CHAR_BIT_SPACE + ((needed_bits % CHAR_BIT_SPACE) > 0) as usize;
    println!("needed_chars: {needed_chars}");

    let mut values_iterator = value.iter();
    let mut buffer: Vec<u8> = Vec::new();
    // TODO: Utilize this when I actually do a cleaner way to modify the buffer and clean the later code
    buffer.resize_with(needed_chars * 4, Default::default);
    let mut leftover_bits_n_offset: Option<(usize, u8)> = None;
    for char_index in 0..needed_chars {
        let buffer_index = CHAR_SIZE * char_index;
        let mut character: [u8; CHAR_SIZE] = [
            // always have the first_byte default with 2nd low bit flipped for utf-8 range validity
            0b1111_0010,
            0b1000_0000,
            0b1000_0000,
            0b1000_0000,
        ];
        println!("first_byte: {:0b}", character[0]);
        println!("second_byte: {:0b}", character[1]);
        println!("third_byte: {:0b}", character[2]);
        println!("fourth_byte: {:0b}", character[3]);

        let mut bit_queue: [u8; CHAR_BIT_SPACE] = [0b0; CHAR_BIT_SPACE];
        let mut queue_index: usize = 0;

        // If there were leftover bits from a byte that couldn't fit in the previous char,
        // fill the rest of them here
        if let Some((shift_offset, bits)) = leftover_bits_n_offset {
            for bit_index in shift_offset..BITS_IN_BYTE {
                bit_queue[queue_index] = (bits >> bit_index) & 1;
                queue_index += 1;
            }
        }

        // Fill the queue with the max amount of bits that can fit into a char and then carry
        // leftover bits that couldn't fit from a byte into the next char iteration
        while queue_index < bit_queue.len() {
            match values_iterator.next() {
                Some(byte) => {
                    println!("values_iterator byte {byte:0b}");
                    let leftover_queue_size = (bit_queue.len() - queue_index).min(BITS_IN_BYTE);
                    for bit_index in 0..leftover_queue_size {
                        bit_queue[queue_index] = (byte >> bit_index) & 1;
                        println!("bit_queue[{queue_index}]: {:0b}", bit_queue[queue_index]);
                        queue_index += 1;
                    }
                    if leftover_queue_size < BITS_IN_BYTE {
                        let leftover_bits = BITS_IN_BYTE - leftover_queue_size;
                        println!("leftover_bits: {:0b}", (byte >> leftover_queue_size) & 1);
                        leftover_bits_n_offset = Some((
                            (BITS_IN_BYTE - 1) - leftover_bits,
                            byte >> leftover_queue_size,
                        ));
                    }
                }

                None => break,
            }
        }
        println!("queue index after bit accumulation: {queue_index}");
        // necessary for the index to be at the highest valid index rather than the element count
        queue_index -= 1;

        // fill in the single available bit within the first byte of the character
        println!("first bit: {:0b}", bit_queue[queue_index]);
        character[0] |= bit_queue[queue_index];
        println!("first_byte updated: {:0b}", character[0]);
        let mut pushed_all_bits = queue_index
            .checked_sub(1)
            .inspect(|output| queue_index = *output)
            .is_none();
        buffer[buffer_index] = character[0];

        // fill in the available 18 bits over the 3 continuation bytes of the character
        for continuation_byte_index in 1..=3 {
            if !pushed_all_bits {
                let index_start = BITS_IN_CONTINUATION_BYTES;
                let index_end = index_start - (queue_index + 1).min(BITS_IN_CONTINUATION_BYTES);
                for bit_index in (index_end..index_start).rev() {
                    println!("{continuation_byte_index}: {:0b}", bit_queue[queue_index]);
                    println!(
                        "{continuation_byte_index} shifted: {:0b}",
                        bit_queue[queue_index] << bit_index
                    );
                    character[continuation_byte_index] |= bit_queue[queue_index] << bit_index;
                    println!(
                        "continuation byte {continuation_byte_index} updated: {:0b}",
                        character[continuation_byte_index]
                    );
                    pushed_all_bits = queue_index
                        .checked_sub(1)
                        .inspect(|output| queue_index = *output)
                        .is_none();
                }
            }
            buffer[buffer_index + continuation_byte_index] = character[continuation_byte_index];
        }
    }

    println!("Buffer length: {}", buffer.len());
    String::from_utf8(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let value: u8 = 127;
        let expected_string =
            String::from_utf8(vec![0b11110010, 0b10111111, 0b10100000, 0b10000000]).unwrap();

        println!("bytes: {:?}", expected_string);
        let result = serialize_u8_slice_to_utf8(value.to_le_bytes()).unwrap();
        assert_eq!(result, expected_string);
    }
}
