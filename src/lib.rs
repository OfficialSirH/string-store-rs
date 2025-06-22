pub mod schema;
pub mod types;

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
    schema_data: [u8; N],
) -> Result<String, &'static str> {
    if schema_data.is_empty() {
        return Err("Received empty schema data");
    }

    // Example: a single u8 element should set needed_bits to 8
    let needed_bits = BITS_IN_BYTE * schema_data.len();
    // Example: one byte should only require 1 char
    let needed_chars = needed_bits / CHAR_BIT_SPACE + ((needed_bits % CHAR_BIT_SPACE) > 0) as usize;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize_with(needed_chars * 4, Default::default);

    let mut bit_queue: Vec<u8> = Vec::new();
    bit_queue.resize_with(schema_data.len() * BITS_IN_BYTE, Default::default);
    let mut bit_queue_index: usize = 0;

    for data_segment in schema_data {
        for offset in (0..=(BITS_IN_BYTE - 1)).rev() {
            bit_queue[bit_queue_index] = (data_segment >> offset) & 1;
            bit_queue_index += 1;
        }
    }

    let mut bit_queue_iter = bit_queue.iter();
    for char_index in 0..needed_chars {
        let buffer_index = CHAR_SIZE * char_index;
        let mut character: [u8; CHAR_SIZE] = [
            // always have the first_byte default with 2nd low bit flipped for utf-8 range validity
            0b1111_0010,
            0b1000_0000,
            0b1000_0000,
            0b1000_0000,
        ];

        // This unwrap is fine as the calculated required characters ensures that if we're at a new
        // character, there will definitely be at least one bit left in the queue.
        character[0] |= bit_queue_iter.next().unwrap();
        buffer[buffer_index] = character[0];

        // fill in the available 18 bits over the 3 continuation bytes of the character
        for continuation_byte_index in 1..=3 {
            for offset in (0..BITS_IN_CONTINUATION_BYTES).rev() {
                if let Some(bit) = bit_queue_iter.next() {
                    character[continuation_byte_index] |= bit << offset;
                } else {
                    break;
                }
            }
            buffer[buffer_index + continuation_byte_index] = character[continuation_byte_index];
        }
    }

    String::from_utf8(buffer).map_err(
        |_| "Invalid utf-8 buffer (If you see this error, this is a bug and should be reported)",
    )
}

enum CharByteSegment {
    Start,
    FirstContinuation,
    SecondContinuation,
    ThirdContinuation,
}

// Parses `schema_size` amount of bytes from the `buffer`
pub fn deserialize_u8_slice_from_utf8(
    buffer: String,
    schema_size: usize,
) -> Result<Vec<u8>, &'static str> {
    let expected_bits = schema_size * BITS_IN_BYTE;
    println!("expected_bits: {expected_bits}");
    // Example: one byte should only require 1 char
    let expected_chars =
        expected_bits / CHAR_BIT_SPACE + ((expected_bits % CHAR_BIT_SPACE) > 0) as usize;
    println!("expected_chars: {expected_chars}");
    if buffer.len() != expected_chars * CHAR_SIZE {
        return Err("Content doesn't contain enough bytes for the schema");
    }

    let mut schema_data: Vec<u8> = Vec::new();
    schema_data.resize_with(schema_size, Default::default);
    let mut shift_offset = BITS_IN_BYTE - 1;
    let mut schema_data_iter = schema_data.iter_mut();
    let mut data_segment = schema_data_iter.next().ok_or("Received 0 sized schema")?;
    let mut expected_char_segment = CharByteSegment::Start;
    for char_byte in buffer.as_bytes() {
        let expected_byte_pattern: u8 = match expected_char_segment {
            CharByteSegment::Start => 0b1111_0010,
            _ => 0b1000_0000,
        };

        if char_byte & expected_byte_pattern != expected_byte_pattern {
            return Err("Content has invalid data");
        }

        let mut extract_n_iterate = |bit_count: u8| {
            // let mut collected_bits = Vec::new();
            for bit_index in (0..bit_count).rev() {
                *data_segment |= ((char_byte >> bit_index) & 1) << shift_offset;
                // collected_bits.push(((char_byte >> bit_index) & 1) << shift_offset);
                if shift_offset == 0 {
                    // data_segment.from_bits(collected_bits);
                    match schema_data_iter.next() {
                        Some(next_segment) => data_segment = next_segment,
                        None => return false,
                    };
                    shift_offset = BITS_IN_BYTE - 1;
                    continue;
                }
                shift_offset -= 1;
            }
            true
        };
        expected_char_segment = match expected_char_segment {
            CharByteSegment::Start => {
                if !extract_n_iterate(1) {
                    break;
                }
                CharByteSegment::FirstContinuation
            }
            CharByteSegment::FirstContinuation => {
                if !extract_n_iterate(6) {
                    break;
                };
                CharByteSegment::SecondContinuation
            }
            CharByteSegment::SecondContinuation => {
                if !extract_n_iterate(6) {
                    break;
                };
                CharByteSegment::ThirdContinuation
            }
            CharByteSegment::ThirdContinuation => {
                if !extract_n_iterate(6) {
                    break;
                };
                CharByteSegment::Start
            }
        };
    }
    println!("schema_data: {schema_data:?}");
    Ok(schema_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization() {
        let value: u8 = 127;
        let expected_string =
            String::from_utf8(vec![0b11110010, 0b10111111, 0b10100000, 0b10000000]).unwrap();

        println!("bytes: {:?}", expected_string);
        let result = serialize_u8_slice_to_utf8(value.to_le_bytes()).unwrap();
        assert_eq!(result, expected_string);
    }

    #[test]
    fn deserialization() {
        let four_byte_char =
            String::from_utf8(vec![0b11110010, 0b10111111, 0b10100000, 0b10000000]).unwrap();

        let result = deserialize_u8_slice_from_utf8(four_byte_char, 1);
        if let Err(message) = result {
            println!("{message}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn serialize_n_deserialize() {
        let values = [200, 100, 50, 25, 10, 5, 1];
        let serialized_data = serialize_u8_slice_to_utf8(values).unwrap();
        println!("values: {:?}", values.map(|value| format!("{value:0b}")));
        println!(
            "serialized_data: {:?}",
            serialized_data
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:0b} "))
                .collect::<String>()
        );
        let deserialized_data = deserialize_u8_slice_from_utf8(serialized_data, values.len());

        if let Err(message) = deserialized_data {
            println!("{message}");
        }
        assert!(deserialized_data.is_ok());
    }
}
