use std::slice::Iter;

use crate::{
  constants::{BITS_IN_CONTINUATION_BYTES, CHAR_SIZE},
  data_requirement::get_data_requirement,
};

pub struct Serializer {
  schema: Vec<u8>,
}

impl Serializer {
  pub fn new(schema: Vec<u8>) -> Self {
    Self { schema }
  }

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
  pub fn serialize(&self, buffer: Vec<u8>) -> Result<String, &'static str> {
    let (required_chars, required_bits) = get_data_requirement(&self.schema, &buffer)?;

    let bit_queue = self.collect_bit_queue(buffer, vec![0; required_bits]);

    let serialized_buffer = self.write_serialized_buffer(bit_queue.iter(), required_chars);

    String::from_utf8(serialized_buffer).map_err(
      |_| "Invalid utf-8 buffer (If you see this error, this is a bug and should be reported)",
    )
  }

  fn collect_bit_queue(&self, buffer: Vec<u8>, mut bit_queue: Vec<u8>) -> Vec<u8> {
    let mut bit_queue_index: usize = 0;
    let mut schema_bit_counts_iter = self.schema.iter();
    for data_segment in buffer {
      let bit_count = *schema_bit_counts_iter.next().unwrap();
      // Nullable values
      if bit_count == 0 {
        if data_segment == 0 {
          let nullable_bytes = schema_bit_counts_iter.next().unwrap();
          for _ in 0..*nullable_bytes {
            schema_bit_counts_iter.next();
          }
          bit_queue[bit_queue_index] = 0;
          bit_queue_index += 1;
        } else {
          schema_bit_counts_iter.next();
          bit_queue[bit_queue_index] = 1;
          bit_queue_index += 1;
        }
        continue;
      }
      for offset in (0..bit_count).rev() {
        bit_queue[bit_queue_index] = (data_segment
          .checked_shr(offset.try_into().unwrap())
          .unwrap_or(0))
          & 1;
        bit_queue_index += 1;
      }
    }
    bit_queue
  }

  fn write_serialized_buffer(
    &self,
    mut bit_queue_iterator: Iter<'_, u8>,
    required_chars: usize,
  ) -> Vec<u8> {
    let mut serialized_buffer: Vec<u8> = vec![0; required_chars * CHAR_SIZE];
    for char_index in 0..required_chars {
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
      character[0] |= bit_queue_iterator.next().unwrap();
      serialized_buffer[buffer_index] = character[0];

      // fill in the available 18 bits over the 3 continuation bytes of the character
      for continuation_byte_index in 1..=3 {
        for offset in (0..BITS_IN_CONTINUATION_BYTES).rev() {
          let Some(bit) = bit_queue_iterator.next() else {
            break;
          };
          character[continuation_byte_index] |= bit << offset;
        }
        serialized_buffer[buffer_index + continuation_byte_index] =
          character[continuation_byte_index];
      }
    }
    serialized_buffer
  }
}
