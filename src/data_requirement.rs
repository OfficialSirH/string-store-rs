use crate::constants::CHAR_BIT_SPACE;

/// Parses the `schema_bit_counts` to retrieve the exact bits and characters
/// needed for the serializer/deserializer
pub fn get_data_requirement(schema: &[u8], buffer: &[u8]) -> Result<(usize, usize), &'static str> {
  if buffer.is_empty() {
    return Err("Received empty buffer");
  }

  let mut required_bits: usize = 0;
  let mut schema_bits_iter = schema.iter();
  while let Some(count) = schema_bits_iter.next() {
    // Handle nullable schema cases
    if *count == 0 {
      schema_bits_iter.next();
      required_bits += 1;
      continue;
    }
    required_bits += *count as usize;
  }

  if required_bits == 0 {
    return Err("Received 0 sized schema");
  }

  if schema
    .iter()
    .any(|bit_count| ![0, 1, 2, 4, 8].contains(bit_count))
  {
    return Err("Received unsupported bit count from schema");
  }

  let required_chars =
    required_bits / CHAR_BIT_SPACE + ((required_bits % CHAR_BIT_SPACE) > 0) as usize;
  Ok((required_chars, required_bits))
}
