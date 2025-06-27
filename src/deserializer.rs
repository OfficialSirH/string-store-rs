use crate::{char_byte_segment::CharByteSegment, data_requirement::get_data_requirement};

pub struct Deserializer {
  schema: Vec<u8>,
}

impl Deserializer {
  pub fn new(schema: Vec<u8>) -> Self {
    Self { schema }
  }

  pub fn deserialize(&self, buffer: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    // ensures bare minimum requirements met without the need for the values
    let _ = get_data_requirement(&self.schema, &buffer)?;

    let required_bytes = self
      .schema
      .iter()
      .cloned()
      .fold(0, |acc, count| acc + (count != 0) as usize);

    let deserialized_buffer = self.write_deserialized_buffer(buffer, required_bytes)?;

    Ok(deserialized_buffer)
  }

  fn write_deserialized_buffer(
    &self,
    buffer: Vec<u8>,
    required_bytes: usize,
  ) -> Result<Vec<u8>, &'static str> {
    let mut deserialized_buffer = vec![0; required_bytes];
    let mut deserialized_buffer_iterator = deserialized_buffer.iter_mut();
    let mut data_segment = deserialized_buffer_iterator.next().unwrap();
    let mut schema_iterator = self.schema.iter();
    let mut schema_segment = schema_iterator.next().unwrap();
    let mut shift_offset = schema_segment.saturating_sub(1);
    let mut expected_char_segment = CharByteSegment::Start;
    for char_byte in buffer {
      let (char_mask, char_bit_space) = expected_char_segment.next().unwrap();

      if char_byte & char_mask != char_mask {
        return Err("Buffer has invalid data");
      }

      let mut extract_n_iterate = |bit_count: u8| {
        for bit_index in (0..bit_count).rev() {
          *data_segment |= ((char_byte >> bit_index) & 1) << shift_offset;
          if shift_offset == 0 {
            // Nullable values
            if *schema_segment == 0 {
              if *data_segment == 0 {
                println!("the sacred NULL");
                let nullable_bytes = schema_iterator.next().unwrap();
                for _ in 0..*nullable_bytes {
                  schema_iterator.next();
                  deserialized_buffer_iterator.next();
                }
              } else {
                schema_iterator.next();
              }
            }
            match deserialized_buffer_iterator.next() {
              Some(next_segment) => data_segment = next_segment,
              None => return false,
            };
            schema_segment = schema_iterator.next().unwrap();
            shift_offset = schema_segment.saturating_sub(1);
            continue;
          }
          shift_offset -= 1;
        }
        true
      };
      if !extract_n_iterate(char_bit_space) {
        break;
      }
    }
    Ok(deserialized_buffer)
  }
}
