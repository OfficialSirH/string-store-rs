#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

mod char_byte_segment;
mod constants;
mod data_requirement;
mod deserializer;
mod napi;
mod serializer;

pub use char_byte_segment::CharByteSegment;
pub use constants::{BITS_IN_CONTINUATION_BYTES, CHAR_BIT_SPACE, CHAR_SIZE};
pub use data_requirement::get_data_requirement;
pub use deserializer::Deserializer;
pub use serializer::Serializer;

#[cfg(test)]
mod tests {
  use std::mem::transmute;

  use crate::{deserializer::Deserializer, serializer::Serializer};

  #[test]
  fn serialization() {
    let value: u8 = 127;
    // 127 serialized
    let expected_string =
      String::from_utf8(vec![0b11110010, 0b10111111, 0b10100000, 0b10000000]).unwrap();

    println!("bytes: {:?}", expected_string);
    let serializer = Serializer::new(vec![8]);
    let result = serializer.serialize(value.to_be_bytes().to_vec()).unwrap();
    assert_eq!(result, expected_string);
  }

  #[test]
  fn deserialization() {
    // 127 serialized
    let four_byte_char =
      String::from_utf8(vec![0b11110010, 0b10111111, 0b10100000, 0b10000000]).unwrap();

    let deserializer = Deserializer::new(vec![8]);
    let result = deserializer.deserialize(four_byte_char.as_bytes().to_vec());
    if let Err(message) = result {
      println!("{message}");
    }
    assert!(result.is_ok());
  }

  #[test]
  fn serialize_n_deserialize() {
    let values = [400, 200, 100, 50, 25, 10, 5, 1]
      .map(|data: u64| {
        if data > u8::MAX as u64 {
          data.to_be_bytes().to_vec()
        } else {
          [data as u8].to_vec()
        }
      })
      .concat();

    let schema = vec![8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

    println!(
      "values: {:?}",
      values
        .iter()
        .map(|value| format!("{value:0b}"))
        .collect::<Vec<String>>()
        .join(" ")
    );
    let serializer = Serializer::new(schema.clone());
    let serialized_data = serializer.serialize(values).unwrap();
    println!(
      "serialized_data: {:?}",
      serialized_data
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte}"))
        .collect::<Vec<String>>()
        .join(" ")
    );
    let deserializer = Deserializer::new(schema);
    let deserialized_data = deserializer.deserialize(serialized_data.as_bytes().to_vec());

    if let Err(message) = deserialized_data {
      println!("{message}");
    }

    assert!(deserialized_data.is_ok());

    println!(
      "deserialized_data: {}",
      deserialized_data.map_or_else(
        |err| err.to_string(),
        |data| [
          // Not a major issue but just annoying, figure out how to properly convert a slice of bytes to u64
          format!(
            "{}",
            u128::from_be_bytes(unsafe { transmute(data.get(0..8).unwrap()) })
          ),
          data
            .iter()
            .skip(8)
            .map(|byte| format!("{byte}"))
            .collect::<Vec<String>>()
            .join(" ")
        ]
        .join(" ")
      )
    );
  }

  #[test]
  fn serialize_n_deserialize_real_sample() {
    // Schema Id: (1 bytes)
    let schema_id = vec![0];
    // "Terra" (5 bytes)
    let username = vec![0b01010100, 0b01100101, 0b01110010, 0b01110010, 0b01100001];
    // "1071822091814441000" (19 bytes)
    let user_id = vec![
      0b00110001, 0b00110000, 0b00110111, 0b00110001, 0b00111000, 0b00110010, 0b00110010,
      0b00110000, 0b00111001, 0b00110001, 0b00111000, 0b00110001, 0b00110100, 0b00110100,
      0b00110100, 0b00110001, 0b00110000, 0b00110000, 0b00110000,
    ];

    let buffer = [schema_id, username, user_id].concat();

    let serializer = Serializer::new(vec![
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ]);
    let serialized_data = serializer.serialize(buffer).unwrap();

    println!("serialized_data: {}", serialized_data);

    let deserializer = Deserializer::new([vec![8], [8].repeat(5), [8].repeat(19)].concat());
    let deserialized_data = deserializer
      .deserialize(serialized_data.as_bytes().to_vec())
      .unwrap();
    let mut deserialized_data_iter = deserialized_data.iter();

    let schema_id = deserialized_data_iter.next().unwrap();
    println!("{schema_id}");

    let mut username_parts = Vec::new();
    for _ in 0..5 {
      username_parts.push(*deserialized_data_iter.next().unwrap());
    }
    let username = String::from_utf8(username_parts).unwrap();
    println!("{username}");

    let mut user_id_parts = Vec::new();
    for _ in 0..19 {
      user_id_parts.push(*deserialized_data_iter.next().unwrap());
    }
    let user_id = String::from_utf8(user_id_parts).unwrap();
    println!("{user_id}");
  }

  fn nullabe_cases(have_nullish_be_null: bool) {
    // Schema Id: 4 (1 byte)
    let schema_id = vec![0b0000_0100];
    // "Yippee!" (7 bytes)
    let message = vec![
      0b01011001, 0b01101001, 0b01110000, 0b01110000, 0b01100101, 0b01100101, 0b00100001,
    ];
    println!("message: {message:?}");
    // Nullable<500> (1 bit + 2 bytes)
    let extra_value = if have_nullish_be_null {
      vec![0b000000000]
    } else {
      vec![0b000000001, 0b00000001, 0b11110100]
    };
    println!("extra_value: {extra_value:?}");
    // 69 (1 byte)
    let final_value = vec![0b01000101];

    let buffer = [schema_id, message, extra_value, final_value].concat();
    let schema = [
      // schema_id
      vec![8],
      // message
      vec![8].repeat(7),
      // extra_value
      vec![0, 2, 8, 8],
      // final_value
      vec![8],
    ]
    .concat();

    let serializer = Serializer::new(schema.clone());
    let serialized_data = serializer.serialize(buffer).unwrap();

    println!(
      "serialized_data: {:?}",
      serialized_data
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:0b}"))
        .collect::<Vec<String>>()
    );

    let deserializer = Deserializer::new(schema);
    let deserialized_data = deserializer
      .deserialize(serialized_data.as_bytes().to_vec())
      .unwrap();
    let mut deserialized_data_iter = deserialized_data.iter();

    let schema_id = deserialized_data_iter.next().unwrap();
    println!("{schema_id}");

    let mut message_parts = Vec::new();
    for _ in 0..7 {
      message_parts.push(*deserialized_data_iter.next().unwrap());
    }
    let message = String::from_utf8(message_parts).unwrap();
    println!("{message}");

    let extra_value_is_null = *deserialized_data_iter.next().unwrap() == 0;
    let extra_value = extra_value_is_null
      .then(|| {
        deserialized_data_iter.next().unwrap();
        deserialized_data_iter.next().unwrap();

        "NULL".to_string()
      })
      .unwrap_or_else(|| {
        format!(
          "{}",
          u16::from_be_bytes([
            *deserialized_data_iter.next().unwrap(),
            *deserialized_data_iter.next().unwrap()
          ])
        )
      });
    println!("{extra_value}");

    let final_value = deserialized_data_iter.next().unwrap();
    println!("{final_value}");
  }

  #[test]
  fn serialize_n_deserialize_nullable_is_null() {
    nullabe_cases(true);
  }

  #[test]
  fn serialize_n_deserialize_nullable_is_not_null() {
    nullabe_cases(false);
  }
}
