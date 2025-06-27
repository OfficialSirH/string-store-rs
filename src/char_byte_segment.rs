pub enum CharByteSegment {
    Start,
    FirstContinuation,
    SecondContinuation,
    ThirdContinuation,
}

impl Iterator for CharByteSegment {
    /// Returns the char byte mask, and the char bit space
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            CharByteSegment::Start => {
                *self = CharByteSegment::FirstContinuation;
                Some((0b1111_0010, 1))
            }
            CharByteSegment::FirstContinuation => {
                *self = CharByteSegment::SecondContinuation;
                Some((0b1000_0000, 6))
            }
            CharByteSegment::SecondContinuation => {
                *self = CharByteSegment::ThirdContinuation;
                Some((0b1000_0000, 6))
            }
            CharByteSegment::ThirdContinuation => {
                *self = CharByteSegment::Start;
                Some((0b1000_0000, 6))
            }
        }
    }
}
