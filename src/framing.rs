//! Incrementally separate a TCP byte stream into complete RotMG frames.
//!
//! A frame begins with a four-byte big-endian signed length that includes the
//! full frame, followed by a one-byte packet ID. The decoder extracts that ID
//! and returns the remaining body unchanged; decryption and packet decoding are
//! left to the caller.

use std::fmt;

/// An invalid frame length or decoder configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// The configured maximum cannot fit the four-byte length and packet ID.
    InvalidMaximumFrameSize(usize),
    /// A frame length was smaller than the five-byte minimum.
    InvalidLength(i32),
    /// A frame length exceeded the configured maximum.
    FrameTooLarge { length: usize, maximum: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaximumFrameSize(maximum) => write!(
                formatter,
                "maximum frame size must be at least 5 bytes, got {maximum}"
            ),
            Self::InvalidLength(length) => {
                write!(formatter, "invalid frame length {length}; minimum is 5")
            }
            Self::FrameTooLarge { length, maximum } => write!(
                formatter,
                "frame length {length} exceeds configured maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

/// A complete frame with its packet ID and opaque body bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// The packet ID from the frame header.
    pub packet_id: u8,
    /// The bytes after the packet ID, unchanged from the input stream.
    pub body: Vec<u8>,
}

/// Separates a direction's ordered TCP bytes into complete RotMG frames.
///
/// The decoder retains at most one incomplete frame, bounded by
/// `maximum_frame_size`. Complete frames are returned from
/// [`push`](Self::push), with the length prefix removed and packet ID separated
/// from the unchanged body. A framing error resets the decoder; frames
/// completed earlier in that same call are discarded because the stream is no
/// longer trusted.
#[derive(Debug)]
pub struct FrameDecoder {
    maximum_frame_size: usize,
    length_bytes: [u8; 4],
    length_bytes_received: usize,
    frame: Option<Vec<u8>>,
    frame_length: usize,
    frame_bytes_received: usize,
}

impl FrameDecoder {
    /// Create a decoder with an upper bound on total frame size in bytes.
    pub fn new(maximum_frame_size: usize) -> Result<Self, FrameError> {
        if maximum_frame_size < 5 {
            return Err(FrameError::InvalidMaximumFrameSize(maximum_frame_size));
        }

        Ok(Self {
            maximum_frame_size,
            length_bytes: [0; 4],
            length_bytes_received: 0,
            frame: None,
            frame_length: 0,
            frame_bytes_received: 0,
        })
    }

    /// Add ordered stream bytes and return every frame completed by this input.
    ///
    /// On an invalid or oversized length, the decoder resets and returns an
    /// error. A caller should treat that stream as unusable or explicitly
    /// establish a new framing boundary before continuing.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, FrameError> {
        let mut frames = Vec::new();
        let mut input_offset = 0;

        while input_offset < bytes.len() {
            if self.frame.is_none() {
                let needed = 4 - self.length_bytes_received;
                let copied = needed.min(bytes.len() - input_offset);
                let end = input_offset + copied;
                let prefix_end = self.length_bytes_received + copied;
                self.length_bytes[self.length_bytes_received..prefix_end]
                    .copy_from_slice(&bytes[input_offset..end]);
                self.length_bytes_received = prefix_end;
                input_offset = end;

                if self.length_bytes_received < 4 {
                    continue;
                }

                let signed_length = i32::from_be_bytes(self.length_bytes);
                if signed_length < 5 {
                    self.reset();
                    return Err(FrameError::InvalidLength(signed_length));
                }
                let length = signed_length as usize;
                if length > self.maximum_frame_size {
                    self.reset();
                    return Err(FrameError::FrameTooLarge {
                        length,
                        maximum: self.maximum_frame_size,
                    });
                }

                let mut frame = Vec::with_capacity(length);
                frame.extend_from_slice(&self.length_bytes);
                self.frame = Some(frame);
                self.frame_length = length;
                self.frame_bytes_received = 4;
            } else {
                let frame = self.frame.as_mut().expect("frame was checked above");
                let needed = self.frame_length - self.frame_bytes_received;
                let copied = needed.min(bytes.len() - input_offset);
                let end = input_offset + copied;
                frame.extend_from_slice(&bytes[input_offset..end]);
                self.frame_bytes_received += copied;
                input_offset = end;

                if self.frame_bytes_received == self.frame_length {
                    let mut complete_frame = self.frame.take().expect("complete frame is present");
                    let packet_id = complete_frame[4];
                    let body = complete_frame.split_off(5);
                    frames.push(Frame { packet_id, body });
                    self.frame_length = 0;
                    self.frame_bytes_received = 0;
                    self.length_bytes = [0; 4];
                    self.length_bytes_received = 0;
                }
            }
        }

        Ok(frames)
    }

    /// Discard any partial length prefix or frame body.
    pub fn reset(&mut self) {
        self.length_bytes = [0; 4];
        self.length_bytes_received = 0;
        self.frame = None;
        self.frame_length = 0;
        self.frame_bytes_received = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameDecoder, FrameError};

    fn frame(packet_id: u8, body: &[u8]) -> Vec<u8> {
        let length = (5 + body.len()) as i32;
        let mut frame = Vec::with_capacity(length as usize);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.push(packet_id);
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn accepts_the_minimum_frame_size() {
        let frame = frame(75, &[]);
        let mut decoder = FrameDecoder::new(5).unwrap();

        assert_eq!(
            decoder.push(&frame),
            Ok(vec![Frame {
                packet_id: 75,
                body: vec![],
            }])
        );
    }

    #[test]
    fn handles_every_boundary_split_in_a_frame() {
        let expected = frame(75, &[1, 2, 3]);

        for split in 1..expected.len() {
            let mut decoder = FrameDecoder::new(64).unwrap();
            assert_eq!(decoder.push(&expected[..split]), Ok(Vec::new()));
            assert_eq!(
                decoder.push(&expected[split..]),
                Ok(vec![Frame {
                    packet_id: 75,
                    body: vec![1, 2, 3],
                }])
            );
        }
    }

    #[test]
    fn rejects_signed_invalid_and_oversized_lengths_and_resets() {
        let mut decoder = FrameDecoder::new(8).unwrap();

        assert_eq!(
            decoder.push(&(-1_i32).to_be_bytes()),
            Err(FrameError::InvalidLength(-1))
        );
        assert_eq!(
            decoder.push(&9_i32.to_be_bytes()),
            Err(FrameError::FrameTooLarge {
                length: 9,
                maximum: 8,
            })
        );
        assert_eq!(
            decoder.push(&frame(75, &[])),
            Ok(vec![Frame {
                packet_id: 75,
                body: vec![],
            }])
        );
    }
}
