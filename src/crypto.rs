//! Legacy ciphers needed to decode the RotMG wire protocol.

use std::fmt;

/// An error constructing an [`Rc4`] stream cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rc4Error {
    /// RC4 requires a non-empty key.
    EmptyKey,
}

impl fmt::Display for Rc4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => formatter.write_str("RC4 key must not be empty"),
        }
    }
}

impl std::error::Error for Rc4Error {}

/// Stateful RC4 keystream for compatibility with the legacy RotMG protocol.
///
/// RC4 is cryptographically broken and must not be used to protect new data.
/// This type exists only to decode or encode protocol traffic that requires it.
#[derive(Debug)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initialize an RC4 keystream with `key`.
    pub fn new(key: &[u8]) -> Result<Self, Rc4Error> {
        if key.is_empty() {
            return Err(Rc4Error::EmptyKey);
        }

        let mut state = [0; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }

        let mut j = 0_u8;
        for index in 0..256 {
            j = j
                .wrapping_add(state[index])
                .wrapping_add(key[index % key.len()]);
            state.swap(index, usize::from(j));
        }

        Ok(Self { state, i: 0, j: 0 })
    }

    /// XOR the next keystream bytes into `data`, advancing this cipher's state.
    ///
    /// Calling this method on successive chunks produces the same result as
    /// calling it once on their concatenation.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let index =
                self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
            *byte ^= self.state[usize::from(index)];
        }
    }
}
