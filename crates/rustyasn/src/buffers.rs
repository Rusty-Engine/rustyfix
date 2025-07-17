//! Buffer types for optimal performance.
//!
//! This module provides buffer types with specific size parameters
//! for better performance and reduced allocations.

use smallvec::SmallVec;

/// A field buffer optimized for small field values.
#[derive(Debug, Clone)]
pub struct FieldBuffer {
    inner: SmallVec<[u8; 64]>,
}

impl FieldBuffer {
    /// Creates a new empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: SmallVec::new(),
        }
    }

    /// Creates a buffer with the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: SmallVec::with_capacity(capacity),
        }
    }

    /// Returns the capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns the length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Extends the buffer with the given slice.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Returns a slice of the buffer contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Clears the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns true if the buffer is currently using stack allocation.
    #[inline]
    pub fn is_inline(&self) -> bool {
        !self.inner.spilled()
    }
}

impl Default for FieldBuffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for FieldBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// A header buffer optimized for message headers.
#[derive(Debug, Clone)]
pub struct HeaderBuffer {
    inner: SmallVec<[u8; 128]>,
}

impl HeaderBuffer {
    /// Creates a new empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: SmallVec::new(),
        }
    }

    /// Returns the length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Extends the buffer with the given slice.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Returns a slice of the buffer contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Clears the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Default for HeaderBuffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// A message buffer for larger messages.
#[derive(Debug, Clone)]
pub struct MessageBuffer {
    inner: SmallVec<[u8; 256]>,
}

impl MessageBuffer {
    /// Creates a new empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: SmallVec::new(),
        }
    }

    /// Returns the length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Extends the buffer with the given slice.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Returns a slice of the buffer contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Clears the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Default for MessageBuffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_buffer() {
        let mut buffer = FieldBuffer::new();
        assert!(buffer.is_empty());
        assert!(buffer.is_inline());

        buffer.extend_from_slice(b"Hello, World!");
        assert_eq!(buffer.as_slice(), b"Hello, World!");
        assert!(buffer.is_inline());
    }

    #[test]
    fn test_header_buffer() {
        let mut buffer = HeaderBuffer::new();
        assert!(buffer.is_empty());

        buffer.extend_from_slice(b"Header data");
        assert_eq!(buffer.as_slice(), b"Header data");
    }

    #[test]
    fn test_message_buffer() {
        let mut buffer = MessageBuffer::new();
        assert!(buffer.is_empty());

        buffer.extend_from_slice(b"Message data");
        assert_eq!(buffer.as_slice(), b"Message data");
    }
}
