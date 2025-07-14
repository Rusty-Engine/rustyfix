//! Const generic buffer types for optimal performance.
//!
//! This module provides buffer types with compile-time size parameters
//! for better performance and reduced allocations.

use smallvec::SmallVec;
use std::marker::PhantomData;

/// A fixed-size buffer with const generic size parameter.
///
/// This buffer type provides stack allocation for sizes up to N bytes,
/// falling back to heap allocation only when the size exceeds N.
#[derive(Debug, Clone)]
pub struct ConstBuffer<const N: usize> {
    inner: SmallVec<[u8; N]>,
}

impl<const N: usize> ConstBuffer<N> {
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
        // Check if we're using inline storage by comparing capacity
        self.inner.len() <= N && self.inner.capacity() <= N
    }
}

impl<const N: usize> Default for ConstBuffer<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for ConstBuffer<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// Type alias for field serialization buffers.
pub type FieldBuffer = ConstBuffer<{ crate::FIELD_BUFFER_SIZE }>;

/// Type alias for message header buffers.
pub type HeaderBuffer = ConstBuffer<{ crate::MAX_HEADER_FIELDS * 16 }>;

/// A const-sized message buffer pool for efficient allocation.
pub struct MessageBufferPool<const N: usize, const POOL_SIZE: usize> {
    buffers: [ConstBuffer<N>; POOL_SIZE],
    next_idx: usize,
    _phantom: PhantomData<()>,
}

impl<const N: usize, const POOL_SIZE: usize> Default for MessageBufferPool<N, POOL_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const POOL_SIZE: usize> MessageBufferPool<N, POOL_SIZE> {
    /// Creates a new buffer pool.
    pub fn new() -> Self {
        let buffers = core::array::from_fn(|_| ConstBuffer::new());
        Self {
            buffers,
            next_idx: 0,
            _phantom: PhantomData,
        }
    }

    /// Gets the next available buffer from the pool.
    #[inline]
    pub fn get_buffer(&mut self) -> &mut ConstBuffer<N> {
        let buffer = &mut self.buffers[self.next_idx];
        buffer.clear();
        self.next_idx = (self.next_idx + 1) % POOL_SIZE;
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_buffer_inline() {
        let mut buffer: ConstBuffer<64> = ConstBuffer::new();
        assert!(buffer.is_empty());
        assert!(buffer.is_inline());

        // Add data that fits in stack allocation
        buffer.extend_from_slice(b"Hello, World!");
        assert_eq!(buffer.as_slice(), b"Hello, World!");
        assert!(buffer.is_inline());
    }

    #[test]
    fn test_const_buffer_spill() {
        let mut buffer: ConstBuffer<8> = ConstBuffer::new();

        // Add data that exceeds stack allocation
        buffer.extend_from_slice(b"This is a longer string that will spill to heap");
        assert_eq!(buffer.len(), 47);
        assert!(!buffer.is_inline());
    }

    #[test]
    fn test_field_buffer_alias() {
        let mut buffer: FieldBuffer = FieldBuffer::new();
        buffer.extend_from_slice(b"EUR/USD");
        assert_eq!(buffer.as_slice(), b"EUR/USD");
    }

    #[test]
    fn test_buffer_pool() {
        let mut pool: MessageBufferPool<64, 4> = MessageBufferPool::new();

        let buffer1 = pool.get_buffer();
        buffer1.extend_from_slice(b"First");

        let buffer2 = pool.get_buffer();
        buffer2.extend_from_slice(b"Second");

        // Should wrap around and reuse buffers
        for _ in 0..4 {
            let buffer = pool.get_buffer();
            assert!(buffer.is_empty()); // Should be cleared
        }
    }
}
