//! Local trait definitions for ASN.1 integration.
//!
//! This module defines traits that were previously imported from rustyfix
//! but are now implemented locally to avoid dependency on the main rustyfix crate.

/// A growable buffer that can be written to.
pub trait Buffer {
    /// Extends the buffer with the contents of the slice.
    fn extend_from_slice(&mut self, data: &[u8]);
}

impl Buffer for Vec<u8> {
    fn extend_from_slice(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

impl Buffer for smallvec::SmallVec<[u8; 64]> {
    fn extend_from_slice(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

impl Buffer for smallvec::SmallVec<[u8; 128]> {
    fn extend_from_slice(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

impl Buffer for smallvec::SmallVec<[u8; 256]> {
    fn extend_from_slice(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

/// Provides (de)serialization logic for a Rust type as FIX field values.
pub trait FieldType<'a>
where
    Self: Sized,
{
    /// The error type that can arise during deserialization.
    type Error;
    /// A type with values that customize the serialization algorithm.
    type SerializeSettings: Default;

    /// Writes `self` to `buffer` using default settings.
    fn serialize<B>(&self, buffer: &mut B) -> usize
    where
        B: Buffer,
    {
        self.serialize_with(buffer, Self::SerializeSettings::default())
    }

    /// Writes `self` to `buffer` using custom serialization `settings`.
    fn serialize_with<B>(&self, buffer: &mut B, settings: Self::SerializeSettings) -> usize
    where
        B: Buffer;

    /// Parses and deserializes from `data`.
    fn deserialize(data: &'a [u8]) -> Result<Self, Self::Error>;

    /// Like [`FieldType::deserialize`], but with relaxed validation.
    fn deserialize_lossy(data: &'a [u8]) -> Result<Self, Self::Error> {
        Self::deserialize(data)
    }
}

/// Errors that can occur when accessing field values.
#[derive(Debug, Clone)]
pub enum FieldValueError<E> {
    /// The field is missing from the message.
    Missing,
    /// The field value is invalid and cannot be deserialized.
    Invalid(E),
}

/// Provides random access to FIX fields and groups within messages.
pub trait FieldMap<F> {
    /// The type returned by group access methods.
    type Group: RepeatingGroup<Entry = Self>;

    /// Looks for a `field` within `self` and returns its raw byte contents.
    fn get_raw(&self, field: F) -> Option<&[u8]>;

    /// Gets a field value with deserialization.
    fn get<'a, V: FieldType<'a>>(&'a self, field: F) -> Result<V, FieldValueError<V::Error>>;

    /// Gets an optional field value with deserialization.
    fn get_opt<'a, V: FieldType<'a>>(&'a self, field: F) -> Result<Option<V>, V::Error>;

    /// Gets a field value with lossy deserialization.
    fn get_lossy<'a, V: FieldType<'a>>(&'a self, field: F) -> Result<V, FieldValueError<V::Error>>;

    /// Gets an optional field value with lossy deserialization.
    fn get_lossy_opt<'a, V: FieldType<'a>>(&'a self, field: F) -> Result<Option<V>, V::Error>;

    /// Gets a repeating group.
    fn group(&self, field: F) -> Result<Self::Group, FieldValueError<<usize as FieldType>::Error>>;

    /// Gets an optional repeating group.
    fn group_opt(&self, field: F) -> Result<Option<Self::Group>, <usize as FieldType>::Error>;
}

/// Represents a repeating group of entries.
pub trait RepeatingGroup {
    /// The type of entries in this group.
    type Entry;

    /// Returns the number of entries in the group.
    fn len(&self) -> usize;

    /// Returns `true` if the group is empty.
    fn is_empty(&self) -> bool;

    /// Gets the entry at the specified index.
    fn get(&self, index: usize) -> Option<Self::Entry>;
}

/// Allows getting and setting configuration options.
pub trait GetConfig {
    /// The configuration options type.
    type Config;

    /// Returns an immutable reference to the configuration options.
    fn config(&self) -> &Self::Config;

    /// Returns a mutable reference to the configuration options.
    fn config_mut(&mut self) -> &mut Self::Config;
}

/// Allows setting field values.
pub trait SetField<F> {
    /// Sets a field with custom serialization settings.
    fn set_with<'b, V>(&'b mut self, field: F, value: V, settings: V::SerializeSettings)
    where
        V: FieldType<'b>;

    /// Sets a field with default serialization settings.
    fn set<'b, V>(&'b mut self, field: F, value: V)
    where
        V: FieldType<'b>,
    {
        self.set_with(field, value, V::SerializeSettings::default());
    }
}

/// Trait for streaming decoders.
pub trait StreamingDecoder {
    /// The buffer type used by this decoder.
    type Buffer;
    /// The error type that can be returned.
    type Error;

    /// Returns a mutable reference to the internal buffer.
    fn buffer(&mut self) -> &mut Self::Buffer;

    /// Returns the number of bytes required for the next parsing attempt.
    fn num_bytes_required(&self) -> usize;

    /// Attempts to parse the next message from the buffer.
    fn try_parse(&mut self) -> Result<Option<()>, Self::Error>;
}

// Implement FieldType for common types
impl<'a> FieldType<'a> for usize {
    type Error = InvalidInt;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        let s = self.to_string();
        buffer.extend_from_slice(s.as_bytes());
        s.len()
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(data)
            .map_err(|_| InvalidInt)?
            .parse()
            .map_err(|_| InvalidInt)
    }
}

/// Error type for invalid integer parsing.
#[derive(Debug, Clone, Copy)]
pub struct InvalidInt;

impl std::fmt::Display for InvalidInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid integer")
    }
}

impl std::error::Error for InvalidInt {}
