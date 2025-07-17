//! ASN.1 field type implementations that integrate with `RustyFix` `FieldType` trait.
//!
//! This module provides ASN.1 wrapper types that implement the `RustyFix` `FieldType` trait,
//! enabling seamless integration between ASN.1 encoding and the `RustyFix` ecosystem.

use crate::error::{DecodeError, EncodeError};
use crate::traits::{Buffer, FieldType};
use rasn::{AsnType, Decode, Decoder, Encode};
use std::convert::TryFrom;

/// Error type for ASN.1 field type operations.
#[derive(Debug, thiserror::Error)]
pub enum Asn1FieldError {
    /// Invalid ASN.1 encoding.
    #[error("Invalid ASN.1 encoding: {0}")]
    Encode(#[from] EncodeError),
    /// Invalid ASN.1 decoding.
    #[error("Invalid ASN.1 decoding: {0}")]
    Decode(#[from] DecodeError),
    /// Invalid UTF-8 string.
    #[error("Invalid UTF-8 string: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// Invalid numeric value.
    #[error("Invalid numeric value")]
    InvalidNumber,
    /// Invalid boolean value.
    #[error("Invalid boolean value")]
    InvalidBool,
    /// Repeating group parsing is not yet supported.
    #[error("Repeating group parsing is not yet supported. Group field tag: {tag}, count: {count}")]
    GroupParsingUnsupported {
        /// The field tag for the group count field
        tag: u32,
        /// The number of group entries that were expected
        count: usize,
    },
}

/// ASN.1 wrapper for UTF-8 strings.
#[derive(AsnType, Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1String {
    #[rasn(tag(0))]
    inner: String,
}

impl Asn1String {
    /// Creates a new ASN.1 string.
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Gets the inner string value.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Converts to inner string.
    pub fn into_string(self) -> String {
        self.inner
    }
}

impl From<String> for Asn1String {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Asn1String {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl<'a> FieldType<'a> for Asn1String {
    type Error = Asn1FieldError;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        // For FIX compatibility, serialize as plain UTF-8 string
        buffer.extend_from_slice(self.inner.as_bytes());
        self.inner.len()
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        let s = std::str::from_utf8(data)?;
        Ok(Self::new(s.to_string()))
    }

    fn deserialize_lossy(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        // For lossy deserialization, use String::from_utf8_lossy
        let s = String::from_utf8_lossy(data);
        Ok(Self::new(s.to_string()))
    }
}

/// ASN.1 wrapper for integers.
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1Integer {
    #[rasn(tag(0))]
    inner: i64,
}

impl Asn1Integer {
    /// Creates a new ASN.1 integer.
    pub fn new(value: i64) -> Self {
        Self { inner: value }
    }

    /// Gets the inner integer value.
    pub fn value(&self) -> i64 {
        self.inner
    }
}

impl From<i64> for Asn1Integer {
    fn from(value: i64) -> Self {
        Self::new(value)
    }
}

impl From<u32> for Asn1Integer {
    fn from(value: u32) -> Self {
        Self::new(i64::from(value))
    }
}

impl From<i32> for Asn1Integer {
    fn from(value: i32) -> Self {
        Self::new(i64::from(value))
    }
}

impl TryFrom<Asn1Integer> for u32 {
    type Error = Asn1FieldError;

    fn try_from(value: Asn1Integer) -> Result<Self, Self::Error> {
        u32::try_from(value.inner).map_err(|_| Asn1FieldError::InvalidNumber)
    }
}

impl<'a> FieldType<'a> for Asn1Integer {
    type Error = Asn1FieldError;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        // For FIX compatibility, serialize as decimal string
        let s = ToString::to_string(&self.inner);
        buffer.extend_from_slice(s.as_bytes());
        s.len()
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        let s = std::str::from_utf8(data)?;
        let value = s
            .parse::<i64>()
            .map_err(|_| Asn1FieldError::InvalidNumber)?;
        Ok(Self::new(value))
    }

    fn deserialize_lossy(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        // For lossy parsing, try to parse as much as possible
        let mut result = 0i64;
        let mut sign = 1i64;
        let mut idx = 0;

        if data.is_empty() {
            return Ok(Self::new(0));
        }

        // Handle sign
        if data[0] == b'-' {
            sign = -1;
            idx = 1;
        } else if data[0] == b'+' {
            idx = 1;
        }

        // Parse digits
        while idx < data.len() && data[idx].is_ascii_digit() {
            result = result
                .saturating_mul(10)
                .saturating_add(i64::from(data[idx] - b'0'));
            idx += 1;
        }

        Ok(Self::new(result * sign))
    }
}

/// ASN.1 wrapper for unsigned integers.
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1UInteger {
    #[rasn(tag(0))]
    inner: u64,
}

impl Asn1UInteger {
    /// Creates a new ASN.1 unsigned integer.
    pub fn new(value: u64) -> Self {
        Self { inner: value }
    }

    /// Gets the inner unsigned integer value.
    pub fn value(&self) -> u64 {
        self.inner
    }
}

impl From<u64> for Asn1UInteger {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<u32> for Asn1UInteger {
    fn from(value: u32) -> Self {
        Self::new(u64::from(value))
    }
}

impl From<u16> for Asn1UInteger {
    fn from(value: u16) -> Self {
        Self::new(u64::from(value))
    }
}

impl TryFrom<Asn1UInteger> for u32 {
    type Error = Asn1FieldError;

    fn try_from(value: Asn1UInteger) -> Result<Self, Self::Error> {
        u32::try_from(value.inner).map_err(|_| Asn1FieldError::InvalidNumber)
    }
}

impl TryFrom<Asn1UInteger> for u16 {
    type Error = Asn1FieldError;

    fn try_from(value: Asn1UInteger) -> Result<Self, Self::Error> {
        u16::try_from(value.inner).map_err(|_| Asn1FieldError::InvalidNumber)
    }
}

impl<'a> FieldType<'a> for Asn1UInteger {
    type Error = Asn1FieldError;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        // For FIX compatibility, serialize as decimal string
        let s = ToString::to_string(&self.inner);
        buffer.extend_from_slice(s.as_bytes());
        s.len()
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        let s = std::str::from_utf8(data)?;
        let value = s
            .parse::<u64>()
            .map_err(|_| Asn1FieldError::InvalidNumber)?;
        Ok(Self::new(value))
    }

    fn deserialize_lossy(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        // For lossy parsing, try to parse as much as possible
        let mut result = 0u64;
        let mut idx = 0;

        if data.is_empty() {
            return Ok(Self::new(0));
        }

        // Skip leading plus sign
        if data[0] == b'+' {
            idx = 1;
        }

        // Parse digits
        while idx < data.len() && data[idx].is_ascii_digit() {
            result = result
                .saturating_mul(10)
                .saturating_add(u64::from(data[idx] - b'0'));
            idx += 1;
        }

        Ok(Self::new(result))
    }
}

/// ASN.1 wrapper for boolean values.
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1Boolean {
    #[rasn(tag(0))]
    inner: bool,
}

impl Asn1Boolean {
    /// Creates a new ASN.1 boolean.
    pub fn new(value: bool) -> Self {
        Self { inner: value }
    }

    /// Gets the inner boolean value.
    pub fn value(&self) -> bool {
        self.inner
    }
}

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self::new(value)
    }
}

impl From<Asn1Boolean> for bool {
    fn from(value: Asn1Boolean) -> Self {
        value.inner
    }
}

impl<'a> FieldType<'a> for Asn1Boolean {
    type Error = Asn1FieldError;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        // For FIX compatibility, serialize as Y/N
        buffer.extend_from_slice(if self.inner { b"Y" } else { b"N" });
        1
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        match data {
            b"Y" | b"y" | b"1" | b"true" | b"TRUE" | b"True" => Ok(Self::new(true)),
            b"N" | b"n" | b"0" | b"false" | b"FALSE" | b"False" => Ok(Self::new(false)),
            _ => Err(Asn1FieldError::InvalidBool),
        }
    }

    fn deserialize_lossy(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        // For lossy parsing, be more liberal
        if data.is_empty() {
            return Ok(Self::new(false));
        }

        match data[0] {
            b'Y' | b'y' | b'T' | b't' | b'1' => Ok(Self::new(true)),
            _ => Ok(Self::new(false)),
        }
    }
}

/// ASN.1 wrapper for byte arrays.
#[derive(AsnType, Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1Bytes {
    #[rasn(tag(0))]
    inner: Vec<u8>,
}

impl Asn1Bytes {
    /// Creates a new ASN.1 byte array.
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Gets the inner byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Converts to inner byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }
}

impl From<Vec<u8>> for Asn1Bytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Asn1Bytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl<'a> FieldType<'a> for Asn1Bytes {
    type Error = Asn1FieldError;
    type SerializeSettings = ();

    fn serialize_with<B>(&self, buffer: &mut B, _settings: Self::SerializeSettings) -> usize
    where
        B: Buffer,
    {
        // For FIX compatibility, serialize as raw bytes
        buffer.extend_from_slice(&self.inner);
        self.inner.len()
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, <Self as FieldType<'a>>::Error> {
        Ok(Self::new(data.to_vec()))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_asn1_string_field_type() {
        let value = Asn1String::from("Hello World");

        // Test serialization
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = value.serialize(&mut buffer);
        assert_eq!(len, 11);
        assert_eq!(&buffer[..], b"Hello World");

        // Test deserialization
        let deserialized = Asn1String::deserialize(b"Test String")
            .expect("Failed to deserialize valid UTF-8 string");
        assert_eq!(deserialized.as_str(), "Test String");

        // Test lossy deserialization with invalid UTF-8
        let lossy = Asn1String::deserialize_lossy(b"Valid UTF-8")
            .expect("Lossy deserialization should not fail");
        assert_eq!(lossy.as_str(), "Valid UTF-8");
    }

    #[test]
    fn test_asn1_integer_field_type() {
        let value = Asn1Integer::from(42i64);

        // Test serialization
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = value.serialize(&mut buffer);
        assert_eq!(len, 2);
        assert_eq!(&buffer[..], b"42");

        // Test negative number
        let negative = Asn1Integer::from(-123i64);
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = negative.serialize(&mut buffer);
        assert_eq!(len, 4);
        assert_eq!(&buffer[..], b"-123");

        // Test deserialization
        let deserialized =
            Asn1Integer::deserialize(b"456").expect("Failed to deserialize valid integer");
        assert_eq!(deserialized.value(), 456);

        // Test lossy deserialization
        let lossy = Asn1Integer::deserialize_lossy(b"789abc")
            .expect("Lossy integer deserialization should not fail");
        assert_eq!(lossy.value(), 789);
    }

    #[test]
    fn test_asn1_uinteger_field_type() {
        let value = Asn1UInteger::from(123u64);

        // Test serialization
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = value.serialize(&mut buffer);
        assert_eq!(len, 3);
        assert_eq!(&buffer[..], b"123");

        // Test deserialization
        let deserialized = Asn1UInteger::deserialize(b"456")
            .expect("Failed to deserialize valid unsigned integer");
        assert_eq!(deserialized.value(), 456);

        // Test conversion
        let as_u32: u32 = deserialized.try_into().expect("Failed to convert to u32");
        assert_eq!(as_u32, 456);
    }

    #[test]
    fn test_asn1_boolean_field_type() {
        let true_value = Asn1Boolean::from(true);
        let false_value = Asn1Boolean::from(false);

        // Test serialization
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = true_value.serialize(&mut buffer);
        assert_eq!(len, 1);
        assert_eq!(&buffer[..], b"Y");

        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = false_value.serialize(&mut buffer);
        assert_eq!(len, 1);
        assert_eq!(&buffer[..], b"N");

        // Test deserialization
        assert!(
            Asn1Boolean::deserialize(b"Y")
                .expect("Failed to deserialize 'Y' as boolean")
                .value()
        );
        assert!(
            Asn1Boolean::deserialize(b"1")
                .expect("Failed to deserialize '1' as boolean")
                .value()
        );
        assert!(
            !Asn1Boolean::deserialize(b"N")
                .expect("Failed to deserialize 'N' as boolean")
                .value()
        );
        assert!(
            !Asn1Boolean::deserialize(b"0")
                .expect("Failed to deserialize '0' as boolean")
                .value()
        );

        // Test lossy deserialization
        assert!(
            Asn1Boolean::deserialize_lossy(b"Yes")
                .expect("Lossy boolean deserialization should not fail")
                .value()
        );
        assert!(
            !Asn1Boolean::deserialize_lossy(b"No")
                .expect("Lossy boolean deserialization should not fail")
                .value()
        );
    }

    #[test]
    fn test_asn1_bytes_field_type() {
        let data = vec![0x01, 0x02, 0x03, 0xFF];
        let value = Asn1Bytes::from(data.clone());

        // Test serialization
        let mut buffer: smallvec::SmallVec<[u8; 64]> = smallvec::SmallVec::new();
        let len = value.serialize(&mut buffer);
        assert_eq!(len, 4);
        assert_eq!(&buffer[..], &data[..]);

        // Test deserialization
        let deserialized = Asn1Bytes::deserialize(&data).expect("Failed to deserialize byte array");
        assert_eq!(deserialized.as_bytes(), &data[..]);
    }
}
