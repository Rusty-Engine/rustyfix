//! Error types for ASN.1 encoding and decoding operations.

use smartstring::{LazyCompact, SmartString};
use thiserror::Error;

type FixString = SmartString<LazyCompact>;

/// Result type alias for ASN.1 operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for ASN.1 operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Encoding error occurred
    #[error("Encoding error: {0}")]
    Encode(#[from] EncodeError),

    /// Decoding error occurred
    #[error("Decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Schema-related error
    #[error("Schema error: {0}")]
    Schema(FixString),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(FixString),

    /// I/O error during operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// ASN.1 library error
    #[error("ASN.1 library error: {0}")]
    Asn1(String),
}

/// Errors that can occur during encoding.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Field value is invalid for encoding
    #[error("Invalid field value for tag {tag}: {reason}")]
    InvalidFieldValue {
        /// FIX tag number
        tag: u32,
        /// Reason for invalidity
        reason: FixString,
    },

    /// Message exceeds maximum allowed size
    #[error("Message size {size} exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual message size
        size: usize,
        /// Maximum allowed size
        max_size: usize,
    },

    /// Required field is missing
    #[error("Required field {tag} ({name}) is missing")]
    RequiredFieldMissing {
        /// FIX tag number
        tag: u32,
        /// Field name
        name: FixString,
    },

    /// Unsupported encoding rule for this message type
    #[error("Encoding rule {rule} not supported for message type {msg_type}")]
    UnsupportedEncodingRule {
        /// Encoding rule name
        rule: &'static str,
        /// Message type
        msg_type: FixString,
    },

    /// Buffer capacity exceeded
    #[error("Buffer capacity exceeded: needed {needed}, available {available}")]
    BufferCapacityExceeded {
        /// Bytes needed
        needed: usize,
        /// Bytes available
        available: usize,
    },

    /// Schema mismatch
    #[error("Schema mismatch: {0}")]
    SchemaMismatch(FixString),

    /// Internal encoding error from rasn
    #[error("Internal ASN.1 encoding error: {0}")]
    Internal(String),
}

/// Errors that can occur during decoding.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Invalid ASN.1 tag encountered
    #[error("Invalid ASN.1 tag {tag:02X} at offset {offset}")]
    InvalidTag {
        /// The invalid tag value
        tag: u8,
        /// Byte offset in input
        offset: usize,
    },

    /// Unexpected end of input
    #[error("Unexpected end of input at offset {offset}, needed {needed} more bytes")]
    UnexpectedEof {
        /// Byte offset where EOF occurred
        offset: usize,
        /// Additional bytes needed
        needed: usize,
    },

    /// Length encoding is invalid
    #[error("Invalid length encoding at offset {offset}")]
    InvalidLength {
        /// Byte offset of invalid length
        offset: usize,
    },

    /// Value violates constraints
    #[error("Value constraint violation for field {field}: {reason}")]
    ConstraintViolation {
        /// Field name or tag
        field: FixString,
        /// Constraint violation reason
        reason: FixString,
    },

    /// Checksum validation failed
    #[error("Checksum validation failed: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Expected checksum value
        expected: u32,
        /// Actual checksum value
        actual: u32,
    },

    /// Maximum recursion depth exceeded
    #[error("Maximum recursion depth {max_depth} exceeded")]
    RecursionDepthExceeded {
        /// Maximum allowed depth
        max_depth: u32,
    },

    /// Invalid UTF-8 in string field
    #[error("Invalid UTF-8 in string field at offset {offset}")]
    InvalidUtf8 {
        /// Byte offset of invalid UTF-8
        offset: usize,
    },

    /// Unsupported encoding rule
    #[error("Unsupported encoding rule for decoding: {0}")]
    UnsupportedEncodingRule(&'static str),

    /// Schema required but not provided
    #[error("Schema required for {encoding_rule} decoding but not provided")]
    SchemaRequired {
        /// Encoding rule that requires schema
        encoding_rule: &'static str,
    },

    /// Internal decoding error from rasn
    #[error("Internal ASN.1 decoding error: {0}")]
    Internal(String),
}

impl From<rasn::error::EncodeError> for EncodeError {
    fn from(err: rasn::error::EncodeError) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<rasn::error::DecodeError> for DecodeError {
    fn from(err: rasn::error::DecodeError) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<rasn::error::EncodeError> for Error {
    fn from(err: rasn::error::EncodeError) -> Self {
        Self::Encode(err.into())
    }
}

impl From<rasn::error::DecodeError> for Error {
    fn from(err: rasn::error::DecodeError) -> Self {
        Self::Decode(err.into())
    }
}

/// Extension trait for converting rasn errors with context.
pub(crate) trait ErrorContext<T> {
    /// Add context to an error.
    fn context(self, msg: impl Into<FixString>) -> Result<T>;

    /// Add field context to an error.
    fn field_context(self, tag: u32, name: impl Into<FixString>) -> Result<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: Into<Error>,
{
    fn context(self, msg: impl Into<FixString>) -> Result<T> {
        self.map_err(|e| {
            let base_error = e.into();
            match base_error {
                Error::Encode(EncodeError::Internal(s)) => Error::Encode(
                    EncodeError::SchemaMismatch(format!("{}: {}", msg.into(), s).into()),
                ),
                Error::Decode(DecodeError::Internal(s)) => {
                    Error::Schema(format!("{}: {}", msg.into(), s).into())
                }
                other => other,
            }
        })
    }

    fn field_context(self, tag: u32, name: impl Into<FixString>) -> Result<T> {
        self.map_err(|e| {
            let base_error = e.into();
            match base_error {
                Error::Encode(EncodeError::Internal(s)) => {
                    Error::Encode(EncodeError::InvalidFieldValue {
                        tag,
                        reason: format!("{} - {}", name.into(), s).into(),
                    })
                }
                other => other,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = EncodeError::MessageTooLarge {
            size: 100_000,
            max_size: 65_536,
        };
        assert_eq!(err.to_string(), "Message size 100000 exceeds maximum 65536");
    }

    #[test]
    fn test_error_conversion() {
        // Test the error types can be created and converted
        let encode_err = EncodeError::Internal("test error".to_string());
        let main_error: Error = encode_err.into();
        assert!(matches!(main_error, Error::Encode(_)));
    }
}
