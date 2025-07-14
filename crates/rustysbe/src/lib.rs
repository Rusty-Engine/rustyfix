//! RustySBE - High-performance Simple Binary Encoding (SBE) for Rust
//!
//! This crate provides zero-copy, high-performance SBE encoding and decoding
//! capabilities optimized for financial trading systems and other low-latency
//! applications.
//!
//! # Features
//!
//! - **Zero-copy decoding** - Read directly from network buffers
//! - **SIMD-aligned buffers** - Optimized memory access patterns
//! - **Type-safe message handling** - Compile-time message validation
//! - **Group iteration** - Efficient handling of repeating groups
//! - **Variable-length data** - Support for varchar fields
//! - **High performance** - Minimal allocations and overhead
//!
//! # Example
//!
//! ```rust,ignore
//! use rustysbe::{SbeDecoder, SbeEncoder, SbeMessage};
//!
//! // Encode a message
//! let mut encoder = SbeEncoder::new(1, 0, 64);
//! encoder.write_u64(0, 12345)?;
//! encoder.write_string(8, 16, "BTCUSDT")?;
//! let message = encoder.finalize()?;
//!
//! // Decode the message
//! let decoder = SbeDecoder::new(&message)?;
//! let value = decoder.read_u64(0)?;
//! let symbol = decoder.read_string(8, 16)?;
//! ```

pub mod buffer;
pub mod codegen;
pub mod decoder;
pub mod encoder;
pub mod error;
pub mod message;

// Re-export commonly used types for convenience
pub use buffer::{SbeBuffer, SbeReader};
pub use decoder::{SbeDecoder, SbeGroupElement, SbeGroupIterator, SbeHeader, SbeVariableData};
pub use encoder::{GroupElementEncoder, GroupEncoderBuilder, SbeEncoder};
pub use error::{SbeError, SbeResult};
pub use message::{
    SbeMessage, SbeMessageDecoder, SbeMessageEncoder, SbeMessageHeader, SbeMessageMetadata,
    SbeMessageRegistry,
};

/// Generated SBE message types from schema
pub mod generated {
    #![allow(clippy::all)]
    #![allow(missing_docs)]
    #![allow(non_snake_case)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/sbe.rs"));
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        SbeBuffer, SbeDecoder, SbeEncoder, SbeError, SbeMessage, SbeMessageDecoder,
        SbeMessageEncoder, SbeMessageHeader, SbeMessageRegistry, SbeReader, SbeResult,
    };
}

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SBE specification version supported
pub const SBE_VERSION: &str = "2.0";

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_basic_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        // Test basic encoding/decoding functionality
        let mut encoder = SbeEncoder::new(1, 0, 32);

        // Write test data
        encoder
            .write_u64(0, 1234567890)
            .map_err(|e| format!("Failed to write u64: {e}"))?;
        encoder
            .write_u32(8, 42)
            .map_err(|e| format!("Failed to write u32: {e}"))?;
        encoder
            .write_string(12, 16, "TEST_STRING")
            .map_err(|e| format!("Failed to write string: {e}"))?;
        encoder
            .write_f32(28, std::f32::consts::PI)
            .map_err(|e| format!("Failed to write f32: {e}"))?;

        let message = encoder
            .finalize()
            .map_err(|e| format!("Failed to finalize encoder: {e}"))?;

        // Decode and verify
        let decoder =
            SbeDecoder::new(&message).map_err(|e| format!("Failed to create decoder: {e}"))?;
        assert_eq!(decoder.template_id(), 1);
        assert_eq!(decoder.schema_version(), 0);

        let read_u64 = decoder
            .read_u64(0)
            .map_err(|e| format!("Failed to read u64: {e}"))?;
        assert_eq!(read_u64, 1234567890);

        let read_u32 = decoder
            .read_u32(8)
            .map_err(|e| format!("Failed to read u32: {e}"))?;
        assert_eq!(read_u32, 42);

        let read_string = decoder
            .read_string(12, 16)
            .map_err(|e| format!("Failed to read string: {e}"))?;
        assert_eq!(read_string.trim_end_matches('\0'), "TEST_STRING");

        let read_f32 = decoder
            .read_f32(28)
            .map_err(|e| format!("Failed to read f32: {e}"))?;
        assert!((read_f32 - std::f32::consts::PI).abs() < 0.001);

        Ok(())
    }

    #[test]
    fn test_variable_data() -> Result<(), Box<dyn std::error::Error>> {
        let mut encoder = SbeEncoder::new(2, 0, 8);

        // Fixed field
        encoder
            .write_u64(0, 999)
            .map_err(|e| format!("Failed to write u64: {e}"))?;

        // Variable data
        encoder
            .write_variable_string("Hello")
            .map_err(|e| format!("Failed to write variable string: {e}"))?;
        encoder
            .write_variable_string("World")
            .map_err(|e| format!("Failed to write variable string: {e}"))?;
        encoder
            .write_variable_bytes(b"Binary data")
            .map_err(|e| format!("Failed to write variable bytes: {e}"))?;

        let message = encoder
            .finalize()
            .map_err(|e| format!("Failed to finalize encoder: {e}"))?;

        // Verify fixed field
        let decoder =
            SbeDecoder::new(&message).map_err(|e| format!("Failed to create decoder: {e}"))?;
        let read_u64 = decoder
            .read_u64(0)
            .map_err(|e| format!("Failed to read u64: {e}"))?;
        assert_eq!(read_u64, 999);

        // Variable data would be processed by generated code
        assert!(message.len() > 8 + 8); // Header + fixed field + variable data
        Ok(())
    }

    #[test]
    fn test_header_utilities() -> Result<(), Box<dyn std::error::Error>> {
        let mut encoder = SbeEncoder::new(123, 5, 16);
        encoder
            .write_u64(0, 42)
            .map_err(|e| format!("Failed to write u64: {e}"))?;
        encoder
            .write_u64(8, 84)
            .map_err(|e| format!("Failed to write u64: {e}"))?;
        let message = encoder
            .finalize()
            .map_err(|e| format!("Failed to finalize encoder: {e}"))?;

        // Test header extraction
        let template_id = SbeMessageHeader::extract_template_id(&message)
            .map_err(|e| format!("Failed to extract template_id: {e}"))?;
        let schema_version = SbeMessageHeader::extract_schema_version(&message)
            .map_err(|e| format!("Failed to extract schema_version: {e}"))?;
        let length = SbeMessageHeader::extract_message_length(&message)
            .map_err(|e| format!("Failed to extract message_length: {e}"))?;

        assert_eq!(template_id, 123);
        assert_eq!(schema_version, 5);
        assert_eq!(length, message.len() as u32);

        // Test validation
        let (len, tid, sv) = SbeMessageHeader::validate_basic(&message)
            .map_err(|e| format!("Failed to validate basic: {e}"))?;
        assert_eq!(len, message.len() as u32);
        assert_eq!(tid, 123);
        assert_eq!(sv, 5);

        Ok(())
    }

    #[test]
    fn test_error_handling() {
        // Test buffer too small
        let small_buffer = [1, 2, 3];
        assert!(SbeDecoder::new(&small_buffer).is_err());

        // Test invalid template ID extraction
        let invalid_header = [0, 0, 0, 0]; // Too small
        assert!(SbeMessageHeader::extract_template_id(&invalid_header).is_err());

        // Test field offset out of bounds
        let mut encoder = SbeEncoder::new(1, 0, 8);
        assert!(encoder.write_u64(4, 123).is_err()); // Would overlap boundary
    }
}
