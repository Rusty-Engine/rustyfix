//! # `RustyASN` - ASN.1 Encoding for FIX Protocol
//!
//! This crate provides Abstract Syntax Notation One (ASN.1) encoding support for the FIX protocol.
//! It supports multiple encoding rules:
//!
//! - **BER** (Basic Encoding Rules) - Self-describing, flexible
//! - **DER** (Distinguished Encoding Rules) - Canonical subset of BER
//! - **OER** (Octet Encoding Rules) - Byte-aligned, efficient
//!
//! ## Features
//!
//! - Zero-copy decoding where possible
//! - Streaming support for continuous message processing
//! - Type-safe ASN.1 schema compilation
//! - Integration with `RustyFix` field types
//! - High-performance implementation optimized for low-latency trading
//!
//! ## Usage
//!
//! ```rust,no_run
//! use rustyasn::{Config, Encoder, Decoder, EncodingRule};
//! use rustyfix::Dictionary;
//! use std::sync::Arc;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure encoding
//!     let config = Config::new(EncodingRule::OER);
//!     let dictionary = Arc::new(Dictionary::fix44()?);
//!
//!     // Create encoder and decoder
//!     let encoder = Encoder::new(config.clone(), dictionary.clone());
//!     let decoder = Decoder::new(config, dictionary);
//!
//!     // Start encoding a message
//!     let mut handle = encoder.start_message(
//!         "D",         // MsgType: NewOrderSingle
//!         "SENDER",    // SenderCompID
//!         "TARGET",    // TargetCompID
//!         1,           // MsgSeqNum
//!     );
//!
//!     // Add fields and encode
//!     handle.add_string(11, "ORDER001");  // ClOrdID
//!     let encoded = handle.encode()?;
//!
//!     // Decode the message
//!     let message = decoder.decode(&encoded)?;
//!     println!("Decoded message type: {}", message.msg_type());
//!     
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    missing_docs,
    rust_2024_incompatible_pat,
    unsafe_op_in_unsafe_fn,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![warn(clippy::all, clippy::pedantic, rust_2024_compatibility)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod buffers;
pub mod config;
pub mod decoder;
pub mod encoder;
pub mod error;
pub mod field_types;
pub mod generated;
pub mod message;
pub mod schema;
pub mod types;

#[cfg(feature = "tracing")]
pub mod tracing;

pub use config::{Config, EncodingRule};
pub use decoder::{Decoder, DecoderStreaming};
pub use encoder::{Encoder, EncoderHandle};
pub use error::{DecodeError, EncodeError, Error, Result};
pub use field_types::{
    Asn1Boolean, Asn1Bytes, Asn1FieldError, Asn1Integer, Asn1String, Asn1UInteger,
};
pub use generated::{Asn1Field, Asn1FixMessage, FixFieldTag, FixMessageType};
pub use message::{Message, MessageGroup};

// Re-export rasn types that users might need
pub use rasn::{AsnType, Decode, Encode};

/// Version information for the ASN.1 encoding implementation
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Const generic buffer sizes for optimal performance
/// Default buffer size for field serialization (64 bytes)
pub const FIELD_BUFFER_SIZE: usize = 64;

/// Size for small field collections (8 fields)
pub const SMALL_FIELD_COLLECTION_SIZE: usize = 8;

/// Size for medium field collections (16 fields)
pub const MEDIUM_FIELD_COLLECTION_SIZE: usize = 16;

/// Maximum number of standard header fields
pub const MAX_HEADER_FIELDS: usize = 8;
