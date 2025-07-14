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
//! ```rust,ignore
//! use rustyasn::{Config, Encoder, Decoder, EncodingRule};
//! use rustyfix::Dictionary;
//!
//! // Configure encoding
//! let config = Config::new(EncodingRule::OER);
//! let dictionary = Dictionary::fix44();
//!
//! // Encode a message
//! let mut encoder = Encoder::new(config, dictionary);
//! let encoded = encoder.encode_message(msg)?;
//!
//! // Decode a message
//! let decoder = Decoder::new(config, dictionary);
//! let message = decoder.decode(&encoded)?;
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
mod tracing;

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
