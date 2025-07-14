//! Configuration options for ASN.1 encoding and decoding.

use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;
use std::sync::Arc;

/// Encoding rule to use for ASN.1 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EncodingRule {
    /// Basic Encoding Rules - Self-describing, flexible format
    BER,
    /// Distinguished Encoding Rules - Canonical subset of BER
    DER,
    /// Packed Encoding Rules - Compact, bit-oriented format
    PER,
    /// Aligned Packed Encoding Rules - PER with alignment
    APER,
    /// Unaligned Packed Encoding Rules - PER without alignment
    UPER,
    /// Octet Encoding Rules - Byte-aligned, efficient format
    OER,
}

impl EncodingRule {
    /// Returns the name of the encoding rule.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BER => "BER",
            Self::DER => "DER",
            Self::PER => "PER",
            Self::APER => "APER",
            Self::UPER => "UPER",
            Self::OER => "OER",
        }
    }

    /// Returns whether the encoding is self-describing (contains type information).
    #[must_use]
    pub const fn is_self_describing(&self) -> bool {
        matches!(self, Self::BER | Self::DER)
    }

    /// Returns whether the encoding requires strict schema adherence.
    #[must_use]
    pub const fn requires_schema(&self) -> bool {
        matches!(self, Self::PER | Self::APER | Self::UPER | Self::OER)
    }
}

impl Default for EncodingRule {
    fn default() -> Self {
        // Default to DER for deterministic encoding
        Self::DER
    }
}

/// Configuration for ASN.1 encoding and decoding operations.
#[derive(Clone)]
pub struct Config {
    /// The encoding rule to use
    pub encoding_rule: EncodingRule,

    /// Maximum message size in bytes (default: 64KB)
    pub max_message_size: usize,

    /// Maximum recursion depth for nested structures (default: 32)
    pub max_recursion_depth: u32,

    /// Whether to validate message checksums (default: true)
    pub validate_checksums: bool,

    /// Whether to use strict type checking (default: true)
    pub strict_type_checking: bool,

    /// Buffer size for streaming operations (default: 8KB)
    pub stream_buffer_size: usize,

    /// Whether to enable zero-copy optimizations where possible
    pub enable_zero_copy: bool,

    /// Custom encoding options for specific message types
    pub message_options: Arc<RwLock<FxHashMap<FixString, MessageOptions>>>,
}

/// Per-message type encoding options.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageOptions {
    /// Override encoding rule for this message type
    pub encoding_rule: Option<EncodingRule>,

    /// Whether to compress this message type
    pub compress: bool,

    /// Custom maximum size for this message type
    pub max_size: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            encoding_rule: EncodingRule::default(),
            max_message_size: 64 * 1024, // 64KB
            max_recursion_depth: 32,
            validate_checksums: true,
            strict_type_checking: true,
            stream_buffer_size: 8 * 1024, // 8KB
            enable_zero_copy: true,
            message_options: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }
}

impl Config {
    /// Creates a new configuration with the specified encoding rule.
    #[must_use]
    pub fn new(encoding_rule: EncodingRule) -> Self {
        Self {
            encoding_rule,
            ..Default::default()
        }
    }

    /// Creates a configuration optimized for low-latency trading.
    #[must_use]
    pub fn low_latency() -> Self {
        Self {
            encoding_rule: EncodingRule::PER, // Most compact
            max_message_size: 16 * 1024,      // Smaller for faster processing
            validate_checksums: false,        // Skip validation for speed
            strict_type_checking: false,      // Relax checking
            enable_zero_copy: true,           // Always enable
            ..Default::default()
        }
    }

    /// Creates a configuration optimized for reliability and compliance.
    #[must_use]
    pub fn high_reliability() -> Self {
        Self {
            encoding_rule: EncodingRule::DER, // Deterministic
            validate_checksums: true,         // Always validate
            strict_type_checking: true,       // Strict checking
            enable_zero_copy: false,          // Prefer safety
            ..Default::default()
        }
    }

    /// Sets custom options for a specific message type.
    pub fn set_message_options(&self, message_type: impl Into<FixString>, options: MessageOptions) {
        self.message_options
            .write()
            .insert(message_type.into(), options);
    }

    /// Gets custom options for a specific message type.
    pub fn get_message_options(&self, message_type: &str) -> Option<MessageOptions> {
        self.message_options.read().get(message_type).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_rule_properties() {
        assert!(EncodingRule::BER.is_self_describing());
        assert!(EncodingRule::DER.is_self_describing());
        assert!(!EncodingRule::PER.is_self_describing());

        assert!(EncodingRule::PER.requires_schema());
        assert!(!EncodingRule::BER.requires_schema());
    }

    #[test]
    fn test_config_presets() {
        let low_latency = Config::low_latency();
        assert_eq!(low_latency.encoding_rule, EncodingRule::PER);
        assert!(!low_latency.validate_checksums);

        let high_reliability = Config::high_reliability();
        assert_eq!(high_reliability.encoding_rule, EncodingRule::DER);
        assert!(high_reliability.validate_checksums);
    }

    #[test]
    fn test_message_options() {
        let config = Config::default();
        let options = MessageOptions {
            encoding_rule: Some(EncodingRule::OER),
            compress: true,
            max_size: Some(1024),
        };

        config.set_message_options("NewOrderSingle", options.clone());
        let retrieved = config
            .get_message_options("NewOrderSingle")
            .expect("Failed to retrieve message options for test");
        assert_eq!(retrieved.encoding_rule, Some(EncodingRule::OER));
        assert!(retrieved.compress);
    }
}
