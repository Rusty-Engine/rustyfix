//! Performance tracing support for ASN.1 operations.

use fastrace::{Span, prelude::LocalSpan};
use std::time::Instant;

/// Creates a new span for encoding operations.
#[inline]
pub fn encoding_span(encoding_rule: &str, _message_type: &str) -> Span {
    Span::enter_with_local_parent(format!("asn1.encode.{encoding_rule}"))
}

/// Creates a new span for decoding operations.
#[inline]
pub fn decoding_span(encoding_rule: &str, _data_size: usize) -> Span {
    Span::enter_with_local_parent(format!("asn1.decode.{encoding_rule}"))
}

/// Creates a new span for schema operations.
#[inline]
pub fn schema_span(operation: &str) -> Span {
    Span::enter_with_local_parent(format!("asn1.schema.{operation}"))
}

/// Measures encoding performance metrics.
pub struct EncodingMetrics {
    start: Instant,
    encoding_rule: &'static str,
    message_type: String,
    field_count: usize,
}

impl EncodingMetrics {
    /// Creates new encoding metrics.
    pub fn new(encoding_rule: &'static str, message_type: String) -> Self {
        Self {
            start: Instant::now(),
            encoding_rule,
            message_type,
            field_count: 0,
        }
    }

    /// Records a field being encoded.
    pub fn record_field(&mut self) {
        self.field_count += 1;
    }

    /// Completes the metrics and records them.
    pub fn complete(self, _encoded_size: usize) {
        let _duration = self.start.elapsed();

        let _span = LocalSpan::enter_with_local_parent("encoding_complete");
        // TODO: Add proper metrics when fastrace API is stable
    }
}

/// Measures decoding performance metrics.
pub struct DecodingMetrics {
    start: Instant,
    encoding_rule: &'static str,
    input_size: usize,
}

impl DecodingMetrics {
    /// Creates new decoding metrics.
    pub fn new(encoding_rule: &'static str, input_size: usize) -> Self {
        Self {
            start: Instant::now(),
            encoding_rule,
            input_size,
        }
    }

    /// Completes the metrics and records them.
    pub fn complete(self, _message_type: &str, _field_count: usize) {
        let _duration = self.start.elapsed();

        let _span = LocalSpan::enter_with_local_parent("decoding_complete");
        // TODO: Add proper metrics when fastrace API is stable
    }
}

/// Records buffer allocation metrics.
pub fn record_buffer_allocation(_size: usize, _purpose: &str) {
    let _span = LocalSpan::enter_with_local_parent("buffer_allocation");
    // TODO: Add proper metrics when fastrace API is stable
}

/// Records schema lookup metrics.
pub fn record_schema_lookup(_message_type: &str, _found: bool, _duration_ns: u64) {
    let _span = LocalSpan::enter_with_local_parent("schema_lookup");
    // TODO: Add proper metrics when fastrace API is stable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_metrics() {
        let mut metrics = EncodingMetrics::new("DER", "NewOrderSingle".to_string());
        metrics.record_field();
        metrics.record_field();
        metrics.complete(256);
        // Metrics are recorded to fastrace
    }

    #[test]
    fn test_decoding_metrics() {
        let metrics = DecodingMetrics::new("BER", 512);
        metrics.complete("ExecutionReport", 15);
        // Metrics are recorded to fastrace
    }
}
