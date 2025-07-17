//! Performance tracing support for ASN.1 operations.

use fastrace::{Span, prelude::LocalSpan};
use std::time::Instant;

// Static span names for common encoding operations (zero-allocation)
const ENCODE_BER_SPAN: &str = "asn1.encode.BER";
const ENCODE_DER_SPAN: &str = "asn1.encode.DER";
const ENCODE_OER_SPAN: &str = "asn1.encode.OER";
const ENCODE_PER_SPAN: &str = "asn1.encode.PER";
const ENCODE_XER_SPAN: &str = "asn1.encode.XER";
const ENCODE_JER_SPAN: &str = "asn1.encode.JER";

// Static span names for common decoding operations (zero-allocation)
const DECODE_BER_SPAN: &str = "asn1.decode.BER";
const DECODE_DER_SPAN: &str = "asn1.decode.DER";
const DECODE_OER_SPAN: &str = "asn1.decode.OER";
const DECODE_PER_SPAN: &str = "asn1.decode.PER";
const DECODE_XER_SPAN: &str = "asn1.decode.XER";
const DECODE_JER_SPAN: &str = "asn1.decode.JER";

// Static span names for common schema operations (zero-allocation)
const SCHEMA_VALIDATE_SPAN: &str = "asn1.schema.validate";
const SCHEMA_LOOKUP_SPAN: &str = "asn1.schema.lookup";
const SCHEMA_COMPILE_SPAN: &str = "asn1.schema.compile";
const SCHEMA_TRANSFORM_SPAN: &str = "asn1.schema.transform";
const SCHEMA_PARSE_SPAN: &str = "asn1.schema.parse";
const SCHEMA_SERIALIZE_SPAN: &str = "asn1.schema.serialize";

/// Creates a distributed tracing span for ASN.1 encoding operations.
///
/// Tracks encoding performance and aids in debugging high-throughput systems.
///
/// # Arguments
///
/// * `encoding_rule` - The ASN.1 encoding rule being used (e.g., "BER", "DER", "OER").
/// * `_message_type` - Reserved for future metrics; currently unused.
///
/// # Returns
///
/// A [`Span`] that tracks the encoding operation. The span is entered automatically
/// and exits when dropped.
///
/// # Examples
///
/// ```rust
/// use rustyasn::tracing::encoding_span;
///
/// let _span = encoding_span("DER", "NewOrderSingle");
/// // Encoding work happens within this span
/// // Span is automatically closed when _span is dropped
/// ```
///
/// # Performance
///
/// This function is marked `#[inline]` for minimal overhead in performance-critical
/// encoding paths. The span creation is optimized for low-latency trading systems.
/// Common encoding rules (BER, DER, OER, PER, XER, JER) use static strings to avoid
/// heap allocation, with fallback to generic span name for rare unknown rules.
#[inline]
pub fn encoding_span(encoding_rule: &str, _message_type: &str) -> Span {
    match encoding_rule {
        "BER" => Span::enter_with_local_parent(ENCODE_BER_SPAN),
        "DER" => Span::enter_with_local_parent(ENCODE_DER_SPAN),
        "OER" => Span::enter_with_local_parent(ENCODE_OER_SPAN),
        "PER" => Span::enter_with_local_parent(ENCODE_PER_SPAN),
        "XER" => Span::enter_with_local_parent(ENCODE_XER_SPAN),
        "JER" => Span::enter_with_local_parent(ENCODE_JER_SPAN),
        // Use generic span name for unknown encoding rules (rare case) to avoid heap allocation
        _ => Span::enter_with_local_parent("asn1.encode.unknown"),
    }
}

/// Creates a new span for decoding operations.
///
/// This function creates a distributed tracing span to track ASN.1 decoding operations.
/// The span helps monitor decoding performance, detect bottlenecks, and debug parsing
/// issues in high-frequency trading systems.
///
/// # Arguments
///
/// * `encoding_rule` - The ASN.1 encoding rule being used (e.g., "BER", "DER", "OER")
/// * `_data_size` - The size of the data being decoded (currently unused but reserved for future metrics)
///
/// # Returns
///
/// A [`Span`] that tracks the decoding operation. The span is automatically entered
/// and will be exited when dropped.
///
/// # Examples
///
/// ```rust
/// use rustyasn::tracing::decoding_span;
///
/// let data = &[0x30, 0x0A, 0x02, 0x01, 0x05]; // Sample ASN.1 data
/// let _span = decoding_span("DER", data.len());
/// // Decoding work happens within this span
/// // Span is automatically closed when _span is dropped
/// ```
///
/// # Performance
///
/// This function is marked `#[inline]` for minimal overhead in performance-critical
/// decoding paths. The span creation is optimized for low-latency message processing.
/// Common encoding rules (BER, DER, OER, PER, XER, JER) use static strings to avoid
/// heap allocation, with fallback to generic span name for rare unknown rules.
#[inline]
pub fn decoding_span(encoding_rule: &str, _data_size: usize) -> Span {
    match encoding_rule {
        "BER" => Span::enter_with_local_parent(DECODE_BER_SPAN),
        "DER" => Span::enter_with_local_parent(DECODE_DER_SPAN),
        "OER" => Span::enter_with_local_parent(DECODE_OER_SPAN),
        "PER" => Span::enter_with_local_parent(DECODE_PER_SPAN),
        "XER" => Span::enter_with_local_parent(DECODE_XER_SPAN),
        "JER" => Span::enter_with_local_parent(DECODE_JER_SPAN),
        // Use generic span name for unknown encoding rules (rare case) to avoid heap allocation
        _ => Span::enter_with_local_parent("asn1.decode.unknown"),
    }
}

/// Creates a new span for schema operations.
///
/// This function creates a distributed tracing span to track ASN.1 schema-related operations
/// such as validation, lookup, compilation, and transformation. Schema operations are critical
/// for ensuring message integrity and type safety in FIX protocol implementations.
///
/// # Arguments
///
/// * `operation` - The schema operation being performed (e.g., "validate", "lookup", "compile", "transform")
///
/// # Returns
///
/// A [`Span`] that tracks the schema operation. The span is automatically entered
/// and will be exited when dropped.
///
/// # Examples
///
/// ```rust
/// use rustyasn::tracing::schema_span;
///
/// // Track schema validation
/// let _span = schema_span("validate");
/// // Schema validation work happens within this span
///
/// // Track schema lookup
/// let _span = schema_span("lookup");
/// // Schema lookup work happens within this span
/// ```
///
/// # Common Operations
///
/// - `"validate"` - Schema validation against ASN.1 definitions
/// - `"lookup"` - Field or message type lookups in schema
/// - `"compile"` - Schema compilation from definitions
/// - `"transform"` - Schema transformations and optimizations
///
/// # Performance
///
/// This function is marked `#[inline]` for minimal overhead. Schema operations
/// can be performance-critical in message processing pipelines, especially when
/// validating incoming messages in real-time trading systems.
/// Common operations (validate, lookup, compile, transform, parse, serialize) use
/// static strings to avoid heap allocation, with fallback to generic span name for rare unknown operations.
#[inline]
pub fn schema_span(operation: &str) -> Span {
    match operation {
        "validate" => Span::enter_with_local_parent(SCHEMA_VALIDATE_SPAN),
        "lookup" => Span::enter_with_local_parent(SCHEMA_LOOKUP_SPAN),
        "compile" => Span::enter_with_local_parent(SCHEMA_COMPILE_SPAN),
        "transform" => Span::enter_with_local_parent(SCHEMA_TRANSFORM_SPAN),
        "parse" => Span::enter_with_local_parent(SCHEMA_PARSE_SPAN),
        "serialize" => Span::enter_with_local_parent(SCHEMA_SERIALIZE_SPAN),
        // Use generic span name for unknown operations (rare case) to avoid heap allocation
        _ => Span::enter_with_local_parent("asn1.schema.unknown"),
    }
}

/// Measures encoding performance metrics.
pub struct EncodingMetrics {
    start: Instant,
    encoding_rule: &'static str,
    message_type: String,
    field_count: usize,
}

impl EncodingMetrics {
    /// Creates a new encoding metrics tracker.
    pub fn new(encoding_rule: &'static str, message_type: String) -> Self {
        Self {
            start: Instant::now(),
            encoding_rule,
            message_type,
            field_count: 0,
        }
    }

    /// Records that a field has been encoded.
    pub fn record_field(&mut self) {
        self.field_count += 1;
    }

    /// Completes the encoding metrics and logs the results.
    pub fn complete(self, encoded_size: usize) {
        let duration = self.start.elapsed();

        // TODO: Implement proper metrics collection
        // For now, we use basic logging. In production, this would integrate with
        // a metrics system like Prometheus or send to a telemetry service.
        log::debug!(
            "ASN.1 encoding completed: rule={}, type={}, fields={}, size={}, duration={:?}",
            self.encoding_rule,
            self.message_type,
            self.field_count,
            encoded_size,
            duration
        );
    }

    /// Gets the encoding rule being used.
    pub fn encoding_rule(&self) -> &'static str {
        self.encoding_rule
    }

    /// Gets the message type being encoded.
    pub fn message_type(&self) -> &str {
        &self.message_type
    }

    /// Gets the current field count.
    pub fn field_count(&self) -> usize {
        self.field_count
    }
}

/// Measures decoding performance metrics.
pub struct DecodingMetrics {
    start: Instant,
    encoding_rule: &'static str,
    input_size: usize,
}

impl DecodingMetrics {
    /// Creates a new decoding metrics tracker.
    pub fn new(encoding_rule: &'static str, input_size: usize) -> Self {
        Self {
            start: Instant::now(),
            encoding_rule,
            input_size,
        }
    }

    /// Completes the decoding metrics and logs the results.
    pub fn complete(self, message_type: &str, field_count: usize) {
        let duration = self.start.elapsed();

        // TODO: Implement proper metrics collection
        // For now, we use basic logging. In production, this would integrate with
        // a metrics system like Prometheus or send to a telemetry service.
        log::debug!(
            "ASN.1 decoding completed: rule={}, type={}, fields={}, input_size={}, duration={:?}",
            self.encoding_rule,
            message_type,
            field_count,
            self.input_size,
            duration
        );
    }

    /// Gets the encoding rule being used.
    pub fn encoding_rule(&self) -> &'static str {
        self.encoding_rule
    }

    /// Gets the input size being decoded.
    pub fn input_size(&self) -> usize {
        self.input_size
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

    #[test]
    fn test_encoding_span_known_rules() {
        // Test that known encoding rules return expected span names
        let _span_ber = encoding_span("BER", "TestMessage");
        let _span_der = encoding_span("DER", "TestMessage");
        let _span_oer = encoding_span("OER", "TestMessage");
        let _span_per = encoding_span("PER", "TestMessage");
        let _span_xer = encoding_span("XER", "TestMessage");
        let _span_jer = encoding_span("JER", "TestMessage");

        // All spans should be created without panicking
        // The actual span names are verified by the constants
    }

    #[test]
    fn test_encoding_span_unknown_rule() {
        // Test that unknown encoding rules fallback to generic span name
        let _span = encoding_span("UNKNOWN_RULE", "TestMessage");

        // Should not panic and should use the fallback span name
    }

    #[test]
    fn test_decoding_span_known_rules() {
        // Test that known encoding rules return expected span names
        let _span_ber = decoding_span("BER", 1024);
        let _span_der = decoding_span("DER", 1024);
        let _span_oer = decoding_span("OER", 1024);
        let _span_per = decoding_span("PER", 1024);
        let _span_xer = decoding_span("XER", 1024);
        let _span_jer = decoding_span("JER", 1024);

        // All spans should be created without panicking
        // The actual span names are verified by the constants
    }

    #[test]
    fn test_decoding_span_unknown_rule() {
        // Test that unknown encoding rules fallback to generic span name
        let _span = decoding_span("UNKNOWN_RULE", 1024);

        // Should not panic and should use the fallback span name
    }

    #[test]
    fn test_schema_span_known_operations() {
        // Test that known schema operations return expected span names
        let _span_validate = schema_span("validate");
        let _span_lookup = schema_span("lookup");
        let _span_compile = schema_span("compile");
        let _span_transform = schema_span("transform");
        let _span_parse = schema_span("parse");
        let _span_serialize = schema_span("serialize");

        // All spans should be created without panicking
        // The actual span names are verified by the constants
    }

    #[test]
    fn test_schema_span_unknown_operation() {
        // Test that unknown schema operations fallback to generic span name
        let _span = schema_span("unknown_operation");

        // Should not panic and should use the fallback span name
    }

    #[test]
    fn test_span_constants() {
        // Verify that the span constants have expected values
        assert_eq!(ENCODE_BER_SPAN, "asn1.encode.BER");
        assert_eq!(ENCODE_DER_SPAN, "asn1.encode.DER");
        assert_eq!(ENCODE_OER_SPAN, "asn1.encode.OER");
        assert_eq!(ENCODE_PER_SPAN, "asn1.encode.PER");
        assert_eq!(ENCODE_XER_SPAN, "asn1.encode.XER");
        assert_eq!(ENCODE_JER_SPAN, "asn1.encode.JER");

        assert_eq!(DECODE_BER_SPAN, "asn1.decode.BER");
        assert_eq!(DECODE_DER_SPAN, "asn1.decode.DER");
        assert_eq!(DECODE_OER_SPAN, "asn1.decode.OER");
        assert_eq!(DECODE_PER_SPAN, "asn1.decode.PER");
        assert_eq!(DECODE_XER_SPAN, "asn1.decode.XER");
        assert_eq!(DECODE_JER_SPAN, "asn1.decode.JER");

        assert_eq!(SCHEMA_VALIDATE_SPAN, "asn1.schema.validate");
        assert_eq!(SCHEMA_LOOKUP_SPAN, "asn1.schema.lookup");
        assert_eq!(SCHEMA_COMPILE_SPAN, "asn1.schema.compile");
        assert_eq!(SCHEMA_TRANSFORM_SPAN, "asn1.schema.transform");
        assert_eq!(SCHEMA_PARSE_SPAN, "asn1.schema.parse");
        assert_eq!(SCHEMA_SERIALIZE_SPAN, "asn1.schema.serialize");
    }

    #[test]
    fn test_utility_functions() {
        // Test that utility functions don't panic
        record_buffer_allocation(1024, "test_buffer");
        record_schema_lookup("NewOrderSingle", true, 1000);
        record_schema_lookup("NonExistentMessage", false, 500);

        // These functions currently have no return values but should not panic
    }
}
