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

/// Creates a new span for encoding operations.
///
/// This function creates a distributed tracing span to track ASN.1 encoding operations.
/// The span helps monitor encoding performance and debug issues in high-throughput
/// financial messaging systems.
///
/// # Arguments
///
/// * `encoding_rule` - The ASN.1 encoding rule being used (e.g., "BER", "DER", "OER")
/// * `_message_type` - The FIX message type being encoded (currently unused but reserved for future metrics)
///
/// # Returns
///
/// A [`Span`] that tracks the encoding operation. The span is automatically entered
/// and will be exited when dropped.
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
/// heap allocation, with format!() fallback only for rare unknown rules.
#[inline]
pub fn encoding_span(encoding_rule: &str, _message_type: &str) -> Span {
    let span_name = match encoding_rule {
        "BER" => ENCODE_BER_SPAN,
        "DER" => ENCODE_DER_SPAN,
        "OER" => ENCODE_OER_SPAN,
        "PER" => ENCODE_PER_SPAN,
        "XER" => ENCODE_XER_SPAN,
        "JER" => ENCODE_JER_SPAN,
        // Fall back to format!() for unknown encoding rules (rare case)
        _ => return Span::enter_with_local_parent(format!("asn1.encode.{encoding_rule}")),
    };
    Span::enter_with_local_parent(span_name)
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
/// heap allocation, with format!() fallback only for rare unknown rules.
#[inline]
pub fn decoding_span(encoding_rule: &str, _data_size: usize) -> Span {
    let span_name = match encoding_rule {
        "BER" => DECODE_BER_SPAN,
        "DER" => DECODE_DER_SPAN,
        "OER" => DECODE_OER_SPAN,
        "PER" => DECODE_PER_SPAN,
        "XER" => DECODE_XER_SPAN,
        "JER" => DECODE_JER_SPAN,
        // Fall back to format!() for unknown encoding rules (rare case)
        _ => return Span::enter_with_local_parent(format!("asn1.decode.{encoding_rule}")),
    };
    Span::enter_with_local_parent(span_name)
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
/// static strings to avoid heap allocation, with format!() fallback only for rare unknown operations.
#[inline]
pub fn schema_span(operation: &str) -> Span {
    let span_name = match operation {
        "validate" => SCHEMA_VALIDATE_SPAN,
        "lookup" => SCHEMA_LOOKUP_SPAN,
        "compile" => SCHEMA_COMPILE_SPAN,
        "transform" => SCHEMA_TRANSFORM_SPAN,
        "parse" => SCHEMA_PARSE_SPAN,
        "serialize" => SCHEMA_SERIALIZE_SPAN,
        // Fall back to format!() for unknown operations (rare case)
        _ => return Span::enter_with_local_parent(format!("asn1.schema.{operation}")),
    };
    Span::enter_with_local_parent(span_name)
}

/// Measures encoding performance metrics.
pub struct EncodingMetrics {
    start: Instant,
    #[allow(dead_code)]
    encoding_rule: &'static str,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    encoding_rule: &'static str,
    #[allow(dead_code)]
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
