//! ASN.1 encoder implementation for FIX messages.

use crate::{
    config::{Config, EncodingRule},
    error::{EncodeError, Error, Result},
    schema::Schema,
    traits::{FieldMap, FieldType, GetConfig, SetField},
    types::{Field, FixMessage, ToFixFieldValue},
};
use bytes::BytesMut;
use rasn::{ber::encode as ber_encode, der::encode as der_encode, oer::encode as oer_encode};
use rustc_hash::FxHashSet;
use rustyfix_dictionary::Dictionary;
use smallvec::SmallVec;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;
use std::sync::Arc;

// FIX standard header field tags
/// FIX field tag for `BeginString` (8).
pub const BEGIN_STRING_TAG: u32 = 8;
/// FIX field tag for `BodyLength` (9).
pub const BODY_LENGTH_TAG: u32 = 9;
/// FIX field tag for `CheckSum` (10).
pub const CHECK_SUM_TAG: u32 = 10;
/// FIX field tag for `MsgSeqNum` (34).
pub const MSG_SEQ_NUM_TAG: u32 = 34;
/// FIX field tag for `MsgType` (35).
pub const MSG_TYPE_TAG: u32 = 35;
/// FIX field tag for `SenderCompID` (49).
pub const SENDER_COMP_ID_TAG: u32 = 49;
/// FIX field tag for `SendingTime` (52).
pub const SENDING_TIME_TAG: u32 = 52;
/// FIX field tag for `TargetCompID` (56).
pub const TARGET_COMP_ID_TAG: u32 = 56;

// Size estimation constants for performance and maintainability
/// Base overhead for ASN.1 message structure.
///
/// This value represents the fixed overhead in bytes for encoding an ASN.1 message.
/// It includes:
/// - 2 bytes for the SEQUENCE tag of the message structure
/// - 2 bytes for the length encoding of the message sequence  
/// - 16 bytes for the message sequence number encoding (assuming a 128-bit integer)
///
/// These components add up to a total of 20 bytes of base overhead.
pub const BASE_ASN1_OVERHEAD: usize = 20;

/// Conservative estimate for ASN.1 tag encoding size (handles up to 5-digit tag numbers)
pub const TAG_ENCODING_SIZE: usize = 5;

/// Size estimate for integer field values (i64/u64 can be up to 8 bytes when encoded)
pub const INTEGER_ESTIMATE_SIZE: usize = 8;

/// Size for boolean field values (single byte: Y or N)
pub const BOOLEAN_SIZE: usize = 1;

/// ASN.1 TLV (Tag-Length-Value) encoding overhead per field
pub const FIELD_TLV_OVERHEAD: usize = 5;

/// Encoder for ASN.1 encoded FIX messages.
pub struct Encoder {
    config: Config,
    schema: Arc<Schema>,
    /// Common fields that appear in many message types (configurable, ordered by frequency)
    /// This significantly improves performance for typical messages
    common_field_tags: SmallVec<[u32; 32]>,
}

/// Handle for encoding a single message.
pub struct EncoderHandle<'a> {
    encoder: &'a Encoder,
    message: FixMessage,
}

impl GetConfig for Encoder {
    type Config = Config;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.config
    }
}

impl Encoder {
    /// Creates a new encoder with the given configuration and dictionary.
    pub fn new(config: Config, dictionary: Arc<Dictionary>) -> Self {
        let schema = Arc::new(Schema::new(dictionary));

        let mut encoder = Self {
            config,
            schema,
            common_field_tags: SmallVec::new(),
        };

        // Initialize common field tags with default high-frequency fields
        encoder.initialize_common_field_tags();

        encoder
    }

    /// Initializes common field tags with default high-frequency fields.
    /// These can be updated based on actual usage statistics in production.
    fn initialize_common_field_tags(&mut self) {
        // Default common fields ordered by typical frequency in trading systems
        let default_common_tags = &[
            // Market data fields
            55, // Symbol
            54, // Side
            38, // OrderQty
            44, // Price
            40, // OrdType
            59, // TimeInForce
            // Order/execution fields
            11,  // ClOrdID
            37,  // OrderID
            17,  // ExecID
            150, // ExecType
            39,  // OrdStatus
            // Additional common fields
            1,   // Account
            6,   // AvgPx
            14,  // CumQty
            32,  // LastQty
            31,  // LastPx
            151, // LeavesQty
            60,  // TransactTime
            109, // ClientID
            // Reference fields
            58,  // Text
            354, // EncodedTextLen
            355, // EncodedText
        ];

        self.common_field_tags
            .extend_from_slice(default_common_tags);
    }

    /// Updates common field tags based on usage statistics.
    /// This method allows runtime optimization based on actual message patterns.
    pub fn update_common_field_tags(&mut self, field_usage_stats: &[(u32, usize)]) {
        self.common_field_tags.clear();

        // Sort by usage frequency (descending) and take the most common ones
        let mut sorted_stats = field_usage_stats.to_vec();
        sorted_stats.sort_by(|a, b| b.1.cmp(&a.1));

        // Take up to 32 most common fields
        for (tag, _count) in sorted_stats.iter().take(32) {
            self.common_field_tags.push(*tag);
        }
    }

    /// Starts encoding a new message.
    pub fn start_message<'a>(
        &'a self,
        msg_type: &str,
        sender_comp_id: &str,
        target_comp_id: &str,
        msg_seq_num: u64,
    ) -> EncoderHandle<'a> {
        let message = FixMessage {
            msg_type: msg_type.to_string(),
            sender_comp_id: sender_comp_id.to_string(),
            target_comp_id: target_comp_id.to_string(),
            msg_seq_num,
            fields: Vec::new(),
        };

        EncoderHandle {
            encoder: self,
            message,
        }
    }

    /// Encodes a complete FIX message from a field map.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required header fields (`MsgType`, `SenderCompID`, `TargetCompID`, `MsgSeqNum`) are missing
    /// - Field values contain invalid UTF-8 sequences
    /// - Field values cannot be parsed as expected types (e.g., `MsgSeqNum` as u64)
    /// - The estimated message size exceeds configured limits
    /// - ASN.1 encoding fails due to internal errors
    pub fn encode_message<F: FieldMap<u32>>(&self, msg: &F) -> Result<Vec<u8>> {
        // Extract standard header fields
        let msg_type = Self::get_required_string_field(msg, MSG_TYPE_TAG)?;
        let sender = Self::get_required_string_field(msg, SENDER_COMP_ID_TAG)?;
        let target = Self::get_required_string_field(msg, TARGET_COMP_ID_TAG)?;
        let seq_num = Self::get_required_u64_field(msg, MSG_SEQ_NUM_TAG)?;

        let mut handle = self.start_message(&msg_type, &sender, &target, seq_num);

        // Add all other fields
        self.add_message_fields(&mut handle, msg);

        handle.encode()
    }

    /// Extracts a required string field from a message.
    fn get_required_string_field<F: FieldMap<u32>>(msg: &F, tag: u32) -> Result<FixString> {
        msg.get_raw(tag)
            .ok_or_else(|| {
                Error::Encode(EncodeError::RequiredFieldMissing {
                    tag,
                    name: format!("Tag {tag}").into(),
                })
            })
            .and_then(|bytes| {
                std::str::from_utf8(bytes)
                    .map(std::convert::Into::into)
                    .map_err(|_| {
                        Error::Encode(EncodeError::InvalidFieldValue {
                            tag,
                            reason: "Invalid UTF-8 in field value".into(),
                        })
                    })
            })
    }

    /// Extracts a required u64 field from a message.
    fn get_required_u64_field<F: FieldMap<u32>>(msg: &F, tag: u32) -> Result<u64> {
        let bytes = msg.get_raw(tag).ok_or_else(|| {
            Error::Encode(EncodeError::RequiredFieldMissing {
                tag,
                name: format!("Tag {tag}").into(),
            })
        })?;

        std::str::from_utf8(bytes)
            .map_err(|_| {
                Error::Encode(EncodeError::InvalidFieldValue {
                    tag,
                    reason: "Invalid UTF-8 in field value".into(),
                })
            })?
            .parse::<u64>()
            .map_err(|_| {
                Error::Encode(EncodeError::InvalidFieldValue {
                    tag,
                    reason: "Invalid u64 value".into(),
                })
            })
    }

    /// Adds all non-header fields to the message.
    ///
    /// This method uses an optimized approach that prioritizes common fields
    /// and intelligently iterates through dictionary fields.
    fn add_message_fields<F: FieldMap<u32>>(&self, handle: &mut EncoderHandle, msg: &F) {
        // Get the dictionary for field validation
        let dictionary = self.schema.dictionary();

        // Track which tags we've already processed
        let mut processed_tags = FxHashSet::default();

        // First pass: Check common fields (O(1) for each)
        for &tag in &self.common_field_tags {
            if Self::is_standard_header_field(tag) {
                continue;
            }

            if let Some(raw_data) = msg.get_raw(tag) {
                let value_str = String::from_utf8_lossy(raw_data);
                handle.add_field(tag, &value_str.to_string());
                processed_tags.insert(tag);
            }
        }

        // Second pass: Check message-type specific fields if available
        if let Some(msg_type_def) = dictionary
            .messages()
            .iter()
            .find(|m| m.msg_type() == handle.message.msg_type)
        {
            // Get fields specific to this message type by iterating through its layout
            for layout_item in msg_type_def.layout() {
                if let rustyfix_dictionary::LayoutItemKind::Field(field) = layout_item.kind() {
                    let tag = field.tag().get();

                    if processed_tags.contains(&tag) || Self::is_standard_header_field(tag) {
                        continue;
                    }

                    if let Some(raw_data) = msg.get_raw(tag) {
                        let value_str = String::from_utf8_lossy(raw_data);
                        handle.add_field(tag, &value_str.to_string());
                        processed_tags.insert(tag);
                    }
                }
                // We could also handle groups and components here if needed
            }
        }

        // Third pass: For completeness, check remaining dictionary fields
        // This ensures we don't miss any fields that might be present
        // but weren't in our common fields or message-specific fields
        for field in dictionary.fields() {
            let tag = field.tag().get();

            // Skip if already processed or is a header field
            if processed_tags.contains(&tag) || Self::is_standard_header_field(tag) {
                continue;
            }

            if let Some(raw_data) = msg.get_raw(tag) {
                let value_str = String::from_utf8_lossy(raw_data);
                handle.add_field(tag, &value_str.to_string());
            }
        }
    }

    /// Checks if a field tag is a standard FIX header field.
    /// These fields are handled separately by `start_message`.
    const fn is_standard_header_field(tag: u32) -> bool {
        matches!(
            tag,
            BEGIN_STRING_TAG |      // BeginString
            BODY_LENGTH_TAG |       // BodyLength  
            CHECK_SUM_TAG |         // CheckSum
            MSG_SEQ_NUM_TAG |       // MsgSeqNum
            MSG_TYPE_TAG |          // MsgType
            SENDER_COMP_ID_TAG |    // SenderCompID
            SENDING_TIME_TAG |      // SendingTime
            TARGET_COMP_ID_TAG // TargetCompID
        )
    }

    /// Encodes using the specified encoding rule.
    fn encode_with_rule(message: &FixMessage, rule: EncodingRule) -> Result<Vec<u8>> {
        match rule {
            EncodingRule::BER => {
                ber_encode(message).map_err(|e| Error::Encode(EncodeError::Internal(e.to_string())))
            }

            EncodingRule::DER => {
                der_encode(message).map_err(|e| Error::Encode(EncodeError::Internal(e.to_string())))
            }

            EncodingRule::OER => {
                oer_encode(message).map_err(|e| Error::Encode(EncodeError::Internal(e.to_string())))
            }
        }
    }
}

impl SetField<u32> for EncoderHandle<'_> {
    fn set_with<'b, V>(&'b mut self, field: u32, value: V, settings: V::SerializeSettings)
    where
        V: FieldType<'b>,
    {
        // Serialize the value to bytes using a temporary buffer that implements Buffer
        let mut temp_buffer: SmallVec<[u8; crate::FIELD_BUFFER_SIZE]> = SmallVec::new();
        value.serialize_with(&mut temp_buffer, settings);

        // Convert to string for FIX compatibility
        let value_str = String::from_utf8_lossy(&temp_buffer);

        // Add to the message using the existing add_field method
        self.add_field(field, &value_str.to_string());
    }
}

impl EncoderHandle<'_> {
    /// Adds a field to the message.
    pub fn add_field(&mut self, tag: u32, value: &impl ToFixFieldValue) -> &mut Self {
        self.message.fields.push(Field {
            tag,
            value: value.to_fix_field_value(),
        });
        self
    }

    /// Adds a string field to the message.
    pub fn add_string(&mut self, tag: u32, value: impl Into<String>) -> &mut Self {
        let val = value.into();
        self.add_field(tag, &val)
    }

    /// Adds an integer field to the message.
    pub fn add_int(&mut self, tag: u32, value: i64) -> &mut Self {
        self.add_field(tag, &value)
    }

    /// Adds an unsigned integer field to the message.
    pub fn add_uint(&mut self, tag: u32, value: u64) -> &mut Self {
        self.add_field(tag, &value)
    }

    /// Adds a boolean field to the message.
    pub fn add_bool(&mut self, tag: u32, value: bool) -> &mut Self {
        self.add_field(tag, &value)
    }

    /// Encodes the message and returns the encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The estimated message size exceeds the configured maximum message size
    /// - ASN.1 encoding fails due to internal encoding errors
    pub fn encode(self) -> Result<Vec<u8>> {
        // Check message size before encoding
        let estimated_size = self.estimate_size();
        if estimated_size > self.encoder.config.max_message_size {
            return Err(Error::Encode(EncodeError::MessageTooLarge {
                size: estimated_size,
                max_size: self.encoder.config.max_message_size,
            }));
        }

        // Get encoding rule (check for message-specific override)
        let encoding_rule = self
            .encoder
            .config
            .get_message_options(&self.message.msg_type)
            .and_then(|opts| opts.encoding_rule)
            .unwrap_or(self.encoder.config.encoding_rule);

        // Encode the message
        Encoder::encode_with_rule(&self.message, encoding_rule)
    }

    /// Estimates the encoded size of the message.
    fn estimate_size(&self) -> usize {
        // More accurate estimation based on actual field content
        let base_size = self.message.sender_comp_id.len()
            + self.message.target_comp_id.len()
            + self.message.msg_type.len()
            + BASE_ASN1_OVERHEAD; // for msg_seq_num and ASN.1 overhead

        let fields_size = self
            .message
            .fields
            .iter()
            .map(|field| {
                // Each field has tag number + value + ASN.1 encoding overhead
                let tag_size = TAG_ENCODING_SIZE; // Conservative estimate for tag encoding
                let value_size = match &field.value {
                    crate::types::FixFieldValue::String(s)
                    | crate::types::FixFieldValue::Decimal(s)
                    | crate::types::FixFieldValue::Character(s)
                    | crate::types::FixFieldValue::UtcTimestamp(s)
                    | crate::types::FixFieldValue::UtcDate(s)
                    | crate::types::FixFieldValue::UtcTime(s)
                    | crate::types::FixFieldValue::Raw(s) => s.len(),
                    crate::types::FixFieldValue::Integer(_)
                    | crate::types::FixFieldValue::UnsignedInteger(_) => INTEGER_ESTIMATE_SIZE, // i64/u64 estimate
                    crate::types::FixFieldValue::Boolean(_) => BOOLEAN_SIZE,
                    crate::types::FixFieldValue::Data(data) => data.len(),
                };
                tag_size + value_size + FIELD_TLV_OVERHEAD // ASN.1 TLV overhead per field
            })
            .sum::<usize>();

        base_size + fields_size
    }
}

/// Streaming encoder for continuous message encoding.
pub struct EncoderStreaming {
    encoder: Encoder,
    output_buffer: BytesMut,
}

impl EncoderStreaming {
    /// Creates a new streaming encoder.
    pub fn new(config: Config, dictionary: Arc<Dictionary>) -> Self {
        let buffer_size = config.stream_buffer_size;
        Self {
            encoder: Encoder::new(config, dictionary),
            output_buffer: BytesMut::with_capacity(buffer_size),
        }
    }

    /// Encodes a message and appends to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying encoder fails to encode the message.
    /// See [`Encoder::encode_message`] for detailed error conditions.
    pub fn encode_message<F: FieldMap<u32>>(&mut self, msg: &F) -> Result<()> {
        let encoded = self.encoder.encode_message(msg)?;
        self.output_buffer.extend_from_slice(&encoded);
        Ok(())
    }

    /// Takes the accumulated output buffer.
    pub fn take_output(&mut self) -> BytesMut {
        self.output_buffer.split()
    }

    /// Returns a reference to the output buffer.
    pub fn output(&self) -> &[u8] {
        &self.output_buffer
    }

    /// Clears the output buffer.
    pub fn clear(&mut self) {
        self.output_buffer.clear();
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_creation() {
        let config = Config::default();
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let encoder = Encoder::new(config, dict);

        // Test message creation
        let handle = encoder.start_message("D", "SENDER", "TARGET", 1);

        assert_eq!(handle.message.msg_type, "D");
        assert_eq!(handle.message.sender_comp_id, "SENDER");
    }

    #[test]
    fn test_field_addition() {
        let config = Config::default();
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let encoder = Encoder::new(config, dict);

        let mut handle = encoder.start_message("D", "SENDER", "TARGET", 1);

        handle
            .add_string(55, "EUR/USD")
            .add_int(54, 1)
            .add_uint(38, 1_000_000)
            .add_bool(114, true);

        assert_eq!(handle.message.fields.len(), 4);
        assert_eq!(
            handle.message.fields[0].value,
            crate::types::FixFieldValue::String("EUR/USD".to_string())
        );
        assert_eq!(
            handle.message.fields[1].value,
            crate::types::FixFieldValue::Integer(1)
        );
        assert_eq!(
            handle.message.fields[2].value,
            crate::types::FixFieldValue::UnsignedInteger(1_000_000)
        );
        assert_eq!(
            handle.message.fields[3].value,
            crate::types::FixFieldValue::Boolean(true)
        );
    }
}
