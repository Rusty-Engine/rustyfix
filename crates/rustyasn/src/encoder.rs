//! ASN.1 encoder implementation for FIX messages.

use crate::{
    config::{Config, EncodingRule},
    error::{EncodeError, Error, Result},
    schema::Schema,
    types::{Field, FixMessage, ToFixFieldValue},
};
use bytes::BytesMut;
use rasn::{ber::encode as ber_encode, der::encode as der_encode, oer::encode as oer_encode};
use rustyfix::{Dictionary, FieldMap, FieldType, GetConfig, SetField};
use smallvec::SmallVec;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;
use std::sync::Arc;

// Size estimation constants for performance and maintainability
/// Base overhead for ASN.1 message structure including message sequence number encoding
const BASE_ASN1_OVERHEAD: usize = 20;

/// Conservative estimate for ASN.1 tag encoding size (handles up to 5-digit tag numbers)
const TAG_ENCODING_SIZE: usize = 5;

/// Size estimate for integer field values (i64/u64 can be up to 8 bytes when encoded)
const INTEGER_ESTIMATE_SIZE: usize = 8;

/// Size for boolean field values (single byte: Y or N)
const BOOLEAN_SIZE: usize = 1;

/// ASN.1 TLV (Tag-Length-Value) encoding overhead per field
const FIELD_TLV_OVERHEAD: usize = 5;

/// ASN.1 encoder for FIX messages.
pub struct Encoder {
    config: Config,
    schema: Arc<Schema>,
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

        Self { config, schema }
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
    pub fn encode_message<F: FieldMap<u32>>(&self, msg: &F) -> Result<Vec<u8>> {
        // Extract standard header fields
        let msg_type = self.get_required_string_field(msg, 35)?;
        let sender = self.get_required_string_field(msg, 49)?;
        let target = self.get_required_string_field(msg, 56)?;
        let seq_num = self.get_required_u64_field(msg, 34)?;

        let mut handle = self.start_message(&msg_type, &sender, &target, seq_num);

        // Add all other fields
        self.add_message_fields(&mut handle, msg)?;

        handle.encode()
    }

    /// Extracts a required string field from a message.
    fn get_required_string_field<F: FieldMap<u32>>(&self, msg: &F, tag: u32) -> Result<FixString> {
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
    fn get_required_u64_field<F: FieldMap<u32>>(&self, msg: &F, tag: u32) -> Result<u64> {
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
    /// This method iterates through all fields defined in the FIX dictionary
    /// and checks if they are present in the message. This ensures no data loss
    /// compared to the previous hardcoded approach.
    fn add_message_fields<F: FieldMap<u32>>(
        &self,
        handle: &mut EncoderHandle,
        msg: &F,
    ) -> Result<()> {
        // Get all field definitions from the schema's dictionary
        let dictionary = self.schema.dictionary();
        let all_fields = dictionary.fields();

        // Process each field defined in the dictionary
        for field in all_fields {
            let tag = field.tag().get();

            // Skip standard header fields that are already handled by start_message
            if self.is_standard_header_field(tag) {
                continue;
            }

            // Check if this field is present in the message
            if let Some(raw_data) = msg.get_raw(tag) {
                let value_str = String::from_utf8_lossy(raw_data);
                handle.add_field(tag, value_str.to_string());
            }
        }

        Ok(())
    }

    /// Checks if a field tag is a standard FIX header field.
    /// These fields are handled separately by `start_message`.
    fn is_standard_header_field(&self, tag: u32) -> bool {
        matches!(
            tag,
            8 |  // BeginString
            9 |  // BodyLength  
            10 | // CheckSum
            34 | // MsgSeqNum
            35 | // MsgType
            49 | // SenderCompID
            52 | // SendingTime
            56 // TargetCompID
        )
    }

    /// Encodes using the specified encoding rule.
    fn encode_with_rule(&self, message: &FixMessage, rule: EncodingRule) -> Result<Vec<u8>> {
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
    fn set_with<'b, V>(&'b mut self, field: u32, value: V, _settings: V::SerializeSettings)
    where
        V: FieldType<'b>,
    {
        // Serialize the value to bytes using a temporary buffer that implements Buffer
        let mut temp_buffer: SmallVec<[u8; 64]> = SmallVec::new();
        value.serialize_with(&mut temp_buffer, _settings);

        // Convert to string for FIX compatibility
        let value_str = String::from_utf8_lossy(&temp_buffer);

        // Add to the message using the existing add_field method
        self.add_field(field, value_str.to_string());
    }
}

impl EncoderHandle<'_> {
    /// Adds a field to the message.
    pub fn add_field(&mut self, tag: u32, value: impl ToFixFieldValue) -> &mut Self {
        self.message.fields.push(Field {
            tag,
            value: value.to_fix_field_value(),
        });
        self
    }

    /// Adds a string field to the message.
    pub fn add_string(&mut self, tag: u32, value: impl Into<String>) -> &mut Self {
        self.add_field(tag, value.into())
    }

    /// Adds an integer field to the message.
    pub fn add_int(&mut self, tag: u32, value: i64) -> &mut Self {
        self.add_field(tag, value)
    }

    /// Adds an unsigned integer field to the message.
    pub fn add_uint(&mut self, tag: u32, value: u64) -> &mut Self {
        self.add_field(tag, value)
    }

    /// Adds a boolean field to the message.
    pub fn add_bool(&mut self, tag: u32, value: bool) -> &mut Self {
        self.add_field(tag, value)
    }

    /// Encodes the message and returns the encoded bytes.
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
        self.encoder.encode_with_rule(&self.message, encoding_rule)
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
                    crate::types::FixFieldValue::String(s) => s.len(),
                    crate::types::FixFieldValue::Decimal(s) => s.len(),
                    crate::types::FixFieldValue::Character(s) => s.len(),
                    crate::types::FixFieldValue::UtcTimestamp(s) => s.len(),
                    crate::types::FixFieldValue::UtcDate(s) => s.len(),
                    crate::types::FixFieldValue::UtcTime(s) => s.len(),
                    crate::types::FixFieldValue::Raw(s) => s.len(),
                    crate::types::FixFieldValue::Integer(_) => INTEGER_ESTIMATE_SIZE, // i64 estimate
                    crate::types::FixFieldValue::UnsignedInteger(_) => INTEGER_ESTIMATE_SIZE, // u64 estimate
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
            .add_uint(38, 1000000)
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
            crate::types::FixFieldValue::UnsignedInteger(1000000)
        );
        assert_eq!(
            handle.message.fields[3].value,
            crate::types::FixFieldValue::Boolean(true)
        );
    }
}
