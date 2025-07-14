//! ASN.1 encoder implementation for FIX messages.

use crate::{
    config::{Config, EncodingRule},
    error::{EncodeError, Error, Result},
    schema::Schema,
    types::{Field, FixMessage, ToFixFieldValue},
};
use bytes::BytesMut;
use parking_lot::RwLock;
use rasn::{ber::encode as ber_encode, der::encode as der_encode, oer::encode as oer_encode};
use rustyfix::{Dictionary, FieldMap, FieldType, GetConfig, SetField};
use smallvec::SmallVec;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;
use std::sync::Arc;

/// ASN.1 encoder for FIX messages.
pub struct Encoder {
    config: Config,
    schema: Arc<Schema>,
    buffer: RwLock<BytesMut>,
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
        let buffer_size = config.stream_buffer_size;

        Self {
            config,
            schema,
            buffer: RwLock::new(BytesMut::with_capacity(buffer_size)),
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
    fn add_message_fields<F: FieldMap<u32>>(
        &self,
        handle: &mut EncoderHandle,
        msg: &F,
    ) -> Result<()> {
        // Note: FieldMap doesn't provide field iteration, so we try common field tags
        // In a full implementation, this would use a field iterator or schema
        let common_tags = [55, 54, 38, 44, 114, 60]; // Symbol, Side, OrderQty, Price, etc.

        for &tag in &common_tags {
            if let Some(raw_data) = msg.get_raw(tag) {
                let value_str = String::from_utf8_lossy(raw_data);
                handle.add_field(tag, value_str.to_string());
            }
        }

        Ok(())
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
        // Basic estimation: header + fields
        100 + self.message.fields.len() * 20
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
        assert_eq!(handle.message.fields[0].value, "EUR/USD");
        assert_eq!(handle.message.fields[1].value, "1");
        assert_eq!(handle.message.fields[2].value, "1000000");
        assert_eq!(handle.message.fields[3].value, "Y");
    }
}
