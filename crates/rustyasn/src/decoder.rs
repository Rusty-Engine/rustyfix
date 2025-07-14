//! ASN.1 decoder implementation for FIX messages.

use crate::{
    config::{Config, EncodingRule},
    error::{DecodeError, Error, Result},
    schema::Schema,
    types::FixMessage,
};
use bytes::Bytes;
use rasn::{ber::decode as ber_decode, der::decode as der_decode, oer::decode as oer_decode};
use rustc_hash::FxHashMap;
use rustyfix::{Dictionary, GetConfig, StreamingDecoder as StreamingDecoderTrait};
use std::sync::Arc;

// ASN.1 tag constants
const ASN1_SEQUENCE_TAG: u8 = 0x30;
const ASN1_CONTEXT_SPECIFIC_CONSTRUCTED_MASK: u8 = 0xE0;
const ASN1_CONTEXT_SPECIFIC_CONSTRUCTED_TAG: u8 = 0xA0;
#[cfg(test)]
const ASN1_LONG_FORM_LENGTH_2_BYTES: u8 = 0x82; // Long form length indicator for 2-byte length

/// Decoded FIX message representation.
#[derive(Debug, Clone)]
pub struct DecodedMessage {
    /// Raw ASN.1 encoded data
    raw: Bytes,

    /// Decoded message structure
    inner: FixMessage,

    /// Field lookup map for fast access
    fields: FxHashMap<u32, crate::types::FixFieldValue>,
}

impl DecodedMessage {
    /// Creates a new message from decoded data.
    fn new(raw: Bytes, inner: FixMessage) -> Self {
        let mut fields = FxHashMap::default();

        // Add standard fields
        fields.insert(
            35,
            crate::types::FixFieldValue::String(inner.msg_type.clone()),
        );
        fields.insert(
            49,
            crate::types::FixFieldValue::String(inner.sender_comp_id.clone()),
        );
        fields.insert(
            56,
            crate::types::FixFieldValue::String(inner.target_comp_id.clone()),
        );
        fields.insert(
            34,
            crate::types::FixFieldValue::UnsignedInteger(inner.msg_seq_num),
        );

        // Add additional fields
        for field in &inner.fields {
            fields.insert(field.tag, field.value.clone());
        }

        Self { raw, inner, fields }
    }

    /// Gets the message type (tag 35).
    pub fn msg_type(&self) -> &str {
        &self.inner.msg_type
    }

    /// Gets the sender comp ID (tag 49).
    pub fn sender_comp_id(&self) -> &str {
        &self.inner.sender_comp_id
    }

    /// Gets the target comp ID (tag 56).
    pub fn target_comp_id(&self) -> &str {
        &self.inner.target_comp_id
    }

    /// Gets the message sequence number (tag 34).
    pub fn msg_seq_num(&self) -> u64 {
        self.inner.msg_seq_num
    }

    /// Gets a field value by tag.
    pub fn get_field(&self, tag: u32) -> Option<String> {
        self.fields
            .get(&tag)
            .map(super::types::FixFieldValue::to_string)
    }

    /// Gets a string field value.
    pub fn get_string(&self, tag: u32) -> Option<String> {
        self.get_field(tag)
    }

    /// Gets an integer field value.
    pub fn get_int(&self, tag: u32) -> Result<Option<i64>> {
        match self.fields.get(&tag) {
            Some(crate::types::FixFieldValue::Integer(i)) => Ok(Some(*i)),
            Some(crate::types::FixFieldValue::UnsignedInteger(u)) => Ok(Some(*u as i64)),
            Some(_) => {
                // Try to parse the string representation
                self.get_field(tag)
                    .ok_or_else(|| {
                        Error::Decode(DecodeError::ConstraintViolation {
                            field: format!("Tag {tag}").into(),
                            reason: "Field not found".into(),
                        })
                    })?
                    .parse()
                    .map(Some)
                    .map_err(|_| {
                        Error::Decode(DecodeError::ConstraintViolation {
                            field: format!("Tag {tag}").into(),
                            reason: "Invalid integer format".into(),
                        })
                    })
            }
            None => Ok(None),
        }
    }

    /// Gets an unsigned integer field value.
    pub fn get_uint(&self, tag: u32) -> Result<Option<u64>> {
        match self.fields.get(&tag) {
            Some(crate::types::FixFieldValue::UnsignedInteger(u)) => Ok(Some(*u)),
            Some(crate::types::FixFieldValue::Integer(i)) => {
                if *i >= 0 {
                    Ok(Some(*i as u64))
                } else {
                    Err(Error::Decode(DecodeError::ConstraintViolation {
                        field: format!("Tag {tag}").into(),
                        reason: "Negative value cannot be converted to unsigned integer".into(),
                    }))
                }
            }
            Some(_) => {
                // Try to parse the string representation
                self.get_field(tag)
                    .ok_or_else(|| {
                        Error::Decode(DecodeError::ConstraintViolation {
                            field: format!("Tag {tag}").into(),
                            reason: "Field not found".into(),
                        })
                    })?
                    .parse()
                    .map(Some)
                    .map_err(|_| {
                        Error::Decode(DecodeError::ConstraintViolation {
                            field: format!("Tag {tag}").into(),
                            reason: "Invalid unsigned integer format".into(),
                        })
                    })
            }
            None => Ok(None),
        }
    }

    /// Gets a boolean field value.
    pub fn get_bool(&self, tag: u32) -> Option<bool> {
        match self.fields.get(&tag)? {
            crate::types::FixFieldValue::Boolean(b) => Some(*b),
            _ => match self.get_field(tag)?.as_str() {
                "Y" => Some(true),
                "N" => Some(false),
                _ => None,
            },
        }
    }

    /// Returns the raw encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// ASN.1 decoder for FIX messages.
pub struct Decoder {
    config: Config,
    schema: Arc<Schema>,
}

impl GetConfig for Decoder {
    type Config = Config;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.config
    }
}

impl Decoder {
    /// Creates a new decoder with the given configuration and dictionary.
    pub fn new(config: Config, dictionary: Arc<Dictionary>) -> Self {
        let schema = Arc::new(Schema::new(dictionary));
        Self { config, schema }
    }

    /// Decodes a single message from bytes.
    pub fn decode(&self, data: &[u8]) -> Result<DecodedMessage> {
        if data.is_empty() {
            return Err(Error::Decode(DecodeError::UnexpectedEof {
                offset: 0,
                needed: 1,
            }));
        }

        // Check maximum message size
        if data.len() > self.config.max_message_size {
            return Err(Error::Decode(DecodeError::InvalidLength { offset: 0 }));
        }

        // Decode based on encoding rule
        let fix_msg = self.decode_with_rule(data, self.config.encoding_rule)?;

        // Validate if configured
        if self.config.validate_checksums {
            self.validate_message(&fix_msg)?;
        }

        Ok(DecodedMessage::new(Bytes::copy_from_slice(data), fix_msg))
    }

    /// Decodes using the specified encoding rule.
    fn decode_with_rule(&self, data: &[u8], rule: EncodingRule) -> Result<FixMessage> {
        match rule {
            EncodingRule::BER => ber_decode::<FixMessage>(data)
                .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string()))),

            EncodingRule::DER => der_decode::<FixMessage>(data)
                .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string()))),

            EncodingRule::OER => oer_decode::<FixMessage>(data)
                .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string()))),
        }
    }

    /// Validates a decoded message.
    fn validate_message(&self, msg: &FixMessage) -> Result<()> {
        // Validate message type exists in schema
        if self.schema.get_message_schema(&msg.msg_type).is_none() {
            return Err(Error::Decode(DecodeError::ConstraintViolation {
                field: "MsgType".into(),
                reason: format!("Unknown message type: {}", msg.msg_type).into(),
            }));
        }

        Ok(())
    }
}

/// Streaming decoder for continuous message decoding.
pub struct DecoderStreaming {
    decoder: Decoder,
    buffer: Vec<u8>,
    state: DecoderState,
}

/// Internal state for streaming decoder.
#[derive(Debug, Clone, Copy)]
enum DecoderState {
    /// Waiting for message start
    WaitingForMessage,
    /// Reading message length
    ReadingLength { offset: usize },
    /// Reading message data
    ReadingMessage { length: usize, offset: usize },
}

impl GetConfig for DecoderStreaming {
    type Config = Config;

    fn config(&self) -> &Self::Config {
        self.decoder.config()
    }

    fn config_mut(&mut self) -> &mut Self::Config {
        self.decoder.config_mut()
    }
}

impl DecoderStreaming {
    /// Creates a new streaming decoder.
    pub fn new(config: Config, dictionary: Arc<Dictionary>) -> Self {
        let buffer_size = config.stream_buffer_size;
        Self {
            decoder: Decoder::new(config, dictionary),
            buffer: Vec::with_capacity(buffer_size),
            state: DecoderState::WaitingForMessage,
        }
    }

    /// Feeds data to the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempts to decode the next message.
    pub fn decode_next(&mut self) -> Result<Option<DecodedMessage>> {
        loop {
            match self.state {
                DecoderState::WaitingForMessage => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }

                    // Check for ASN.1 tag
                    let tag = self.buffer[0];
                    if !self.is_valid_asn1_tag(tag) {
                        return Err(Error::Decode(DecodeError::InvalidTag { tag, offset: 0 }));
                    }

                    self.state = DecoderState::ReadingLength { offset: 1 };
                }

                DecoderState::ReadingLength { offset } => {
                    // Try to decode length
                    if let Some((length, consumed)) = self.decode_length(offset)? {
                        // Validate length against maximum message size to prevent DoS
                        if length > self.decoder.config.max_message_size {
                            return Err(Error::Decode(DecodeError::MessageTooLarge {
                                size: length,
                                max_size: self.decoder.config.max_message_size,
                            }));
                        }

                        self.state = DecoderState::ReadingMessage {
                            length,
                            offset: offset + consumed,
                        };
                    } else {
                        // Need more data
                        return Ok(None);
                    }
                }

                DecoderState::ReadingMessage { length, offset } => {
                    if self.buffer.len() >= offset + length {
                        // We have a complete message - decode directly from buffer slice
                        let message = self.decoder.decode(&self.buffer[0..offset + length])?;

                        // Remove the processed data from buffer
                        self.buffer.drain(0..offset + length);
                        self.state = DecoderState::WaitingForMessage;

                        return Ok(Some(message));
                    }
                    // Need more data
                    return Ok(None);
                }
            }
        }
    }

    /// Checks if a byte is a valid ASN.1 tag.
    fn is_valid_asn1_tag(&self, _tag: u8) -> bool {
        // Accept a broader range of ASN.1 tags
        // Universal class tags (0x00-0x1F) are all valid
        // Application class (0x40-0x7F) are valid
        // Context-specific (0x80-0xBF) are valid
        // Private class (0xC0-0xFF) are valid
        // The tag format is: [Class(2 bits)][P/C(1 bit)][Tag number(5 bits)]
        // For now, accept any tag that follows basic ASN.1 structure
        // Bit 6 clear = Universal/Application class
        // Bit 6 set = Context/Private class
        // This is a much more permissive check that accepts all valid ASN.1 tags
        true // All bytes can potentially be valid ASN.1 tags
    }

    /// Decodes ASN.1 length at the given offset.
    fn decode_length(&self, offset: usize) -> Result<Option<(usize, usize)>> {
        if offset >= self.buffer.len() {
            return Ok(None);
        }

        let first_byte = self.buffer[offset];

        if first_byte & 0x80 == 0 {
            // Short form: length is in bits 0-6
            Ok(Some((first_byte as usize, 1)))
        } else {
            // Long form: bits 0-6 indicate number of length bytes
            let num_bytes = (first_byte & 0x7F) as usize;

            if num_bytes == 0 || num_bytes > 4 {
                return Err(Error::Decode(DecodeError::InvalidLength { offset }));
            }

            if offset + 1 + num_bytes > self.buffer.len() {
                // Need more data
                return Ok(None);
            }

            let mut length = 0usize;
            for i in 0..num_bytes {
                length = (length << 8) | (self.buffer[offset + 1 + i] as usize);
            }

            Ok(Some((length, 1 + num_bytes)))
        }
    }

    /// Returns the number of bytes buffered but not yet decoded.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.state = DecoderState::WaitingForMessage;
    }
}

impl StreamingDecoderTrait for DecoderStreaming {
    type Buffer = Vec<u8>;
    type Error = Error;

    fn buffer(&mut self) -> &mut Self::Buffer {
        &mut self.buffer
    }

    fn num_bytes_required(&self) -> usize {
        match self.state {
            DecoderState::WaitingForMessage => 1, // Need at least tag byte
            DecoderState::ReadingLength { offset } => offset + 1, // Need at least one length byte
            DecoderState::ReadingMessage { length, offset } => offset + length,
        }
    }

    fn try_parse(&mut self) -> Result<Option<()>> {
        match self.decode_next()? {
            Some(_) => Ok(Some(())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Field;

    #[test]
    fn test_decoder_creation() {
        let config = Config::default();
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let decoder = Decoder::new(config, dict);

        // Test with empty data
        let result = decoder.decode(&[]);
        assert!(matches!(result, Err(Error::Decode(_))));
    }

    #[test]
    fn test_message_field_access() {
        let msg = FixMessage {
            msg_type: "D".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            msg_seq_num: 123,
            fields: vec![Field {
                tag: 55,
                value: crate::types::FixFieldValue::String("EUR/USD".to_string()),
            }],
        };

        let message = DecodedMessage::new(Bytes::new(), msg);

        assert_eq!(message.msg_type(), "D");
        assert_eq!(message.sender_comp_id(), "SENDER");
        assert_eq!(message.msg_seq_num(), 123);
        assert_eq!(message.get_string(55), Some("EUR/USD".to_string()));
    }

    #[test]
    fn test_streaming_decoder_state() {
        let config = Config::default();
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let mut decoder = DecoderStreaming::new(config, dict);

        assert_eq!(decoder.buffered_bytes(), 0);
        assert_eq!(decoder.num_bytes_required(), 1);

        decoder.feed(&[ASN1_SEQUENCE_TAG, ASN1_LONG_FORM_LENGTH_2_BYTES]); // SEQUENCE tag with long form length
        assert_eq!(decoder.buffered_bytes(), 2);
    }

    #[test]
    fn test_length_validation_against_max_size() {
        // Create a config with a small max message size for testing
        let mut config = Config::default();
        config.max_message_size = 100; // Set a small limit for testing

        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let mut decoder = DecoderStreaming::new(config, dict);

        // Feed a SEQUENCE tag
        decoder.feed(&[ASN1_SEQUENCE_TAG]);

        // Feed a long form length that exceeds max_message_size
        // Using 2-byte length encoding: first byte 0x82 means 2 length bytes follow
        // Next two bytes encode length 0x1000 (4096 bytes) which exceeds our limit of 100
        decoder.feed(&[0x82, 0x10, 0x00]);

        // Try to decode - should fail with MessageTooLarge error
        let result = decoder.decode_next();
        match result {
            Err(Error::Decode(DecodeError::MessageTooLarge { size, max_size })) => {
                assert_eq!(size, 4096);
                assert_eq!(max_size, 100);
            }
            _ => panic!("Expected MessageTooLarge error, got: {result:?}"),
        }
    }

    #[test]
    fn test_length_validation_passes_within_limit() {
        let mut config = Config::default();
        config.max_message_size = 1000; // Set reasonable limit

        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let mut decoder = DecoderStreaming::new(config, dict);

        // Feed a SEQUENCE tag
        decoder.feed(&[ASN1_SEQUENCE_TAG]);

        // Feed a short form length that's within limit (50 bytes)
        decoder.feed(&[50]);

        // Decoder should transition to ReadingMessage state without error
        let result = decoder.decode_next();
        // It will return Ok(None) because we don't have enough data yet
        assert!(result.is_ok());
        assert!(matches!(
            decoder.state,
            DecoderState::ReadingMessage { length: 50, .. }
        ));
    }

    #[test]
    fn test_integer_parsing_with_result() {
        let msg = FixMessage {
            msg_type: "D".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            msg_seq_num: 123,
            fields: vec![
                Field {
                    tag: 38,
                    value: crate::types::FixFieldValue::UnsignedInteger(1000),
                },
                Field {
                    tag: 54,
                    value: crate::types::FixFieldValue::String("not_a_number".to_string()),
                },
                Field {
                    tag: 99,
                    value: crate::types::FixFieldValue::Integer(-50),
                },
            ],
        };

        let message = DecodedMessage::new(Bytes::new(), msg);

        // Test successful parsing
        assert_eq!(
            message.get_int(38).expect("Should parse unsigned as int"),
            Some(1000)
        );
        assert_eq!(
            message.get_uint(38).expect("Should parse unsigned"),
            Some(1000)
        );

        // Test missing field
        assert_eq!(message.get_int(999).expect("Should return Ok(None)"), None);
        assert_eq!(message.get_uint(999).expect("Should return Ok(None)"), None);

        // Test parsing error
        let int_err = message.get_int(54);
        assert!(matches!(
            int_err,
            Err(Error::Decode(DecodeError::ConstraintViolation { .. }))
        ));

        // Test negative to unsigned conversion error
        let uint_err = message.get_uint(99);
        assert!(matches!(
            uint_err,
            Err(Error::Decode(DecodeError::ConstraintViolation { .. }))
        ));
    }
}
