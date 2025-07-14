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
use rustyfix::{Dictionary, StreamingDecoder as StreamingDecoderTrait};
use std::sync::Arc;

/// Decoded FIX message representation.
#[derive(Debug, Clone)]
pub struct Message {
    /// Raw ASN.1 encoded data
    raw: Bytes,

    /// Decoded message structure
    inner: FixMessage,

    /// Field lookup map for fast access
    fields: FxHashMap<u16, String>,
}

impl Message {
    /// Creates a new message from decoded data.
    fn new(raw: Bytes, inner: FixMessage) -> Self {
        let mut fields = FxHashMap::default();

        // Add standard fields
        fields.insert(35, inner.msg_type.clone());
        fields.insert(49, inner.sender_comp_id.clone());
        fields.insert(56, inner.target_comp_id.clone());
        fields.insert(34, inner.msg_seq_num.to_string());

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
    pub fn get_field(&self, tag: u16) -> Option<&str> {
        self.fields.get(&tag).map(std::string::String::as_str)
    }

    /// Gets a string field value.
    pub fn get_string(&self, tag: u16) -> Option<&str> {
        self.get_field(tag)
    }

    /// Gets an integer field value.
    pub fn get_int(&self, tag: u16) -> Option<i64> {
        self.get_field(tag)?.parse().ok()
    }

    /// Gets an unsigned integer field value.
    pub fn get_uint(&self, tag: u16) -> Option<u64> {
        self.get_field(tag)?.parse().ok()
    }

    /// Gets a boolean field value.
    pub fn get_bool(&self, tag: u16) -> Option<bool> {
        match self.get_field(tag)? {
            "Y" => Some(true),
            "N" => Some(false),
            _ => None,
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

impl Decoder {
    /// Creates a new decoder with the given configuration and dictionary.
    pub fn new(config: Config, dictionary: Arc<Dictionary>) -> Self {
        let schema = Arc::new(Schema::new(dictionary));
        Self { config, schema }
    }

    /// Decodes a single message from bytes.
    pub fn decode(&self, data: &[u8]) -> Result<Message> {
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

        Ok(Message::new(Bytes::copy_from_slice(data), fix_msg))
    }

    /// Decodes using the specified encoding rule.
    fn decode_with_rule(&self, data: &[u8], rule: EncodingRule) -> Result<FixMessage> {
        match rule {
            EncodingRule::BER => ber_decode::<FixMessage>(data)
                .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string()))),

            EncodingRule::DER => der_decode::<FixMessage>(data)
                .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string()))),

            EncodingRule::PER | EncodingRule::APER | EncodingRule::UPER => {
                // PER not available in this version, use DER as fallback
                der_decode::<FixMessage>(data)
                    .map_err(|e| Error::Decode(DecodeError::Internal(e.to_string())))
            }

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
    pub fn decode_next(&mut self) -> Result<Option<Message>> {
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
                        // We have a complete message
                        let msg_data: Vec<u8> = self.buffer.drain(0..offset + length).collect();
                        self.state = DecoderState::WaitingForMessage;

                        // Decode the message
                        let message = self.decoder.decode(&msg_data)?;
                        return Ok(Some(message));
                    }
                    // Need more data
                    return Ok(None);
                }
            }
        }
    }

    /// Checks if a byte is a valid ASN.1 tag.
    fn is_valid_asn1_tag(&self, tag: u8) -> bool {
        // Check for valid ASN.1 tag format
        tag == 0x30 || (tag & 0xE0) == 0xA0 // SEQUENCE or context-specific constructed
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
        let dict = Arc::new(Dictionary::fix44().unwrap());
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
                value: "EUR/USD".to_string(),
            }],
        };

        let message = Message::new(Bytes::new(), msg);

        assert_eq!(message.msg_type(), "D");
        assert_eq!(message.sender_comp_id(), "SENDER");
        assert_eq!(message.msg_seq_num(), 123);
        assert_eq!(message.get_string(55), Some("EUR/USD"));
    }

    #[test]
    fn test_streaming_decoder_state() {
        let config = Config::default();
        let dict = Arc::new(Dictionary::fix44().unwrap());
        let mut decoder = DecoderStreaming::new(config, dict);

        assert_eq!(decoder.buffered_bytes(), 0);
        assert_eq!(decoder.num_bytes_required(), 1);

        decoder.feed(&[0x30, 0x82]); // SEQUENCE tag with long form length
        assert_eq!(decoder.buffered_bytes(), 2);
    }
}
