//! ASN.1 message implementation with `FieldMap` trait support.
//!
//! This module provides the core message types that implement `RustyFix` traits
//! for seamless integration with the FIX protocol ecosystem.

use crate::field_types::{Asn1FieldError, Asn1String, Asn1UInteger};
use crate::generated::{Asn1Field, Asn1FixMessage, FixFieldTag, FixMessageType};
use crate::types::{Field, FixMessage};
use rustyfix::{FieldMap, FieldType, FieldValueError, RepeatingGroup};
use std::collections::HashMap;

/// ASN.1 message that implements `FieldMap` for rustyfix integration.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Message type
    pub msg_type: FixMessageType,
    /// Sender company ID
    pub sender_comp_id: String,
    /// Target company ID
    pub target_comp_id: String,
    /// Message sequence number
    pub msg_seq_num: u64,
    /// Sending time (optional)
    pub sending_time: Option<String>,
    /// Fields indexed by tag for fast lookup
    fields: HashMap<u32, Vec<u8>>,
    /// Original field order for groups
    field_order: Vec<u32>,
}

impl Message {
    /// Creates a new ASN.1 message.
    pub fn new(
        msg_type: FixMessageType,
        sender_comp_id: String,
        target_comp_id: String,
        msg_seq_num: u64,
    ) -> Self {
        let mut fields = HashMap::new();
        let mut field_order = Vec::new();

        // Add standard header fields
        fields.insert(35, msg_type.as_str().as_bytes().to_vec());
        field_order.push(35);

        fields.insert(49, sender_comp_id.as_bytes().to_vec());
        field_order.push(49);

        fields.insert(56, target_comp_id.as_bytes().to_vec());
        field_order.push(56);

        fields.insert(34, ToString::to_string(&msg_seq_num).as_bytes().to_vec());
        field_order.push(34);

        Self {
            msg_type,
            sender_comp_id,
            target_comp_id,
            msg_seq_num,
            sending_time: None,
            fields,
            field_order,
        }
    }

    /// Creates a message from a simple `FixMessage`.
    pub fn from_fix_message(fix_msg: &FixMessage) -> Option<Self> {
        let msg_type = FixMessageType::from_str(&fix_msg.msg_type)?;
        let mut message = Self::new(
            msg_type,
            fix_msg.sender_comp_id.clone(),
            fix_msg.target_comp_id.clone(),
            fix_msg.msg_seq_num,
        );

        // Add additional fields
        for field in &fix_msg.fields {
            message.set_field(field.tag, field.value.as_bytes());
        }

        Some(message)
    }

    /// Creates a message from an ASN.1 FIX message.
    pub fn from_asn1_message(asn1_msg: &Asn1FixMessage) -> Self {
        let mut message = Self::new(
            asn1_msg.msg_type,
            asn1_msg.sender_comp_id.clone(),
            asn1_msg.target_comp_id.clone(),
            asn1_msg.msg_seq_num,
        );

        if let Some(ref sending_time) = asn1_msg.sending_time {
            message.sending_time = Some(sending_time.clone());
            message.set_field(52, sending_time.as_bytes().to_vec());
        }

        // Add ASN.1 fields
        for field in &asn1_msg.fields {
            message.set_field(field.tag.as_u32(), field.value.as_bytes().to_vec());
        }

        message
    }

    /// Converts to a simple `FixMessage`.
    pub fn to_fix_message(&self) -> FixMessage {
        let fields = self
            .field_order
            .iter()
            .filter_map(|&tag| {
                // Skip standard header fields that are already in the struct
                if matches!(tag, 35 | 49 | 56 | 34 | 52) {
                    return None;
                }
                self.fields.get(&tag).map(|value| Field {
                    tag,
                    value: crate::types::FixFieldValue::from_string(
                        String::from_utf8_lossy(value).to_string(),
                    ),
                })
            })
            .collect();

        FixMessage {
            msg_type: self.msg_type.as_str().to_string(),
            sender_comp_id: self.sender_comp_id.clone(),
            target_comp_id: self.target_comp_id.clone(),
            msg_seq_num: self.msg_seq_num,
            fields,
        }
    }

    /// Converts to ASN.1 `FixMessage`.
    pub fn to_asn1_message(&self) -> Option<Asn1FixMessage> {
        let fields = self
            .field_order
            .iter()
            .filter_map(|&tag| {
                // Skip standard header fields
                if matches!(tag, 35 | 49 | 56 | 34 | 52) {
                    return None;
                }
                let field_tag = FixFieldTag::from_u32(tag)?;
                let value = self.fields.get(&tag)?;
                Some(Asn1Field {
                    tag: field_tag,
                    value: String::from_utf8_lossy(value).to_string(),
                })
            })
            .collect();

        Some(Asn1FixMessage {
            msg_type: self.msg_type,
            sender_comp_id: self.sender_comp_id.clone(),
            target_comp_id: self.target_comp_id.clone(),
            msg_seq_num: self.msg_seq_num,
            sending_time: self.sending_time.clone(),
            fields,
        })
    }

    /// Sets a field value.
    pub fn set_field(&mut self, tag: u32, value: Vec<u8>) {
        if !self.fields.contains_key(&tag) {
            self.field_order.push(tag);
        }
        self.fields.insert(tag, value);
    }

    /// Gets all field tags in order.
    pub fn field_tags(&self) -> &[u32] {
        &self.field_order
    }

    /// Gets the number of fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl FieldMap<u32> for Message {
    type Group = MessageGroup;

    fn get_raw(&self, field: u32) -> Option<&[u8]> {
        self.fields.get(&field).map(std::vec::Vec::as_slice)
    }

    fn get<'a, V: FieldType<'a>>(&'a self, field: u32) -> Result<V, FieldValueError<V::Error>> {
        self.get_raw(field)
            .ok_or(FieldValueError::Missing)
            .and_then(|data| V::deserialize(data).map_err(FieldValueError::Invalid))
    }

    fn get_opt<'a, V: FieldType<'a>>(&'a self, field: u32) -> Result<Option<V>, V::Error> {
        match self.get_raw(field) {
            Some(data) => V::deserialize(data).map(Some),
            None => Ok(None),
        }
    }

    fn get_lossy<'a, V: FieldType<'a>>(
        &'a self,
        field: u32,
    ) -> Result<V, FieldValueError<V::Error>> {
        self.get_raw(field)
            .ok_or(FieldValueError::Missing)
            .and_then(|data| V::deserialize_lossy(data).map_err(FieldValueError::Invalid))
    }

    fn get_lossy_opt<'a, V: FieldType<'a>>(&'a self, field: u32) -> Result<Option<V>, V::Error> {
        match self.get_raw(field) {
            Some(data) => V::deserialize_lossy(data).map(Some),
            None => Ok(None),
        }
    }

    fn group(
        &self,
        _field: u32,
    ) -> Result<Self::Group, FieldValueError<<usize as FieldType>::Error>> {
        // For simplicity, create an empty group
        // In a full implementation, this would parse repeating groups
        Ok(MessageGroup::new(vec![]))
    }

    fn group_opt(&self, _field: u32) -> Result<Option<Self::Group>, <usize as FieldType>::Error> {
        // For simplicity, return None
        // In a full implementation, this would parse repeating groups
        Ok(None)
    }
}

/// Repeating group implementation for ASN.1 messages.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageGroup {
    entries: Vec<Message>,
}

impl MessageGroup {
    /// Creates a new message group.
    pub fn new(entries: Vec<Message>) -> Self {
        Self { entries }
    }

    /// Adds an entry to the group.
    pub fn add_entry(&mut self, entry: Message) {
        self.entries.push(entry);
    }
}

impl RepeatingGroup for MessageGroup {
    type Entry = Message;

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn get(&self, i: usize) -> Option<Self::Entry> {
        self.entries.get(i).cloned()
    }

    // Use default implementation from RepeatingGroup trait
}

/// Helper functions for common field access patterns.
impl Message {
    /// Gets message type field (tag 35).
    pub fn message_type(&self) -> Result<Asn1String, FieldValueError<Asn1FieldError>> {
        self.get(35)
    }

    /// Gets sender company ID field (tag 49).
    pub fn sender_company_id(&self) -> Result<Asn1String, FieldValueError<Asn1FieldError>> {
        self.get(49)
    }

    /// Gets target company ID field (tag 56).
    pub fn target_company_id(&self) -> Result<Asn1String, FieldValueError<Asn1FieldError>> {
        self.get(56)
    }

    /// Gets message sequence number field (tag 34).
    pub fn msg_seq_num(&self) -> Result<Asn1UInteger, FieldValueError<Asn1FieldError>> {
        self.get(34)
    }

    /// Gets sending time field (tag 52).
    pub fn sending_time(&self) -> Result<Option<Asn1String>, Asn1FieldError> {
        self.get_opt(52)
    }

    /// Gets symbol field (tag 55) if present.
    pub fn symbol(&self) -> Result<Option<Asn1String>, Asn1FieldError> {
        self.get_opt(55)
    }

    /// Gets side field (tag 54) if present.
    pub fn side(&self) -> Result<Option<Asn1String>, Asn1FieldError> {
        self.get_opt(54)
    }

    /// Gets order quantity field (tag 38) if present.
    pub fn order_qty(&self) -> Result<Option<Asn1UInteger>, Asn1FieldError> {
        self.get_opt(38)
    }

    /// Gets price field (tag 44) if present.
    pub fn price(&self) -> Result<Option<Asn1String>, Asn1FieldError> {
        self.get_opt(44)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Field;

    #[test]
    fn test_message_creation() {
        let msg_type =
            FixMessageType::from_str("D").expect("Failed to parse valid message type 'D'");
        let message = Message::new(msg_type, "SENDER".to_string(), "TARGET".to_string(), 123);

        assert_eq!(message.msg_type, msg_type);
        assert_eq!(message.sender_comp_id, "SENDER");
        assert_eq!(message.target_comp_id, "TARGET");
        assert_eq!(message.msg_seq_num, 123);
    }

    #[test]
    fn test_field_map_implementation() {
        let msg_type =
            FixMessageType::from_str("D").expect("Failed to parse valid message type 'D'");
        let mut message = Message::new(msg_type, "SENDER".to_string(), "TARGET".to_string(), 123);

        // Set a custom field
        message.set_field(55, b"EUR/USD".to_vec());

        // Test field access
        let symbol: Asn1String = message
            .get(55)
            .expect("Symbol field (55) should be present in test message");
        assert_eq!(symbol.as_str(), "EUR/USD");

        // Test missing field
        assert!(message.get_raw(999).is_none());

        // Test optional field access
        let symbol_opt: Option<Asn1String> = message
            .get_opt(55)
            .expect("get_opt should not fail for valid field access");
        assert!(symbol_opt.is_some());
        assert_eq!(
            symbol_opt.expect("Symbol should be present").as_str(),
            "EUR/USD"
        );

        let missing_opt: Option<Asn1String> = message
            .get_opt(999)
            .expect("get_opt should not fail even for missing fields");
        assert!(missing_opt.is_none());
    }

    #[test]
    fn test_conversion_from_fix_message() {
        let fix_msg = FixMessage {
            msg_type: "D".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            msg_seq_num: 123,
            fields: vec![
                Field {
                    tag: 55,
                    value: crate::types::FixFieldValue::String("EUR/USD".to_string()),
                },
                Field {
                    tag: 54,
                    value: crate::types::FixFieldValue::String("1".to_string()),
                },
            ],
        };

        let message = Message::from_fix_message(&fix_msg)
            .expect("Failed to convert valid FIX message to ASN.1 message");

        // Check standard fields
        assert_eq!(message.msg_type.as_str(), "D");
        assert_eq!(message.sender_comp_id, "SENDER");
        assert_eq!(message.target_comp_id, "TARGET");
        assert_eq!(message.msg_seq_num, 123);

        // Check custom fields
        let symbol: Asn1String = message
            .get(55)
            .expect("Symbol field (55) should be present in converted message");
        assert_eq!(symbol.as_str(), "EUR/USD");

        let side: Asn1String = message
            .get(54)
            .expect("Side field (54) should be present in converted message");
        assert_eq!(side.as_str(), "1");
    }

    #[test]
    fn test_conversion_to_fix_message() {
        let msg_type =
            FixMessageType::from_str("D").expect("Failed to parse valid message type 'D'");
        let mut message = Message::new(msg_type, "SENDER".to_string(), "TARGET".to_string(), 123);

        message.set_field(55, b"EUR/USD".to_vec());
        message.set_field(54, b"1".to_vec());

        let fix_msg = message.to_fix_message();

        assert_eq!(fix_msg.msg_type, "D");
        assert_eq!(fix_msg.sender_comp_id, "SENDER");
        assert_eq!(fix_msg.target_comp_id, "TARGET");
        assert_eq!(fix_msg.msg_seq_num, 123);
        assert_eq!(fix_msg.fields.len(), 2);

        // Find fields
        let symbol_field = fix_msg
            .fields
            .iter()
            .find(|f| f.tag == 55)
            .expect("Symbol field should exist in converted message");
        assert_eq!(symbol_field.value.to_string(), "EUR/USD");

        let side_field = fix_msg
            .fields
            .iter()
            .find(|f| f.tag == 54)
            .expect("Side field should exist in converted message");
        assert_eq!(side_field.value.to_string(), "1");
    }

    #[test]
    fn test_helper_methods() {
        let msg_type =
            FixMessageType::from_str("D").expect("Failed to parse valid message type 'D'");
        let mut message = Message::new(msg_type, "SENDER".to_string(), "TARGET".to_string(), 123);

        message.set_field(55, b"EUR/USD".to_vec());

        // Test helper methods
        let msg_type_result = message
            .message_type()
            .expect("Message type should be accessible in test message");
        assert_eq!(msg_type_result.as_str(), "D");

        let sender = message
            .sender_company_id()
            .expect("Sender company ID should be accessible in test message");
        assert_eq!(sender.as_str(), "SENDER");

        let symbol = message
            .symbol()
            .expect("Symbol should be accessible in test message");
        assert!(symbol.is_some());
        assert_eq!(
            symbol.expect("Symbol should be present").as_str(),
            "EUR/USD"
        );

        let missing = message
            .price()
            .expect("price() method should not fail even when field is missing");
        assert!(missing.is_none());
    }

    #[test]
    fn test_message_group() {
        let msg_type =
            FixMessageType::from_str("D").expect("Failed to parse valid message type 'D'");
        let message1 = Message::new(msg_type, "SENDER1".to_string(), "TARGET1".to_string(), 1);
        let message2 = Message::new(msg_type, "SENDER2".to_string(), "TARGET2".to_string(), 2);

        let mut group = MessageGroup::new(vec![message1.clone()]);
        group.add_entry(message2.clone());

        assert_eq!(group.len(), 2);
        assert!(!group.is_empty());

        let entry1 = group
            .get(0)
            .expect("First group entry should exist in test");
        assert_eq!(entry1.sender_comp_id, "SENDER1");

        let entry2 = group
            .get(1)
            .expect("Second group entry should exist in test");
        assert_eq!(entry2.sender_comp_id, "SENDER2");

        assert!(group.get(2).is_none());
    }
}
