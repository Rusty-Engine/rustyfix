//! ASN.1 type definitions and FIX field mappings.

use rasn::{AsnType, Decode, Encode};
use rust_decimal::Decimal;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;

/// ASN.1 representation of a FIX message (simplified).
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct FixMessage {
    /// Message type (tag 35)
    pub msg_type: String,

    /// Sender ID (tag 49)
    pub sender_comp_id: String,

    /// Target ID (tag 56)
    pub target_comp_id: String,

    /// Message sequence number (tag 34)
    pub msg_seq_num: u64,

    /// Optional fields as a sequence
    pub fields: Vec<Field>,
}

/// Generic field representation.
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Field {
    /// Field tag number
    pub tag: u16,

    /// Field value as string (simplified)
    pub value: String,
}

/// Trait for converting FIX field types to string values.
pub trait ToFixFieldValue {
    /// Convert to FIX field value.
    fn to_fix_field_value(&self) -> String;
}

impl ToFixFieldValue for i32 {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

impl ToFixFieldValue for i64 {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

impl ToFixFieldValue for u32 {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

impl ToFixFieldValue for u64 {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

impl ToFixFieldValue for bool {
    fn to_fix_field_value(&self) -> String {
        if *self { "Y" } else { "N" }.to_string()
    }
}

impl ToFixFieldValue for &str {
    fn to_fix_field_value(&self) -> String {
        (*self).to_string()
    }
}

impl ToFixFieldValue for String {
    fn to_fix_field_value(&self) -> String {
        self.clone()
    }
}

impl ToFixFieldValue for FixString {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

impl ToFixFieldValue for Decimal {
    fn to_fix_field_value(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_value_conversions() {
        assert_eq!(42i32.to_fix_field_value(), "42");
        assert_eq!(true.to_fix_field_value(), "Y");
        assert_eq!(false.to_fix_field_value(), "N");
        assert_eq!("test".to_fix_field_value(), "test");
    }

    #[test]
    fn test_message_structure() {
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

        assert_eq!(msg.msg_type, "D");
        assert_eq!(msg.fields.len(), 1);
    }
}
