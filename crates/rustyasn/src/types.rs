//! ASN.1 type definitions and FIX field mappings.

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
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

/// ASN.1 CHOICE for representing different FIX field value types natively.
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(choice, crate_root = "rasn")]
pub enum FixFieldValue {
    /// String/text values
    #[rasn(tag(context, 0))]
    String(String),

    /// Signed integer values
    #[rasn(tag(context, 1))]
    Integer(i64),

    /// Unsigned integer values  
    #[rasn(tag(context, 2))]
    UnsignedInteger(u64),

    /// Decimal/floating point values
    #[rasn(tag(context, 3))]
    Decimal(String), // Encoded as string to preserve precision

    /// Boolean values (Y/N in FIX)
    #[rasn(tag(context, 4))]
    Boolean(bool),

    /// Single character values
    #[rasn(tag(context, 5))]
    Character(String), // Single char stored as string

    /// UTC timestamp values (YYYYMMDD-HH:MM:SS[.sss])
    #[rasn(tag(context, 6))]
    UtcTimestamp(String),

    /// UTC date values (YYYYMMDD)
    #[rasn(tag(context, 7))]
    UtcDate(String),

    /// UTC time values (HH:MM:SS[.sss])
    #[rasn(tag(context, 8))]
    UtcTime(String),

    /// Binary data
    #[rasn(tag(context, 9))]
    Data(Vec<u8>),

    /// Raw string for unknown/fallback cases
    #[rasn(tag(context, 10))]
    Raw(String),
}

/// Generic field representation with typed values.
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Field {
    /// Field tag number
    pub tag: u32,

    /// Typed field value using ASN.1 CHOICE
    pub value: FixFieldValue,
}

/// Trait for converting FIX field types to typed field values.
pub trait ToFixFieldValue {
    /// Convert to FIX field value.
    fn to_fix_field_value(&self) -> FixFieldValue;
}

impl FixFieldValue {
    /// Convert the typed value back to a string representation for compatibility.
    pub fn to_string(&self) -> String {
        match self {
            FixFieldValue::String(s) => s.clone(),
            FixFieldValue::Integer(i) => i.to_string(),
            FixFieldValue::UnsignedInteger(u) => u.to_string(),
            FixFieldValue::Decimal(d) => d.clone(),
            FixFieldValue::Boolean(b) => if *b { "Y" } else { "N" }.to_string(),
            FixFieldValue::Character(c) => c.clone(),
            FixFieldValue::UtcTimestamp(ts) => ts.clone(),
            FixFieldValue::UtcDate(date) => date.clone(),
            FixFieldValue::UtcTime(time) => time.clone(),
            FixFieldValue::Data(data) => String::from_utf8_lossy(data).to_string(),
            FixFieldValue::Raw(raw) => raw.clone(),
        }
    }

    /// Convert the typed value to bytes for serialization.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            FixFieldValue::String(s) => s.as_bytes().to_vec(),
            FixFieldValue::Integer(i) => i.to_string().into_bytes(),
            FixFieldValue::UnsignedInteger(u) => u.to_string().into_bytes(),
            FixFieldValue::Decimal(d) => d.as_bytes().to_vec(),
            FixFieldValue::Boolean(b) => if *b { b"Y" } else { b"N" }.to_vec(),
            FixFieldValue::Character(c) => c.as_bytes().to_vec(),
            FixFieldValue::UtcTimestamp(ts) => ts.as_bytes().to_vec(),
            FixFieldValue::UtcDate(date) => date.as_bytes().to_vec(),
            FixFieldValue::UtcTime(time) => time.as_bytes().to_vec(),
            FixFieldValue::Data(data) => data.clone(),
            FixFieldValue::Raw(raw) => raw.as_bytes().to_vec(),
        }
    }

    /// Create a `FixFieldValue` from a string, inferring the best type based on content.
    pub fn from_string(s: String) -> Self {
        // Check for integer types with better precedence handling
        if s.starts_with('-') {
            // Negative numbers can only be signed integers
            if let Ok(i) = s.parse::<i64>() {
                return FixFieldValue::Integer(i);
            }
        } else {
            // For non-negative numbers, try unsigned first to prefer the more specific type
            if let Ok(u) = s.parse::<u64>() {
                // If it fits in i64 range, use signed for consistency with FIX standard
                if i64::try_from(u).is_ok() {
                    return FixFieldValue::Integer(u as i64);
                }
                // Only use unsigned for values that don't fit in i64
                return FixFieldValue::UnsignedInteger(u);
            }
        }

        // Check for boolean values
        if s == "Y" {
            return FixFieldValue::Boolean(true);
        }
        if s == "N" {
            return FixFieldValue::Boolean(false);
        }

        // Check for single character
        if s.len() == 1 {
            return FixFieldValue::Character(s);
        }

        // Check for timestamp format (YYYYMMDD-HH:MM:SS[.sss]) using chrono
        if NaiveDateTime::parse_from_str(&s, "%Y%m%d-%H:%M:%S").is_ok() {
            return FixFieldValue::UtcTimestamp(s);
        }
        // Also check for timestamp with milliseconds
        if NaiveDateTime::parse_from_str(&s, "%Y%m%d-%H:%M:%S%.3f").is_ok() {
            return FixFieldValue::UtcTimestamp(s);
        }

        // Check for date format (YYYYMMDD) using chrono
        if s.len() == 8 && NaiveDate::parse_from_str(&s, "%Y%m%d").is_ok() {
            return FixFieldValue::UtcDate(s);
        }

        // Check for time format (HH:MM:SS[.sss]) using chrono
        if NaiveTime::parse_from_str(&s, "%H:%M:%S").is_ok() {
            return FixFieldValue::UtcTime(s);
        }
        // Also check for time with milliseconds
        if NaiveTime::parse_from_str(&s, "%H:%M:%S%.3f").is_ok() {
            return FixFieldValue::UtcTime(s);
        }

        // Default to string
        FixFieldValue::String(s)
    }

    /// Create a `FixFieldValue` from bytes and field type information.
    pub fn from_bytes_with_type(
        value: &[u8],
        fix_type: crate::schema::FixDataType,
    ) -> Result<Self, String> {
        use crate::schema::FixDataType;

        let s = String::from_utf8_lossy(value).to_string();

        match fix_type {
            FixDataType::Int => {
                let i = s
                    .parse::<i64>()
                    .map_err(|_| format!("Invalid integer: {s}"))?;
                Ok(FixFieldValue::Integer(i))
            }
            FixDataType::Length
            | FixDataType::NumInGroup
            | FixDataType::SeqNum
            | FixDataType::TagNum
            | FixDataType::DayOfMonth => {
                let u = s
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid unsigned integer: {s}"))?;
                Ok(FixFieldValue::UnsignedInteger(u))
            }
            FixDataType::Float
            | FixDataType::Qty
            | FixDataType::Price
            | FixDataType::PriceOffset
            | FixDataType::Amt
            | FixDataType::Percentage => {
                // Validate as decimal but store as string to preserve precision
                s.parse::<f64>()
                    .map_err(|_| format!("Invalid decimal: {s}"))?;
                Ok(FixFieldValue::Decimal(s))
            }
            FixDataType::Char => {
                if s.len() != 1 {
                    return Err(format!(
                        "Character field must be exactly 1 character, got: {s}"
                    ));
                }
                Ok(FixFieldValue::Character(s))
            }
            FixDataType::Boolean => match s.as_str() {
                "Y" => Ok(FixFieldValue::Boolean(true)),
                "N" => Ok(FixFieldValue::Boolean(false)),
                _ => Err(format!("Boolean field must be Y or N, got: {s}")),
            },
            FixDataType::UtcTimestamp => Ok(FixFieldValue::UtcTimestamp(s)),
            FixDataType::UtcDateOnly | FixDataType::LocalMktDate => Ok(FixFieldValue::UtcDate(s)),
            FixDataType::UtcTimeOnly | FixDataType::TzTimeOnly => Ok(FixFieldValue::UtcTime(s)),
            FixDataType::TzTimestamp => Ok(FixFieldValue::UtcTimestamp(s)),
            FixDataType::Data | FixDataType::XmlData => Ok(FixFieldValue::Data(value.to_vec())),
            _ => Ok(FixFieldValue::String(s)),
        }
    }
}

impl ToFixFieldValue for i32 {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::Integer(i64::from(*self))
    }
}

impl ToFixFieldValue for i64 {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::Integer(*self)
    }
}

impl ToFixFieldValue for u32 {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::UnsignedInteger(u64::from(*self))
    }
}

impl ToFixFieldValue for u64 {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::UnsignedInteger(*self)
    }
}

impl ToFixFieldValue for bool {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::Boolean(*self)
    }
}

impl ToFixFieldValue for &str {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::String((*self).to_string())
    }
}

impl ToFixFieldValue for String {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::String(self.clone())
    }
}

impl ToFixFieldValue for FixString {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::String(self.to_string())
    }
}

impl ToFixFieldValue for Decimal {
    fn to_fix_field_value(&self) -> FixFieldValue {
        FixFieldValue::Decimal(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_value_conversions() {
        assert_eq!(42i32.to_fix_field_value(), FixFieldValue::Integer(42));
        assert_eq!(true.to_fix_field_value(), FixFieldValue::Boolean(true));
        assert_eq!(false.to_fix_field_value(), FixFieldValue::Boolean(false));
        assert_eq!(
            "test".to_fix_field_value(),
            FixFieldValue::String("test".to_string())
        );
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
                value: FixFieldValue::String("EUR/USD".to_string()),
            }],
        };

        assert_eq!(msg.msg_type, "D");
        assert_eq!(msg.fields.len(), 1);
        assert_eq!(
            msg.fields[0].value,
            FixFieldValue::String("EUR/USD".to_string())
        );
    }
}
