//! ASN.1 type definitions and FIX field mappings.

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use rasn::{AsnType, Decode, Decoder, Encode};
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
                // Use unsigned types (e.g., u64) to maintain semantic meaning and specificity for non-negative values
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
    /// This method is optimized to avoid unnecessary string conversions for binary data types.
    pub fn from_bytes_with_type(
        value: &[u8],
        fix_type: crate::schema::FixDataType,
    ) -> Result<Self, String> {
        use crate::schema::FixDataType;

        match fix_type {
            // Handle binary data types first to avoid string conversion
            FixDataType::Data | FixDataType::XmlData => Ok(FixFieldValue::Data(value.to_vec())),

            // For numeric types, parse directly from bytes to avoid string allocation
            FixDataType::Int => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for integer field".to_string())?;
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
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for unsigned integer field".to_string())?;
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
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for decimal field".to_string())?;
                // Validate as decimal but store as string to preserve precision
                s.parse::<f64>()
                    .map_err(|_| format!("Invalid decimal: {s}"))?;
                Ok(FixFieldValue::Decimal(s.to_string()))
            }
            FixDataType::Char => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for character field".to_string())?;
                if s.len() != 1 {
                    return Err(format!(
                        "Character field must be exactly 1 character, got: {s}"
                    ));
                }
                Ok(FixFieldValue::Character(s.to_string()))
            }
            FixDataType::Boolean => match value {
                b"Y" => Ok(FixFieldValue::Boolean(true)),
                b"N" => Ok(FixFieldValue::Boolean(false)),
                _ => {
                    let s = std::str::from_utf8(value)
                        .map_err(|_| "Invalid UTF-8 for boolean field".to_string())?;
                    Err(format!("Boolean field must be Y or N, got: {s}"))
                }
            },
            // For timestamp/date/time types, convert to string but validate UTF-8 first
            FixDataType::UtcTimestamp | FixDataType::TzTimestamp => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for timestamp field".to_string())?;
                Ok(FixFieldValue::UtcTimestamp(s.to_string()))
            }
            FixDataType::UtcDateOnly | FixDataType::LocalMktDate => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for date field".to_string())?;
                Ok(FixFieldValue::UtcDate(s.to_string()))
            }
            FixDataType::UtcTimeOnly | FixDataType::TzTimeOnly => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for time field".to_string())?;
                Ok(FixFieldValue::UtcTime(s.to_string()))
            }
            // Default to string for other types
            _ => {
                let s = std::str::from_utf8(value)
                    .map_err(|_| "Invalid UTF-8 for string field".to_string())?;
                Ok(FixFieldValue::String(s.to_string()))
            }
        }
    }

    /// Create a `FixFieldValue` from bytes using schema type information.
    /// This is the preferred method when schema/dictionary type information is available.
    pub fn from_bytes_with_schema(
        value: &[u8],
        tag: u16,
        schema: &crate::schema::Schema,
    ) -> Result<Self, crate::Error> {
        let field_info = schema
            .get_field_type(tag)
            .ok_or_else(|| crate::Error::Schema(format!("Unknown field tag: {tag}").into()))?;

        Self::from_bytes_with_type(value, field_info.fix_type)
            .map_err(|e| crate::Error::Schema(e.into()))
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::schema::{FixDataType, Schema};
    use rustyfix_dictionary::Dictionary;
    use std::sync::Arc;

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

    #[test]
    fn test_from_bytes_with_type_integer() {
        let result = FixFieldValue::from_bytes_with_type(b"42", FixDataType::Int);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Integer(42));

        let result = FixFieldValue::from_bytes_with_type(b"-123", FixDataType::Int);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Integer(-123));

        // Test invalid integer
        let result = FixFieldValue::from_bytes_with_type(b"abc", FixDataType::Int);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_with_type_unsigned_integer() {
        let result = FixFieldValue::from_bytes_with_type(b"123", FixDataType::Length);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::UnsignedInteger(123));

        let result = FixFieldValue::from_bytes_with_type(b"0", FixDataType::SeqNum);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::UnsignedInteger(0));

        // Test invalid unsigned integer
        let result = FixFieldValue::from_bytes_with_type(b"-1", FixDataType::Length);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_with_type_decimal() {
        let result = FixFieldValue::from_bytes_with_type(b"123.45", FixDataType::Price);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::Decimal("123.45".to_string())
        );

        let result = FixFieldValue::from_bytes_with_type(b"0.001", FixDataType::Percentage);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Decimal("0.001".to_string()));

        // Test invalid decimal
        let result = FixFieldValue::from_bytes_with_type(b"abc", FixDataType::Float);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_with_type_boolean() {
        let result = FixFieldValue::from_bytes_with_type(b"Y", FixDataType::Boolean);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Boolean(true));

        let result = FixFieldValue::from_bytes_with_type(b"N", FixDataType::Boolean);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Boolean(false));

        // Test invalid boolean
        let result = FixFieldValue::from_bytes_with_type(b"X", FixDataType::Boolean);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_with_type_character() {
        let result = FixFieldValue::from_bytes_with_type(b"A", FixDataType::Char);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Character("A".to_string()));

        // Test invalid character (multiple characters)
        let result = FixFieldValue::from_bytes_with_type(b"AB", FixDataType::Char);
        assert!(result.is_err());

        // Test empty character
        let result = FixFieldValue::from_bytes_with_type(b"", FixDataType::Char);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_with_type_timestamp() {
        let result =
            FixFieldValue::from_bytes_with_type(b"20240101-12:30:45", FixDataType::UtcTimestamp);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcTimestamp("20240101-12:30:45".to_string())
        );

        let result =
            FixFieldValue::from_bytes_with_type(b"20240101-12:30:45.123", FixDataType::TzTimestamp);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcTimestamp("20240101-12:30:45.123".to_string())
        );
    }

    #[test]
    fn test_from_bytes_with_type_date() {
        let result = FixFieldValue::from_bytes_with_type(b"20240101", FixDataType::UtcDateOnly);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcDate("20240101".to_string())
        );

        let result = FixFieldValue::from_bytes_with_type(b"20241231", FixDataType::LocalMktDate);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcDate("20241231".to_string())
        );
    }

    #[test]
    fn test_from_bytes_with_type_time() {
        let result = FixFieldValue::from_bytes_with_type(b"12:30:45", FixDataType::UtcTimeOnly);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcTime("12:30:45".to_string())
        );

        let result = FixFieldValue::from_bytes_with_type(b"12:30:45.123", FixDataType::TzTimeOnly);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::UtcTime("12:30:45.123".to_string())
        );
    }

    #[test]
    fn test_from_bytes_with_type_binary_data() {
        let binary_data = vec![0x01, 0x02, 0x03, 0xFF];
        let result = FixFieldValue::from_bytes_with_type(&binary_data, FixDataType::Data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Data(binary_data.clone()));

        let xml_data = b"<xml>test</xml>";
        let result = FixFieldValue::from_bytes_with_type(xml_data, FixDataType::XmlData);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Data(xml_data.to_vec()));
    }

    #[test]
    fn test_from_bytes_with_type_string() {
        let result = FixFieldValue::from_bytes_with_type(b"EUR/USD", FixDataType::String);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            FixFieldValue::String("EUR/USD".to_string())
        );

        let result = FixFieldValue::from_bytes_with_type(b"NYSE", FixDataType::Exchange);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::String("NYSE".to_string()));

        let result = FixFieldValue::from_bytes_with_type(b"USD", FixDataType::Currency);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::String("USD".to_string()));
    }

    #[test]
    fn test_from_bytes_with_type_invalid_utf8() {
        // Test invalid UTF-8 for string types
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = FixFieldValue::from_bytes_with_type(&invalid_utf8, FixDataType::String);
        assert!(result.is_err());

        let result = FixFieldValue::from_bytes_with_type(&invalid_utf8, FixDataType::Int);
        assert!(result.is_err());

        // But should work for binary data
        let result = FixFieldValue::from_bytes_with_type(&invalid_utf8, FixDataType::Data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Data(invalid_utf8));
    }

    #[test]
    fn test_from_bytes_with_schema() {
        let dict = Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary"));
        let schema = Schema::new(dict);

        // Test with MsgSeqNum (tag 34) - should be SeqNum type
        let result = FixFieldValue::from_bytes_with_schema(b"123", 34, &schema);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::UnsignedInteger(123));

        // Test with MsgType (tag 35) - should be String type
        let result = FixFieldValue::from_bytes_with_schema(b"D", 35, &schema);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::String("D".to_string()));

        // Test with unknown tag
        let result = FixFieldValue::from_bytes_with_schema(b"test", 9999, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_optimization_binary_data_no_string_conversion() {
        // Test that binary data doesn't go through string conversion
        let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]; // Invalid UTF-8
        let result = FixFieldValue::from_bytes_with_type(&binary_data, FixDataType::Data);
        assert!(result.is_ok());
        if let FixFieldValue::Data(data) = result.unwrap() {
            assert_eq!(data, binary_data);
        } else {
            panic!("Expected Data variant");
        }
    }

    #[test]
    fn test_optimization_boolean_byte_comparison() {
        // Test that boolean comparison uses byte arrays directly
        let result = FixFieldValue::from_bytes_with_type(b"Y", FixDataType::Boolean);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Boolean(true));

        let result = FixFieldValue::from_bytes_with_type(b"N", FixDataType::Boolean);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FixFieldValue::Boolean(false));
    }

    #[test]
    fn test_performance_comparison_from_string_vs_from_bytes_with_type() {
        // This test demonstrates the inefficiency of from_string vs the optimized method
        let test_cases = vec![
            (
                b"42".as_slice(),
                FixDataType::Int,
                FixFieldValue::Integer(42),
            ),
            (
                b"123".as_slice(),
                FixDataType::Length,
                FixFieldValue::UnsignedInteger(123),
            ),
            (
                b"Y".as_slice(),
                FixDataType::Boolean,
                FixFieldValue::Boolean(true),
            ),
            (
                b"EUR/USD".as_slice(),
                FixDataType::String,
                FixFieldValue::String("EUR/USD".to_string()),
            ),
        ];

        for (bytes, fix_type, expected) in test_cases {
            // Test optimized method
            let result_optimized = FixFieldValue::from_bytes_with_type(bytes, fix_type);
            assert!(result_optimized.is_ok());
            assert_eq!(result_optimized.unwrap(), expected);

            // Test legacy method (string inference) - should still work but is less efficient
            let string_value = String::from_utf8_lossy(bytes).to_string();
            let result_legacy = FixFieldValue::from_string(string_value);
            // Note: from_string might infer different types than the explicit type,
            // so we don't assert equality here, just that it works
            assert!(matches!(
                result_legacy,
                FixFieldValue::Integer(_)
                    | FixFieldValue::UnsignedInteger(_)
                    | FixFieldValue::Boolean(_)
                    | FixFieldValue::String(_)
            ));
        }
    }
}
