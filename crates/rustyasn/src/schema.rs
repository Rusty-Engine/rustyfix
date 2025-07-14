//! ASN.1 schema definitions and FIX message type mappings.

use rustc_hash::FxHashMap;
use rustyfix_dictionary::Dictionary;
use smallvec::SmallVec;
use smartstring::{LazyCompact, SmartString};

type FixString = SmartString<LazyCompact>;
use std::sync::Arc;

/// Schema definition for ASN.1 encoding of FIX messages.
#[derive(Clone)]
pub struct Schema {
    /// FIX dictionary reference
    dictionary: Arc<Dictionary>,

    /// Message type to ASN.1 structure mappings
    message_schemas: FxHashMap<FixString, MessageSchema>,

    /// Field tag to type mappings
    field_types: FxHashMap<u16, FieldTypeInfo>,
}

/// Schema for a specific message type.
#[derive(Debug, Clone)]
pub struct MessageSchema {
    /// Message type (tag 35 value)
    pub msg_type: FixString,

    /// Required fields for this message
    pub required_fields: SmallVec<[u16; 8]>,

    /// Optional fields for this message
    pub optional_fields: SmallVec<[u16; 16]>,

    /// Repeating groups in this message
    pub groups: FxHashMap<u16, GroupSchema>,
}

/// Schema for a repeating group.
#[derive(Debug, Clone)]
pub struct GroupSchema {
    /// Group count field tag
    pub count_tag: u16,

    /// First field in the group (delimiter)
    pub first_field: u16,

    /// Fields that can appear in the group
    pub fields: SmallVec<[u16; 8]>,
}

/// Type information for a field.
#[derive(Debug, Clone, Copy)]
pub struct FieldTypeInfo {
    /// FIX data type
    pub fix_type: FixDataType,

    /// Whether field is required in header
    pub in_header: bool,

    /// Whether field is required in trailer
    pub in_trailer: bool,
}

/// FIX data types mapped to ASN.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixDataType {
    /// Integer
    Int,
    /// Unsigned integer
    Length,
    /// Numeric identifier
    NumInGroup,
    /// Sequence number
    SeqNum,
    /// Tag number
    TagNum,
    /// Day of month
    DayOfMonth,
    /// Float
    Float,
    /// Quantity
    Qty,
    /// Price
    Price,
    /// Price offset
    PriceOffset,
    /// Amount
    Amt,
    /// Percentage
    Percentage,
    /// Character
    Char,
    /// Boolean (Y/N)
    Boolean,
    /// String
    String,
    /// Multiple value string
    MultipleValueString,
    /// Multiple char value
    MultipleCharValue,
    /// Currency
    Currency,
    /// Exchange
    Exchange,
    /// UTC timestamp
    UtcTimestamp,
    /// UTC date only
    UtcDateOnly,
    /// UTC time only
    UtcTimeOnly,
    /// Local market date
    LocalMktDate,
    /// TZ time only
    TzTimeOnly,
    /// TZ timestamp
    TzTimestamp,
    /// Binary data
    Data,
    /// XML data
    XmlData,
    /// Language
    Language,
    /// Pattern
    Pattern,
    /// Tenor
    Tenor,
}

impl Schema {
    /// Creates a new schema from a FIX dictionary.
    pub fn new(dictionary: Arc<Dictionary>) -> Self {
        let mut schema = Self {
            dictionary: dictionary.clone(),
            message_schemas: FxHashMap::default(),
            field_types: FxHashMap::default(),
        };

        // Build field type mappings
        schema.build_field_types();

        // Build message schemas
        schema.build_message_schemas();

        schema
    }

    /// Builds field type information from dictionary.
    fn build_field_types(&mut self) {
        // Standard header fields
        self.add_header_fields();

        // Standard trailer fields
        self.add_trailer_fields();

        // TODO: Add all field definitions from dictionary
        // This would normally iterate through dictionary.fields()
    }

    /// Adds standard FIX header fields.
    fn add_header_fields(&mut self) {
        let header_fields = [
            (8, FixDataType::String),        // BeginString
            (9, FixDataType::Length),        // BodyLength
            (35, FixDataType::String),       // MsgType
            (34, FixDataType::SeqNum),       // MsgSeqNum
            (49, FixDataType::String),       // SenderCompID
            (56, FixDataType::String),       // TargetCompID
            (52, FixDataType::UtcTimestamp), // SendingTime
        ];

        for (tag, fix_type) in header_fields {
            self.field_types.insert(
                tag,
                FieldTypeInfo {
                    fix_type,
                    in_header: true,
                    in_trailer: false,
                },
            );
        }
    }

    /// Adds standard FIX trailer fields.
    fn add_trailer_fields(&mut self) {
        let trailer_fields = [
            (10, FixDataType::String), // CheckSum
        ];

        for (tag, fix_type) in trailer_fields {
            self.field_types.insert(
                tag,
                FieldTypeInfo {
                    fix_type,
                    in_header: false,
                    in_trailer: true,
                },
            );
        }
    }

    /// Builds message schemas from dictionary.
    fn build_message_schemas(&mut self) {
        // Add common message types
        self.add_admin_messages();
        self.add_order_messages();
        self.add_market_data_messages();
    }

    /// Adds administrative message schemas.
    fn add_admin_messages(&mut self) {
        // Logon message (A)
        let logon_schema = MessageSchema {
            msg_type: "A".into(),
            required_fields: smallvec::smallvec![98, 108], // EncryptMethod, HeartBtInt
            optional_fields: smallvec::smallvec![95, 96, 141, 789], // SecureDataLen, SecureData, ResetSeqNumFlag, NextExpectedMsgSeqNum
            groups: FxHashMap::default(),
        };
        self.message_schemas.insert("A".into(), logon_schema);

        // Heartbeat message (0)
        let heartbeat_schema = MessageSchema {
            msg_type: "0".into(),
            required_fields: smallvec::smallvec![],
            optional_fields: smallvec::smallvec![112], // TestReqID
            groups: FxHashMap::default(),
        };
        self.message_schemas.insert("0".into(), heartbeat_schema);

        // Test Request (1)
        let test_request_schema = MessageSchema {
            msg_type: "1".into(),
            required_fields: smallvec::smallvec![112], // TestReqID
            optional_fields: smallvec::smallvec![],
            groups: FxHashMap::default(),
        };
        self.message_schemas.insert("1".into(), test_request_schema);
    }

    /// Adds order-related message schemas.
    fn add_order_messages(&mut self) {
        // New Order Single (D)
        let new_order_schema = MessageSchema {
            msg_type: "D".into(),
            required_fields: smallvec::smallvec![
                11, // ClOrdID
                55, // Symbol
                54, // Side
                60, // TransactTime
                40, // OrdType
            ],
            optional_fields: smallvec::smallvec![
                1,  // Account
                38, // OrderQty
                44, // Price
                99, // StopPx
                59, // TimeInForce
                18, // ExecInst
            ],
            groups: FxHashMap::default(),
        };
        self.message_schemas.insert("D".into(), new_order_schema);

        // Execution Report (8)
        let exec_report_schema = MessageSchema {
            msg_type: "8".into(),
            required_fields: smallvec::smallvec![
                37,  // OrderID
                17,  // ExecID
                150, // ExecType
                39,  // OrdStatus
                55,  // Symbol
                54,  // Side
            ],
            optional_fields: smallvec::smallvec![
                11,  // ClOrdID
                41,  // OrigClOrdID
                1,   // Account
                6,   // AvgPx
                14,  // CumQty
                151, // LeavesQty
            ],
            groups: FxHashMap::default(),
        };
        self.message_schemas.insert("8".into(), exec_report_schema);
    }

    /// Adds market data message schemas.
    fn add_market_data_messages(&mut self) {
        // Market Data Request (V)
        let mut md_request_schema = MessageSchema {
            msg_type: "V".into(),
            required_fields: smallvec::smallvec![
                262, // MDReqID
                263, // SubscriptionRequestType
                264, // MarketDepth
            ],
            optional_fields: smallvec::smallvec![
                265, // MDUpdateType
                266, // AggregatedBook
            ],
            groups: FxHashMap::default(),
        };

        // Add MDEntryTypes group (tag 267)
        md_request_schema.groups.insert(
            267,
            GroupSchema {
                count_tag: 267,
                first_field: 269, // MDEntryType
                fields: smallvec::smallvec![269],
            },
        );

        // Add Instruments group (tag 146)
        md_request_schema.groups.insert(
            146,
            GroupSchema {
                count_tag: 146,
                first_field: 55,                             // Symbol
                fields: smallvec::smallvec![55, 65, 48, 22], // Symbol, SymbolSfx, SecurityID, SecurityIDSource
            },
        );

        self.message_schemas.insert("V".into(), md_request_schema);
    }

    /// Gets the schema for a message type.
    pub fn get_message_schema(&self, msg_type: &str) -> Option<&MessageSchema> {
        self.message_schemas.get(msg_type)
    }

    /// Gets the type information for a field.
    pub fn get_field_type(&self, tag: u16) -> Option<&FieldTypeInfo> {
        self.field_types.get(&tag)
    }

    /// Maps a FIX data type to the appropriate string value.
    pub fn map_field_type(&self, tag: u16, value: &[u8]) -> Result<String, crate::Error> {
        let _field_info = self
            .get_field_type(tag)
            .ok_or_else(|| crate::Error::Schema(format!("Unknown field tag: {tag}").into()))?;

        // For simplified implementation, always convert to string
        let s = std::str::from_utf8(value)
            .map_err(|_| crate::Error::Decode(crate::DecodeError::InvalidUtf8 { offset: 0 }))?;
        Ok(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Check header fields
        let field_8 = schema
            .get_field_type(8)
            .expect("Field 8 should exist in FIX 4.4 dictionary");
        assert_eq!(field_8.fix_type, FixDataType::String);
        assert!(field_8.in_header);

        // Check message schemas
        let logon = schema
            .get_message_schema("A")
            .expect("Logon message should exist in FIX 4.4 dictionary");
        assert_eq!(logon.msg_type, "A");
        assert!(logon.required_fields.contains(&98)); // EncryptMethod
    }

    #[test]
    fn test_field_type_mapping() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let mut schema = Schema::new(dict);

        // Test boolean mapping
        schema.field_types.insert(
            1000,
            FieldTypeInfo {
                fix_type: FixDataType::Boolean,
                in_header: false,
                in_trailer: false,
            },
        );

        let result = schema
            .map_field_type(1000, b"Y")
            .expect("Field mapping should not fail in test");
        assert_eq!(result, "Y");

        let result = schema
            .map_field_type(1000, b"N")
            .expect("Field mapping should not fail in test");
        assert_eq!(result, "N");
    }
}
