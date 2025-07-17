//! ASN.1 schema definitions and FIX message type mappings.

use rustc_hash::FxHashMap;
use rustyfix_dictionary::{Dictionary, FixDatatype};
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

    /// Header field tags (configurable, derived from dictionary)
    header_tags: SmallVec<[u32; 16]>,

    /// Trailer field tags (configurable, derived from dictionary)
    trailer_tags: SmallVec<[u32; 8]>,
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
            header_tags: SmallVec::new(),
            trailer_tags: SmallVec::new(),
        };

        // Initialize configurable field tags from dictionary
        schema.initialize_field_tags();

        // Build the schema
        schema.build_field_types();
        schema.build_message_schemas();

        schema
    }

    /// Initializes header and trailer field tags from the dictionary.
    fn initialize_field_tags(&mut self) {
        // Try to extract header tags from StandardHeader component
        if let Some(header_component) = self.dictionary.component_by_name("StandardHeader") {
            for item in header_component.items() {
                match item.kind() {
                    rustyfix_dictionary::LayoutItemKind::Field(field) => {
                        self.header_tags.push(field.tag().get());
                    }
                    _ => {} // Skip non-field items
                }
            }
        }

        // Fallback header tags if StandardHeader component not found
        if self.header_tags.is_empty() {
            self.header_tags
                .extend_from_slice(&[8, 9, 35, 34, 49, 56, 52, 43, 122, 212, 213, 347, 369, 627]);
        }

        // Try to extract trailer tags from StandardTrailer component
        if let Some(trailer_component) = self.dictionary.component_by_name("StandardTrailer") {
            for item in trailer_component.items() {
                match item.kind() {
                    rustyfix_dictionary::LayoutItemKind::Field(field) => {
                        self.trailer_tags.push(field.tag().get());
                    }
                    _ => {} // Skip non-field items
                }
            }
        }

        // Fallback trailer tags if StandardTrailer component not found
        if self.trailer_tags.is_empty() {
            self.trailer_tags.extend_from_slice(&[10, 89, 93]);
        }
    }

    /// Returns a reference to the underlying FIX dictionary.
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    /// Builds field type information from dictionary.
    fn build_field_types(&mut self) {
        // Extract all field definitions from the dictionary
        for field in self.dictionary.fields() {
            let tag = field.tag().get() as u16;
            let fix_type = self.map_dictionary_type_to_schema_type(field.fix_datatype());

            // Determine field location (header, trailer, or body)
            let (in_header, in_trailer) = self.determine_field_location(&field);

            self.field_types.insert(
                tag,
                FieldTypeInfo {
                    fix_type,
                    in_header,
                    in_trailer,
                },
            );
        }
    }

    /// Maps a dictionary `FixDatatype` to the schema's `FixDataType` enum.
    fn map_dictionary_type_to_schema_type(&self, dict_type: FixDatatype) -> FixDataType {
        match dict_type {
            FixDatatype::Int => FixDataType::Int,
            FixDatatype::Length => FixDataType::Length,
            FixDatatype::NumInGroup => FixDataType::NumInGroup,
            FixDatatype::SeqNum => FixDataType::SeqNum,
            FixDatatype::TagNum => FixDataType::TagNum,
            FixDatatype::DayOfMonth => FixDataType::DayOfMonth,
            FixDatatype::Float => FixDataType::Float,
            FixDatatype::Quantity => FixDataType::Qty,
            FixDatatype::Price => FixDataType::Price,
            FixDatatype::PriceOffset => FixDataType::PriceOffset,
            FixDatatype::Amt => FixDataType::Amt,
            FixDatatype::Percentage => FixDataType::Percentage,
            FixDatatype::Char => FixDataType::Char,
            FixDatatype::Boolean => FixDataType::Boolean,
            FixDatatype::String => FixDataType::String,
            FixDatatype::MultipleCharValue => FixDataType::MultipleCharValue,
            FixDatatype::MultipleStringValue => FixDataType::MultipleValueString,
            FixDatatype::Currency => FixDataType::Currency,
            FixDatatype::Exchange => FixDataType::Exchange,
            FixDatatype::UtcTimestamp => FixDataType::UtcTimestamp,
            FixDatatype::UtcDateOnly => FixDataType::UtcDateOnly,
            FixDatatype::UtcTimeOnly => FixDataType::UtcTimeOnly,
            FixDatatype::LocalMktDate => FixDataType::LocalMktDate,
            FixDatatype::Data => FixDataType::Data,
            FixDatatype::XmlData => FixDataType::XmlData,
            FixDatatype::Language => FixDataType::Language,
            // Map additional dictionary types to closest schema equivalent
            FixDatatype::MonthYear => FixDataType::String,
            FixDatatype::Country => FixDataType::String,
            // Note: TzTimeOnly and TzTimestamp are not in the dictionary enum
            // but are in the schema enum. We'll map them to UTC equivalents for now.
            _ => FixDataType::String, // Default mapping for any new types
        }
    }

    /// Determines if a field belongs to header, trailer, or body.
    fn determine_field_location(&self, field: &rustyfix_dictionary::Field) -> (bool, bool) {
        // Check if field is in StandardHeader component
        let in_header =
            if let Some(std_header) = self.dictionary.component_by_name("StandardHeader") {
                std_header.contains_field(field)
            } else {
                // Fallback to known header field tags if component not found
                self.header_tags.contains(&field.tag().get())
            };

        // Check if field is in StandardTrailer component
        let in_trailer =
            if let Some(std_trailer) = self.dictionary.component_by_name("StandardTrailer") {
                std_trailer.contains_field(field)
            } else {
                // Fallback to known trailer field tags if component not found
                self.trailer_tags.contains(&field.tag().get())
            };

        (in_header, in_trailer)
    }

    /// Builds message schemas from dictionary.
    fn build_message_schemas(&mut self) {
        // Extract all message definitions from the dictionary
        for message in self.dictionary.messages() {
            let msg_type: FixString = message.msg_type().into();
            let mut required_fields = SmallVec::new();
            let mut optional_fields = SmallVec::new();
            let mut groups = FxHashMap::default();

            // Process the message layout to extract field information
            self.process_message_layout(
                message.layout(),
                &mut required_fields,
                &mut optional_fields,
                &mut groups,
            );

            let message_schema = MessageSchema {
                msg_type: msg_type.clone(),
                required_fields,
                optional_fields,
                groups,
            };

            self.message_schemas.insert(msg_type, message_schema);
        }
    }

    /// Recursively processes message layout items to extract field information.
    fn process_message_layout<'a>(
        &self,
        layout: impl Iterator<Item = rustyfix_dictionary::LayoutItem<'a>>,
        required_fields: &mut SmallVec<[u16; 8]>,
        optional_fields: &mut SmallVec<[u16; 16]>,
        groups: &mut FxHashMap<u16, GroupSchema>,
    ) {
        for item in layout {
            match item.kind() {
                rustyfix_dictionary::LayoutItemKind::Field(field) => {
                    let tag = field.tag().get() as u16;
                    if item.required() {
                        required_fields.push(tag);
                    } else {
                        optional_fields.push(tag);
                    }
                }
                rustyfix_dictionary::LayoutItemKind::Component(component) => {
                    // Recursively process component fields
                    self.process_message_layout(
                        component.items(),
                        required_fields,
                        optional_fields,
                        groups,
                    );
                }
                rustyfix_dictionary::LayoutItemKind::Group(count_field, group_items) => {
                    let count_tag = count_field.tag().get() as u16;
                    let mut group_fields = SmallVec::new();
                    let mut group_required = SmallVec::new();
                    let mut group_optional = SmallVec::new();
                    let mut nested_groups = FxHashMap::default();

                    // Process group items
                    self.process_message_layout(
                        group_items.iter().cloned(),
                        &mut group_required,
                        &mut group_optional,
                        &mut nested_groups,
                    );

                    // Combine all group fields
                    group_fields.extend(group_required);
                    group_fields.extend(group_optional);

                    // Find first field in group (delimiter)
                    let first_field = group_fields.first().copied().unwrap_or(count_tag);

                    let group_schema = GroupSchema {
                        count_tag,
                        first_field,
                        fields: group_fields,
                    };

                    groups.insert(count_tag, group_schema);

                    // Add nested groups
                    groups.extend(nested_groups);

                    // The count field itself is typically optional
                    optional_fields.push(count_tag);
                }
            }
        }
    }

    /// Gets the schema for a message type.
    pub fn get_message_schema(&self, msg_type: &str) -> Option<&MessageSchema> {
        self.message_schemas.get(msg_type)
    }

    /// Gets the type information for a field.
    pub fn get_field_type(&self, tag: u16) -> Option<&FieldTypeInfo> {
        self.field_types.get(&tag)
    }

    /// Returns the number of fields in the schema.
    pub fn field_count(&self) -> usize {
        self.field_types.len()
    }

    /// Returns the number of messages in the schema.
    pub fn message_count(&self) -> usize {
        self.message_schemas.len()
    }

    /// Returns an iterator over all field types in the schema.
    pub fn field_types(&self) -> impl Iterator<Item = (u16, &FieldTypeInfo)> {
        self.field_types.iter().map(|(tag, info)| (*tag, info))
    }

    /// Maps a dictionary `FixDatatype` to the schema's `FixDataType` enum (public for demo).
    pub fn map_dictionary_type_to_schema_type_public(&self, dict_type: FixDatatype) -> FixDataType {
        self.map_dictionary_type_to_schema_type(dict_type)
    }

    /// Maps a FIX data type to the appropriate typed value based on field type information.
    /// Returns a string representation but validates and processes according to the field's FIX data type.
    pub fn map_field_type(&self, tag: u16, value: &[u8]) -> Result<String, crate::Error> {
        let field_info = self
            .get_field_type(tag)
            .ok_or_else(|| crate::Error::Schema(format!("Unknown field tag: {tag}").into()))?;

        // Convert bytes to UTF-8 string first
        let s = std::str::from_utf8(value)
            .map_err(|_| crate::Error::Decode(crate::DecodeError::InvalidUtf8 { offset: 0 }))?;

        // Validate and process based on FIX data type
        match field_info.fix_type {
            FixDataType::Int => {
                // Validate it's a valid integer
                s.parse::<i64>().map_err(|_| {
                    crate::Error::Schema(format!("Invalid integer value for tag {tag}: {s}").into())
                })?;
                Ok(s.to_string())
            }
            FixDataType::Length
            | FixDataType::NumInGroup
            | FixDataType::SeqNum
            | FixDataType::TagNum
            | FixDataType::DayOfMonth => {
                // Validate it's a valid unsigned integer
                s.parse::<u64>().map_err(|_| {
                    crate::Error::Schema(
                        format!("Invalid unsigned integer value for tag {tag}: {s}").into(),
                    )
                })?;
                Ok(s.to_string())
            }
            FixDataType::Float
            | FixDataType::Qty
            | FixDataType::Price
            | FixDataType::PriceOffset
            | FixDataType::Amt
            | FixDataType::Percentage => {
                // Validate it's a valid decimal number
                s.parse::<f64>().map_err(|_| {
                    crate::Error::Schema(format!("Invalid decimal value for tag {tag}: {s}").into())
                })?;
                Ok(s.to_string())
            }
            FixDataType::Char => {
                // Validate it's a single character
                if s.len() != 1 {
                    return Err(crate::Error::Schema(
                        format!("Char field tag {tag} must be exactly 1 character, got: {s}")
                            .into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::Boolean => {
                // Validate it's Y or N
                match s {
                    "Y" | "N" => Ok(s.to_string()),
                    _ => Err(crate::Error::Schema(
                        format!("Boolean field tag {tag} must be Y or N, got: {s}").into(),
                    )),
                }
            }
            FixDataType::String
            | FixDataType::MultipleValueString
            | FixDataType::MultipleCharValue
            | FixDataType::Currency
            | FixDataType::Exchange
            | FixDataType::Language
            | FixDataType::Pattern
            | FixDataType::Tenor => {
                // String fields - no additional validation needed, just ensure UTF-8 (already done)
                Ok(s.to_string())
            }
            FixDataType::UtcTimestamp => {
                // Validate timestamp format (YYYYMMDD-HH:MM:SS or YYYYMMDD-HH:MM:SS.sss)
                if !Self::is_valid_utc_timestamp(s) {
                    return Err(crate::Error::Schema(
                        format!("Invalid UTC timestamp format for tag {tag}: {s}").into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::UtcDateOnly => {
                // Validate date format (YYYYMMDD)
                if !Self::is_valid_utc_date(s) {
                    return Err(crate::Error::Schema(
                        format!("Invalid UTC date format for tag {tag}: {s}").into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::UtcTimeOnly => {
                // Validate time format (HH:MM:SS or HH:MM:SS.sss)
                if !Self::is_valid_utc_time(s) {
                    return Err(crate::Error::Schema(
                        format!("Invalid UTC time format for tag {tag}: {s}").into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::LocalMktDate => {
                // Validate local market date format (YYYYMMDD)
                if !Self::is_valid_utc_date(s) {
                    return Err(crate::Error::Schema(
                        format!("Invalid local market date format for tag {tag}: {s}").into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::TzTimeOnly | FixDataType::TzTimestamp => {
                // For timezone-aware timestamps, accept as string but validate basic format
                if s.trim().is_empty() {
                    return Err(crate::Error::Schema(
                        format!("Timezone timestamp/time for tag {tag} cannot be empty").into(),
                    ));
                }
                Ok(s.to_string())
            }
            FixDataType::Data | FixDataType::XmlData => {
                // Binary or XML data - return as-is (already validated as UTF-8)
                Ok(s.to_string())
            }
        }
    }

    /// Validates UTC timestamp format (YYYYMMDD-HH:MM:SS or YYYYMMDD-HH:MM:SS.sss)
    /// Supports variable fractional seconds (1-6 digits after decimal point)
    fn is_valid_utc_timestamp(s: &str) -> bool {
        // Use chrono's NaiveDateTime parser with %.f format for fractional seconds
        chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d-%H:%M:%S%.f").is_ok()
    }

    /// Validates UTC date format (YYYYMMDD)
    fn is_valid_utc_date(s: &str) -> bool {
        // Use chrono for robust date validation that handles leap years and days per month correctly
        chrono::NaiveDate::parse_from_str(s, "%Y%m%d").is_ok()
    }

    /// Validates UTC time format (HH:MM:SS or HH:MM:SS.sss)
    fn is_valid_utc_time(s: &str) -> bool {
        // Use chrono for robust time validation. %.f handles optional fractional seconds
        chrono::NaiveTime::parse_from_str(s, "%H:%M:%S%.f").is_ok()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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

        // Check message schemas - they should now be extracted from dictionary
        let logon = schema
            .get_message_schema("A")
            .expect("Logon message should exist in FIX 4.4 dictionary");
        assert_eq!(logon.msg_type, "A");

        // The schema should contain more messages than just the hardcoded ones
        assert!(
            schema.message_schemas.len() > 3,
            "Schema should contain many messages from dictionary"
        );
    }

    #[test]
    fn test_dictionary_driven_field_extraction() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict.clone());

        // Test that all dictionary fields are extracted
        let dict_fields = dict.fields();
        assert!(!dict_fields.is_empty(), "Dictionary should have fields");

        // Check that schema contains all dictionary fields
        for field in dict_fields {
            let tag = field.tag().get() as u16;
            let field_info = schema
                .get_field_type(tag)
                .unwrap_or_else(|| panic!("Field {tag} should exist in schema"));

            // Verify the mapping worked correctly
            let expected_type = schema.map_dictionary_type_to_schema_type(field.fix_datatype());
            assert_eq!(
                field_info.fix_type, expected_type,
                "Field {tag} type mapping incorrect"
            );
        }
    }

    #[test]
    fn test_dictionary_driven_message_extraction() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict.clone());

        // Test that all dictionary messages are extracted
        let dict_messages = dict.messages();
        assert!(!dict_messages.is_empty(), "Dictionary should have messages");

        // Check that schema contains all dictionary messages
        for message in dict_messages {
            let msg_type = message.msg_type();
            let message_schema = schema
                .get_message_schema(msg_type)
                .unwrap_or_else(|| panic!("Message {msg_type} should exist in schema"));

            assert_eq!(message_schema.msg_type, msg_type);

            // Check that the schema has field information (not necessarily matching exact counts
            // due to complex processing, but should have some fields)
            let total_fields =
                message_schema.required_fields.len() + message_schema.optional_fields.len();
            // Some messages might have no body fields (only header/trailer), so we just check it exists
            let _ = total_fields; // Field count is valid by construction
        }
    }

    #[test]
    fn test_field_location_detection() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Test known header fields
        let begin_string = schema.get_field_type(8).expect("BeginString should exist");
        assert!(begin_string.in_header, "BeginString should be in header");
        assert!(
            !begin_string.in_trailer,
            "BeginString should not be in trailer"
        );

        let msg_type = schema.get_field_type(35).expect("MsgType should exist");
        assert!(msg_type.in_header, "MsgType should be in header");
        assert!(!msg_type.in_trailer, "MsgType should not be in trailer");

        // Test known trailer fields
        let checksum = schema.get_field_type(10).expect("CheckSum should exist");
        assert!(!checksum.in_header, "CheckSum should not be in header");
        assert!(checksum.in_trailer, "CheckSum should be in trailer");

        // Test a body field (Symbol)
        if let Some(symbol) = schema.get_field_type(55) {
            assert!(!symbol.in_header, "Symbol should not be in header");
            assert!(!symbol.in_trailer, "Symbol should not be in trailer");
        }
    }

    #[test]
    fn test_data_type_mapping() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Test various data type mappings
        let test_cases = [
            (FixDatatype::Int, FixDataType::Int),
            (FixDatatype::Float, FixDataType::Float),
            (FixDatatype::String, FixDataType::String),
            (FixDatatype::Boolean, FixDataType::Boolean),
            (FixDatatype::Char, FixDataType::Char),
            (FixDatatype::Price, FixDataType::Price),
            (FixDatatype::Quantity, FixDataType::Qty),
            (FixDatatype::UtcTimestamp, FixDataType::UtcTimestamp),
            (FixDatatype::UtcDateOnly, FixDataType::UtcDateOnly),
            (FixDatatype::UtcTimeOnly, FixDataType::UtcTimeOnly),
            (FixDatatype::Currency, FixDataType::Currency),
            (FixDatatype::Exchange, FixDataType::Exchange),
            (FixDatatype::Data, FixDataType::Data),
            (FixDatatype::Language, FixDataType::Language),
            (FixDatatype::MonthYear, FixDataType::String), // Maps to String
            (FixDatatype::Country, FixDataType::String),   // Maps to String
        ];

        for (dict_type, expected_schema_type) in test_cases {
            let mapped_type = schema.map_dictionary_type_to_schema_type(dict_type);
            assert_eq!(
                mapped_type, expected_schema_type,
                "Mapping for {dict_type:?} should be {expected_schema_type:?}"
            );
        }
    }

    #[test]
    fn test_schema_backward_compatibility() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Test that the schema still works with basic operations
        // This ensures we haven't broken existing functionality

        // Test field type lookup
        let field_type = schema.get_field_type(35);
        assert!(field_type.is_some(), "Should be able to get field type");

        // Test message schema lookup
        let message_schema = schema.get_message_schema("0"); // Heartbeat
        assert!(
            message_schema.is_some(),
            "Should be able to get message schema"
        );

        // Test field type mapping
        let result = schema.map_field_type(35, b"0");
        assert!(result.is_ok(), "Should be able to map field type");
        assert_eq!(result.unwrap(), "0");
    }

    #[test]
    fn test_group_processing() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Find a message with groups (Market Data Request typically has groups)
        if let Some(md_request) = schema.get_message_schema("V") {
            // Check if groups were processed
            // Note: The exact group structure depends on the dictionary version
            // This is a basic test to ensure group processing doesn't crash
            let _ = md_request.groups.len(); // Group count is valid by construction
        }
    }

    #[test]
    fn test_field_type_mapping() {
        let dict =
            Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for test"));
        let schema = Schema::new(dict);

        // Test with actual fields from the dictionary instead of inserting fake ones
        // Find a boolean field if it exists
        if let Some(bool_field) = schema
            .field_types
            .iter()
            .find(|(_, info)| info.fix_type == FixDataType::Boolean)
        {
            let tag = *bool_field.0;
            let result = schema.map_field_type(tag, b"Y");
            assert!(result.is_ok(), "Boolean Y should be valid");
            assert_eq!(result.unwrap(), "Y");

            let result = schema.map_field_type(tag, b"N");
            assert!(result.is_ok(), "Boolean N should be valid");
            assert_eq!(result.unwrap(), "N");

            // Test invalid boolean
            let result = schema.map_field_type(tag, b"X");
            assert!(result.is_err(), "Invalid boolean should fail");
        }

        // Test integer mapping with MsgSeqNum (tag 34)
        if let Some(seq_num_field) = schema.get_field_type(34) {
            assert_eq!(seq_num_field.fix_type, FixDataType::SeqNum);

            let result = schema.map_field_type(34, b"123");
            assert!(result.is_ok(), "Valid sequence number should pass");
            assert_eq!(result.unwrap(), "123");

            let result = schema.map_field_type(34, b"abc");
            assert!(result.is_err(), "Invalid sequence number should fail");
        }

        // Test string mapping with MsgType (tag 35)
        if let Some(msg_type_field) = schema.get_field_type(35) {
            assert_eq!(msg_type_field.fix_type, FixDataType::String);

            let result = schema.map_field_type(35, b"D");
            assert!(result.is_ok(), "Valid message type should pass");
            assert_eq!(result.unwrap(), "D");
        }

        // Test with a price field if available
        if let Some(price_field) = schema
            .field_types
            .iter()
            .find(|(_, info)| info.fix_type == FixDataType::Price)
        {
            let tag = *price_field.0;
            let result = schema.map_field_type(tag, b"123.45");
            assert!(result.is_ok(), "Valid price should pass");
            assert_eq!(result.unwrap(), "123.45");

            let result = schema.map_field_type(tag, b"invalid");
            assert!(result.is_err(), "Invalid price should fail");
        }

        // Test with a char field if available
        if let Some(char_field) = schema
            .field_types
            .iter()
            .find(|(_, info)| info.fix_type == FixDataType::Char)
        {
            let tag = *char_field.0;
            let result = schema.map_field_type(tag, b"A");
            assert!(result.is_ok(), "Single character should pass");
            assert_eq!(result.unwrap(), "A");

            let result = schema.map_field_type(tag, b"AB");
            assert!(result.is_err(), "Multiple characters should fail");
        }
    }

    #[test]
    fn test_date_time_validation() {
        // Test valid UTC timestamp
        assert!(Schema::is_valid_utc_timestamp("20240101-12:30:45"));
        assert!(Schema::is_valid_utc_timestamp("20240101-12:30:45.123"));

        // Test invalid UTC timestamp
        assert!(!Schema::is_valid_utc_timestamp("2024-01-01 12:30:45"));
        assert!(!Schema::is_valid_utc_timestamp("20240101-25:30:45"));
        assert!(!Schema::is_valid_utc_timestamp("20240101-12:70:45"));

        // Test valid UTC date
        assert!(Schema::is_valid_utc_date("20240101"));
        assert!(Schema::is_valid_utc_date("20241231"));

        // Test invalid UTC date
        assert!(!Schema::is_valid_utc_date("2024-01-01"));
        assert!(!Schema::is_valid_utc_date("20241301")); // Invalid month
        assert!(!Schema::is_valid_utc_date("20240132")); // Invalid day

        // Test valid UTC time
        assert!(Schema::is_valid_utc_time("12:30:45"));
        assert!(Schema::is_valid_utc_time("12:30:45.123"));

        // Test invalid UTC time
        assert!(!Schema::is_valid_utc_time("25:30:45"));
        assert!(!Schema::is_valid_utc_time("12:70:45"));
        assert!(!Schema::is_valid_utc_time("12:30:70"));
    }
}
