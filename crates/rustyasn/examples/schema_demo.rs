//! Demonstrates the new dictionary-driven schema architecture in rustyasn.
//!
//! This example shows how the schema now dynamically extracts field types and
//! message structures from FIX dictionaries instead of using hardcoded definitions.

use rustyasn::schema::Schema;
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== RustyASN Schema Architecture Demo ===\n");

    // Load FIX 4.4 dictionary
    let dict = Arc::new(Dictionary::fix44()?);
    println!(
        "Loaded FIX 4.4 dictionary with {} fields and {} messages",
        dict.fields().len(),
        dict.messages().len()
    );

    // Create schema with dictionary-driven architecture
    let schema = Schema::new(dict.clone());

    // Demo 1: Field type extraction from dictionary
    println!("\n1. Dictionary-driven field type extraction:");
    println!("   Total fields in schema: {}", schema.field_count());

    // Show some example field mappings
    let example_fields = [
        (8, "BeginString"),
        (35, "MsgType"),
        (34, "MsgSeqNum"),
        (49, "SenderCompID"),
        (56, "TargetCompID"),
        (52, "SendingTime"),
    ];

    for (tag, name) in example_fields {
        if let Some(field_type) = schema.get_field_type(tag) {
            println!(
                "   Field {} ({}): {:?}, Header: {}, Trailer: {}",
                tag, name, field_type.fix_type, field_type.in_header, field_type.in_trailer
            );
        }
    }

    // Demo 2: Message schema extraction from dictionary
    println!("\n2. Dictionary-driven message schema extraction:");
    println!("   Total messages in schema: {}", schema.message_count());

    // Show some example messages
    let example_messages = [
        ("0", "Heartbeat"),
        ("1", "TestRequest"),
        ("A", "Logon"),
        ("D", "NewOrderSingle"),
        ("8", "ExecutionReport"),
        ("V", "MarketDataRequest"),
    ];

    for (msg_type, name) in example_messages {
        if let Some(message_schema) = schema.get_message_schema(msg_type) {
            println!(
                "   Message {} ({}): {} required fields, {} optional fields, {} groups",
                msg_type,
                name,
                message_schema.required_fields.len(),
                message_schema.optional_fields.len(),
                message_schema.groups.len()
            );

            // Show first few fields for this message
            if !message_schema.required_fields.is_empty() {
                let required_sample: Vec<u16> = message_schema
                    .required_fields
                    .iter()
                    .take(3)
                    .cloned()
                    .collect();
                println!("     Required fields (sample): {required_sample:?}");
            }

            if !message_schema.groups.is_empty() {
                println!(
                    "     Groups: {:?}",
                    message_schema.groups.keys().collect::<Vec<_>>()
                );
            }
        }
    }

    // Demo 3: Field type validation
    println!("\n3. Field type validation:");

    // Test various field types
    let test_cases = [
        (35, "D".as_bytes(), "MsgType (string)"),
        (34, "123".as_bytes(), "MsgSeqNum (sequence number)"),
        (
            52,
            "20240101-12:30:45".as_bytes(),
            "SendingTime (UTC timestamp)",
        ),
        (8, "FIX.4.4".as_bytes(), "BeginString (string)"),
    ];

    for (tag, value, description) in test_cases {
        match schema.map_field_type(tag, value) {
            Ok(mapped_value) => {
                println!("   ✓ {description} -> {mapped_value}");
            }
            Err(e) => {
                println!("   ✗ {description} -> Error: {e}");
            }
        }
    }

    // Demo 4: Data type mapping
    println!("\n4. Data type mapping from dictionary to schema:");

    // Show how dictionary types are mapped to schema types
    use rustyfix_dictionary::FixDatatype;

    let type_examples = [
        (FixDatatype::String, "String"),
        (FixDatatype::Int, "Integer"),
        (FixDatatype::Float, "Float"),
        (FixDatatype::Price, "Price"),
        (FixDatatype::Quantity, "Quantity"),
        (FixDatatype::UtcTimestamp, "UTC Timestamp"),
        (FixDatatype::Boolean, "Boolean"),
        (FixDatatype::Char, "Character"),
    ];

    for (dict_type, name) in type_examples {
        let schema_type = schema.map_dictionary_type_to_schema_type_public(dict_type);
        println!("   {name} -> {schema_type:?}");
    }

    // Demo 5: Header/Trailer field detection
    println!("\n5. Header/Trailer field detection:");

    let header_fields: Vec<u16> = schema
        .field_types()
        .filter(|(_, info)| info.in_header)
        .map(|(tag, _)| tag)
        .take(10)
        .collect();

    let trailer_fields: Vec<u16> = schema
        .field_types()
        .filter(|(_, info)| info.in_trailer)
        .map(|(tag, _)| tag)
        .collect();

    println!("   Header fields (sample): {header_fields:?}");
    println!("   Trailer fields: {trailer_fields:?}");

    println!("\n=== Summary ===");
    println!("The schema architecture has been successfully upgraded to:");
    println!("• Extract ALL field definitions from the FIX dictionary");
    println!("• Extract ALL message structures from the FIX dictionary");
    println!("• Dynamically map dictionary types to schema types");
    println!("• Automatically detect header/trailer field locations");
    println!("• Process repeating groups from message layouts");
    println!("• Maintain full backward compatibility with existing APIs");

    Ok(())
}
