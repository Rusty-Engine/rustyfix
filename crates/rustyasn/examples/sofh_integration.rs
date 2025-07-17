//! SOFH (Simple Open Framing Header) integration example.
//!
//! This example demonstrates how RustyASN integrates with Simple Open Framing
//! Header (SOFH) for message framing in network protocols.

use rustyasn::EncodingRule;

// SOFH encoding type enum for demonstration (would come from rustysofh crate)
#[derive(Debug, Clone, Copy)]
enum EncodingType {
    Asn1BER,
    Asn1OER,
}

impl EncodingType {
    /// Get the SOFH encoding byte value
    fn to_byte(self) -> u8 {
        match self {
            EncodingType::Asn1BER => 0x53, // 'S' for ASN.1 BER/DER
            EncodingType::Asn1OER => 0x54, // 'T' for ASN.1 OER
        }
    }

    /// Get human-readable description
    fn description(self) -> &'static str {
        match self {
            EncodingType::Asn1BER => "ASN.1 BER/DER encoding",
            EncodingType::Asn1OER => "ASN.1 OER encoding",
        }
    }
}

fn main() {
    println!("=== SOFH Integration Example ===\n");

    sofh_integration_example();
}

fn sofh_integration_example() {
    println!("1. ASN.1 to SOFH Encoding Type Mapping:");

    let rules = [EncodingRule::BER, EncodingRule::DER, EncodingRule::OER];

    for rule in rules {
        let sofh_encoding = map_asn1_to_sofh(rule);
        println!(
            "   {:?} -> {:?} (0x{:02X}) - {}",
            rule,
            sofh_encoding,
            sofh_encoding.to_byte(),
            sofh_encoding.description()
        );
    }

    println!("\n2. SOFH Frame Structure:");
    println!(
        "   [Start of Message (2 bytes)] [Message Length (2 bytes)] [Encoding Type (1 byte)] [Message Payload (variable)]"
    );
    println!(
        "   0x0000                       0x1234                     0x53 (ASN.1 BER)        [ASN.1 encoded message]"
    );

    println!("\n3. Example Usage in Network Protocol:");
    demonstrate_sofh_framing();

    println!("\n✓ SOFH integration example complete!");
}

/// Map ASN.1 encoding rules to SOFH encoding types
fn map_asn1_to_sofh(rule: EncodingRule) -> EncodingType {
    match rule {
        EncodingRule::BER | EncodingRule::DER => EncodingType::Asn1BER,
        EncodingRule::OER => EncodingType::Asn1OER,
    }
}

/// Demonstrate SOFH framing for ASN.1 messages
fn demonstrate_sofh_framing() {
    // Simulate message payload
    let message_payload = vec![0x30, 0x82, 0x01, 0x23, 0x02, 0x01, 0x01]; // Example ASN.1 data
    let encoding_rule = EncodingRule::DER;

    // Create SOFH frame
    let sofh_encoding = map_asn1_to_sofh(encoding_rule);
    let frame = create_sofh_frame(&message_payload, sofh_encoding);

    println!("   Original payload: {} bytes", message_payload.len());
    println!("   SOFH frame: {} bytes", frame.len());
    println!("   Frame breakdown:");
    println!("     Start of Message: 0x{:02X}{:02X}", frame[0], frame[1]);
    println!(
        "     Message Length: {} bytes",
        u16::from_be_bytes([frame[2], frame[3]])
    );
    println!(
        "     Encoding Type: 0x{:02X} ({})",
        frame[4],
        sofh_encoding.description()
    );
    println!(
        "     Payload: {:02X?}...",
        &frame[5..std::cmp::min(10, frame.len())]
    );
}

/// Create a SOFH frame for the given payload
fn create_sofh_frame(payload: &[u8], encoding_type: EncodingType) -> Vec<u8> {
    let mut frame = Vec::new();

    // Start of Message (2 bytes) - typically 0x0000 for first message
    frame.extend_from_slice(&[0x00, 0x00]);

    // Message Length (2 bytes) - length of encoding type + payload
    let message_length = (1 + payload.len()) as u16;
    frame.extend_from_slice(&message_length.to_be_bytes());

    // Encoding Type (1 byte)
    frame.push(encoding_type.to_byte());

    // Message Payload
    frame.extend_from_slice(payload);

    frame
}
