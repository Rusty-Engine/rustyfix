//! Generated ASN.1 definitions from FIX dictionaries.
//!
//! This module contains automatically generated ASN.1 type definitions
//! based on FIX protocol dictionaries. The definitions are created at
//! build time by the build script.

// Include generated definitions for FIX 4.4 (always available)
include!(concat!(env!("OUT_DIR"), "/fix44_asn1.rs"));

// Include other FIX versions based on feature flags
#[cfg(feature = "fix40")]
pub mod fix40 {
    //! ASN.1 definitions for FIX 4.0
    include!(concat!(env!("OUT_DIR"), "/fix40_asn1.rs"));
}

#[cfg(feature = "fix50")]
pub mod fix50 {
    //! ASN.1 definitions for FIX 5.0 SP2
    include!(concat!(env!("OUT_DIR"), "/fix50_asn1.rs"));
}

// Types are directly available from the included generated code

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Field, FixMessage};

    #[test]
    fn test_message_type_conversion() {
        // Test conversion from string
        assert_eq!(
            FixMessageType::from_str("D")
                .expect("Failed to parse valid message type 'D'")
                .as_str(),
            "D"
        );

        // Test conversion to string
        let msg_type =
            FixMessageType::from_str("8").expect("Failed to parse valid message type '8'");
        assert_eq!(msg_type.as_str(), "8");

        // Test invalid message type
        assert!(FixMessageType::from_str("INVALID").is_none());
    }

    #[test]
    fn test_field_tag_conversion() {
        // Test conversion from u32
        if let Some(tag) = FixFieldTag::from_u32(35) {
            assert_eq!(tag.as_u32(), 35);
            assert_eq!(u32::from(tag), 35u32);
        }

        // Test invalid tag
        assert!(FixFieldTag::from_u32(99999).is_none());
    }

    #[test]
    fn test_asn1_message_conversion() {
        let fix_msg = FixMessage {
            msg_type: "D".to_string(),
            sender_comp_id: "SENDER".to_string(),
            target_comp_id: "TARGET".to_string(),
            msg_seq_num: 123,
            fields: vec![Field {
                tag: 55,
                value: "EUR/USD".to_string(),
            }],
        };

        // Convert to ASN.1 format
        let asn1_msg = Asn1FixMessage::from_fix_message(&fix_msg)
            .expect("Failed to convert valid FIX message to ASN.1");
        assert_eq!(asn1_msg.msg_type.as_str(), "D");
        assert_eq!(asn1_msg.sender_comp_id, "SENDER");
        assert_eq!(asn1_msg.msg_seq_num, 123);
        assert_eq!(asn1_msg.fields.len(), 1);

        // Convert back to simple format
        let converted_back = asn1_msg.to_fix_message();
        assert_eq!(converted_back.msg_type, fix_msg.msg_type);
        assert_eq!(converted_back.sender_comp_id, fix_msg.sender_comp_id);
        assert_eq!(converted_back.msg_seq_num, fix_msg.msg_seq_num);
        assert_eq!(converted_back.fields.len(), fix_msg.fields.len());
    }
}
