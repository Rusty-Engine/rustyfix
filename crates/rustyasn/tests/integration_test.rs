//! Integration tests for RustyASN encoding and decoding.

use rustyasn::{Config, Decoder, Encoder, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

#[test]
fn test_basic_encoding_decoding() -> Result<(), Box<dyn std::error::Error>> {
    let dict = Arc::new(
        Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for integration test"),
    );

    // Test each encoding rule
    let encoding_rules = [EncodingRule::BER, EncodingRule::DER, EncodingRule::OER];

    for rule in encoding_rules {
        let config = Config::new(rule);
        let encoder = Encoder::new(config.clone(), dict.clone());
        let decoder = Decoder::new(config, dict.clone());

        // Create a simple message
        let mut handle = encoder.start_message("D", "SENDER", "TARGET", 1);

        handle
            .add_string(11, "CL001") // ClOrdID
            .add_string(55, "EUR/USD") // Symbol
            .add_int(54, 1) // Side (1=Buy)
            .add_uint(38, 1_000_000); // OrderQty

        let encoded = handle.encode().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Encoding should succeed but failed: {e}"))
        })?;

        // Decode the message
        let decoded = decoder.decode(&encoded).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Decoding should succeed but failed: {e}"))
        })?;

        // Verify standard fields
        assert_eq!(decoded.msg_type(), "D");
        assert_eq!(decoded.sender_comp_id(), "SENDER");
        assert_eq!(decoded.target_comp_id(), "TARGET");
        assert_eq!(decoded.msg_seq_num(), 1);

        // Verify custom fields
        assert_eq!(decoded.get_string(11), Some("CL001".to_string()));
        assert_eq!(decoded.get_string(55), Some("EUR/USD".to_string()));

        let parsed_int = decoded.get_int(54).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Should parse int but failed: {e}"))
        })?;
        assert_eq!(parsed_int, Some(1));

        let parsed_uint = decoded.get_uint(38).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Should parse uint but failed: {e}"))
        })?;
        assert_eq!(parsed_uint, Some(1_000_000));
    }

    Ok(())
}

#[test]
fn test_streaming_decoder() -> Result<(), Box<dyn std::error::Error>> {
    let dict = Arc::new(
        Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for integration test"),
    );
    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());
    let mut decoder = rustyasn::DecoderStreaming::new(config, dict.clone());

    // Encode multiple messages
    let mut messages = Vec::new();
    for i in 1..=3 {
        let mut handle = encoder.start_message(
            "0", // Heartbeat
            "SENDER", "TARGET", i,
        );

        if i == 2 {
            handle.add_string(112, "TEST123"); // TestReqID
        }

        let encoded = handle.encode().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Encoding should succeed but failed: {e}"))
        })?;
        messages.push(encoded);
    }

    // Feed messages to streaming decoder
    for (i, msg_data) in messages.iter().enumerate() {
        // Feed data in chunks to test buffering
        let mid = msg_data.len() / 2;
        decoder.feed(&msg_data[..mid]);

        // Should not have a complete message yet
        let first_decode = decoder.decode_next().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("First decode_next() failed: {e}"))
        })?;
        assert!(first_decode.is_none());

        // Feed rest of data
        decoder.feed(&msg_data[mid..]);

        // Now should have a complete message
        let decoded = decoder
            .decode_next()
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Second decode_next() failed: {e}"))
            })?
            .ok_or_else(|| {
                Box::<dyn std::error::Error>::from("Should have a message but got None")
            })?;

        assert_eq!(decoded.msg_type(), "0");
        assert_eq!(decoded.msg_seq_num(), (i + 1) as u64);

        if i == 1 {
            assert_eq!(decoded.get_string(112), Some("TEST123".to_string()));
        }
    }

    // No more messages
    let final_decode = decoder.decode_next().map_err(|e| {
        Box::<dyn std::error::Error>::from(format!("Final decode_next() failed: {e}"))
    })?;
    assert!(final_decode.is_none());

    Ok(())
}

#[test]
fn test_message_size_limits() {
    let dict = Arc::new(
        Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for integration test"),
    );
    let mut config = Config::new(EncodingRule::BER);
    config.max_message_size = 100; // Very small limit

    let encoder = Encoder::new(config.clone(), dict.clone());
    let _decoder = Decoder::new(config, dict.clone());

    let mut handle = encoder.start_message("D", "SENDER", "TARGET", 1);

    // Add many fields to exceed size limit
    for i in 0..50 {
        handle.add_string(1000 + i, format!("Field value {i}"));
    }

    // Encoding should fail due to size limit
    let result = handle.encode();
    assert!(result.is_err());
}

#[test]
fn test_field_types() -> Result<(), Box<dyn std::error::Error>> {
    let dict = Arc::new(
        Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for integration test"),
    );
    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());
    let decoder = Decoder::new(config, dict.clone());

    let mut handle = encoder.start_message(
        "8", // ExecutionReport
        "EXCHANGE", "CLIENT", 42,
    );

    // Test various field types
    handle
        .add_bool(114, true) // LocateReqd
        .add_string(95, "test_data") // SecureData
        .add_int(31, -100) // LastPx (negative)
        .add_uint(14, 500_000); // CumQty

    let encoded = handle
        .encode()
        .map_err(|e| format!("Encoding should succeed but failed: {e}"))?;
    let decoded = decoder
        .decode(&encoded)
        .map_err(|e| format!("Decoding should succeed but failed: {e}"))?;

    assert_eq!(decoded.get_bool(114), Some(true));
    assert_eq!(decoded.get_string(95), Some("test_data".to_string()));

    let parsed_int = decoded.get_int(31).map_err(|e| {
        Box::<dyn std::error::Error>::from(format!("Should parse int but failed: {e}"))
    })?;
    assert_eq!(parsed_int, Some(-100));

    let parsed_uint = decoded.get_uint(14).map_err(|e| {
        Box::<dyn std::error::Error>::from(format!("Should parse uint but failed: {e}"))
    })?;
    assert_eq!(parsed_uint, Some(500_000));

    Ok(())
}

#[test]
fn test_encoding_rule_performance_profiles() {
    let _dict = Arc::new(
        Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for integration test"),
    );

    // Low latency configuration should use OER
    let low_latency = Config::low_latency();
    assert_eq!(low_latency.encoding_rule, EncodingRule::OER);
    assert!(!low_latency.validate_checksums);

    // High reliability should use DER
    let high_reliability = Config::high_reliability();
    assert_eq!(high_reliability.encoding_rule, EncodingRule::DER);
    assert!(high_reliability.validate_checksums);
}
