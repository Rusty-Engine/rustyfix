//! Integration tests for RustyASN encoding and decoding.

use rustyasn::{Config, Decoder, Encoder, EncodingRule};
use rustyfix::Dictionary;
use std::sync::Arc;

#[test]
fn test_basic_encoding_decoding() {
    let dict = Arc::new(Dictionary::fix44().unwrap());

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

        let encoded = handle.encode().expect("Encoding should succeed");

        // Decode the message
        let decoded = decoder.decode(&encoded).expect("Decoding should succeed");

        // Verify standard fields
        assert_eq!(decoded.msg_type(), "D");
        assert_eq!(decoded.sender_comp_id(), "SENDER");
        assert_eq!(decoded.target_comp_id(), "TARGET");
        assert_eq!(decoded.msg_seq_num(), 1);

        // Verify custom fields
        assert_eq!(decoded.get_string(11), Some("CL001"));
        assert_eq!(decoded.get_string(55), Some("EUR/USD"));
        assert_eq!(decoded.get_int(54), Some(1));
        assert_eq!(decoded.get_uint(38), Some(1_000_000));
    }
}

#[test]
fn test_streaming_decoder() {
    let dict = Arc::new(Dictionary::fix44().unwrap());
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

        let encoded = handle.encode().expect("Encoding should succeed");
        messages.push(encoded);
    }

    // Feed messages to streaming decoder
    for (i, msg_data) in messages.iter().enumerate() {
        // Feed data in chunks to test buffering
        let mid = msg_data.len() / 2;
        decoder.feed(&msg_data[..mid]);

        // Should not have a complete message yet
        assert!(decoder.decode_next().unwrap().is_none());

        // Feed rest of data
        decoder.feed(&msg_data[mid..]);

        // Now should have a complete message
        let decoded = decoder
            .decode_next()
            .expect("Decoding should succeed")
            .expect("Should have a message");

        assert_eq!(decoded.msg_type(), "0");
        assert_eq!(decoded.msg_seq_num(), (i + 1) as u64);

        if i == 1 {
            assert_eq!(decoded.get_string(112), Some("TEST123"));
        }
    }

    // No more messages
    assert!(decoder.decode_next().unwrap().is_none());
}

#[test]
fn test_message_size_limits() {
    let dict = Arc::new(Dictionary::fix44().unwrap());
    let mut config = Config::new(EncodingRule::BER);
    config.max_message_size = 100; // Very small limit

    let encoder = Encoder::new(config.clone(), dict.clone());
    let decoder = Decoder::new(config, dict.clone());

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
fn test_field_types() {
    let dict = Arc::new(Dictionary::fix44().unwrap());
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

    let encoded = handle.encode().expect("Encoding should succeed");
    let decoded = decoder.decode(&encoded).expect("Decoding should succeed");

    assert_eq!(decoded.get_bool(114), Some(true));
    assert_eq!(decoded.get_string(95), Some("test_data"));
    assert_eq!(decoded.get_int(31), Some(-100));
    assert_eq!(decoded.get_uint(14), Some(500_000));
}

#[test]
fn test_encoding_rule_performance_profiles() {
    let dict = Arc::new(Dictionary::fix44().unwrap());

    // Low latency configuration should use PER
    let low_latency = Config::low_latency();
    assert_eq!(low_latency.encoding_rule, EncodingRule::PER);
    assert!(!low_latency.validate_checksums);

    // High reliability should use DER
    let high_reliability = Config::high_reliability();
    assert_eq!(high_reliability.encoding_rule, EncodingRule::DER);
    assert!(high_reliability.validate_checksums);
}
