//! Basic ASN.1 encoding and decoding example.
//!
//! This example demonstrates the fundamental usage of the rustyasn crate for
//! encoding and decoding FIX protocol messages with ASN.1 encoding.

use rustyasn::{Config, Decoder, Encoder, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    basic_example()
}

fn basic_example() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let dict = Arc::new(Dictionary::fix44()?);
    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());
    let decoder = Decoder::new(config, dict);

    // Encode a message
    let mut handle = encoder.start_message(
        "D",         // MsgType: NewOrderSingle
        "SENDER001", // SenderCompID
        "TARGET001", // TargetCompID
        1,           // MsgSeqNum
    );

    handle
        .add_string(11, "CL001") // ClOrdID
        .add_string(55, "EUR/USD") // Symbol
        .add_int(54, 1) // Side (1=Buy)
        .add_uint(38, 1_000_000) // OrderQty
        .add_string(52, "20240101-12:00:00"); // SendingTime

    let encoded = handle.encode()?;
    println!("Encoded message size: {} bytes", encoded.len());

    // Decode the message
    let decoded = decoder.decode(&encoded)?;
    println!("Decoded message type: {}", decoded.msg_type());
    println!("Symbol: {:?}", decoded.get_string(55));
    println!("ClOrdID: {:?}", decoded.get_string(11));

    // Verify the decoded fields
    assert_eq!(decoded.msg_type(), "D");
    assert_eq!(decoded.get_string(55), Some("EUR/USD".to_string()));
    assert_eq!(decoded.get_string(11), Some("CL001".to_string()));

    println!("✓ Basic encoding/decoding successful!");

    Ok(())
}
