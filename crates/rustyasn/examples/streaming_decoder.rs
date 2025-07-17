//! Streaming ASN.1 decoder example.
//!
//! This example demonstrates how to use the streaming decoder to process
//! multiple messages from a continuous stream of data, as would happen
//! when reading from a network connection or file.

use rustyasn::{Config, DecoderStreaming, Encoder, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    streaming_example()
}

fn streaming_example() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let dict = Arc::new(Dictionary::fix44()?);
    let config = Config::new(EncodingRule::DER);

    // Create some test messages first using the encoder
    let encoder = Encoder::new(config.clone(), dict.clone());
    let mut test_messages = Vec::new();

    println!("Creating test messages...");
    for seq_num in 1..=3 {
        let mut handle = encoder.start_message("0", "SENDER", "TARGET", seq_num);
        handle.add_string(112, format!("TestID_{seq_num}")); // TestReqID
        let encoded = handle.encode()?;
        test_messages.extend_from_slice(&encoded);
        println!("  Message {}: {} bytes", seq_num, encoded.len());
    }

    println!("\nTotal test data size: {} bytes", test_messages.len());

    // Now demonstrate streaming decoding
    let mut decoder = DecoderStreaming::new(config, dict);
    let mut messages_decoded = 0;

    // Simulate feeding data in chunks (as would happen from network/file)
    let chunk_size = std::cmp::max(1, test_messages.len() / 3); // Split into 3 chunks
    println!("\nProcessing data in chunks of {chunk_size} bytes...");

    for (chunk_idx, chunk) in test_messages.chunks(chunk_size).enumerate() {
        println!(
            "  Processing chunk {}: {} bytes",
            chunk_idx + 1,
            chunk.len()
        );
        decoder.feed(chunk);

        // Process any complete messages that have been decoded
        while let Ok(Some(message)) = decoder.decode_next() {
            messages_decoded += 1;
            println!(
                "    Decoded message: {} from {} (seq: {})",
                message.msg_type(),
                message.sender_comp_id(),
                message.msg_seq_num()
            );

            // Show TestReqID if present
            if let Some(test_req_id) = message.get_string(112) {
                println!("      TestReqID: {test_req_id}");
            }
        }
    }

    println!("\n✓ Streaming decoding complete!");
    println!("Total messages decoded: {messages_decoded}");

    Ok(())
}
