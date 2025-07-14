# RustyASN

Abstract Syntax Notation One (ASN.1) encoding support for the RustyFix FIX protocol implementation.

## Features

- Multiple encoding rules: BER, DER, OER
- Zero-copy decoding where possible
- Streaming support for continuous message processing
- Type-safe ASN.1 schema compilation
- High-performance implementation optimized for low-latency trading
- Integration with RustyFix field types and dictionaries

## Supported Encoding Rules

- **BER** (Basic Encoding Rules) - Self-describing, flexible format
- **DER** (Distinguished Encoding Rules) - Canonical subset of BER, deterministic encoding
- **OER** (Octet Encoding Rules) - Byte-aligned, balance between efficiency and simplicity

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
rustyasn = "0.7.4"
```

### Basic Encoding/Decoding

```rust
use rustyasn::{Config, Encoder, Decoder, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

fn basic_example() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let dict = Arc::new(Dictionary::fix44()?);
    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());
    let decoder = Decoder::new(config, dict);

    // Encode a message
    let mut handle = encoder.start_message(
        "D",           // MsgType: NewOrderSingle
        "SENDER001",   // SenderCompID
        "TARGET001",   // TargetCompID
        1,             // MsgSeqNum
    );

    handle
        .add_string(11, "CL001")      // ClOrdID
        .add_string(55, "EUR/USD")    // Symbol
        .add_int(54, 1)               // Side (1=Buy)
        .add_uint(38, 1_000_000)      // OrderQty
        .add_string(52, "20240101-12:00:00"); // SendingTime

    let encoded = handle.encode()?;

    // Decode the message
    let decoded = decoder.decode(&encoded)?;
    assert_eq!(decoded.msg_type(), "D");
    assert_eq!(decoded.get_string(55), Some("EUR/USD".to_string()));
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_example() {
        basic_example().expect("Basic example should work");
    }
}
```

### Streaming Decoder

```rust
use rustyasn::{Config, Encoder, DecoderStreaming, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::sync::Arc;

fn streaming_example() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let dict = Arc::new(Dictionary::fix44()?);
    let config = Config::new(EncodingRule::DER);
    
    // Create some test messages first using the encoder
    let encoder = Encoder::new(config.clone(), dict.clone());
    let mut test_messages = Vec::new();
    
    for seq_num in 1..=3 {
        let mut handle = encoder.start_message("0", "SENDER", "TARGET", seq_num);
        handle.add_string(112, format!("TestID_{}", seq_num)); // TestReqID
        let encoded = handle.encode()?;
        test_messages.extend_from_slice(&encoded);
    }
    
    // Now demonstrate streaming decoding
    let mut decoder = DecoderStreaming::new(config, dict);

    // Simulate feeding data in chunks (as would happen from network/file)
    let chunk_size = test_messages.len() / 3; // Split into 3 chunks
    for chunk in test_messages.chunks(chunk_size) {
        decoder.feed(chunk);
        
        // Process any complete messages that have been decoded
        while let Ok(Some(message)) = decoder.decode_next() {
            println!("Received: {} from {} (seq: {})", 
                message.msg_type(), 
                message.sender_comp_id(),
                message.msg_seq_num()
            );
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_example() {
        streaming_example().expect("Streaming example should work");
    }
}
```

### Configuration Profiles

```rust
use rustyasn::{Config, EncodingRule};

fn configuration_examples() {
    // Optimized for low-latency trading
    let low_latency_config = Config::low_latency();  // Uses OER, skips validation
    println!("Low latency rule: {:?}", low_latency_config.encoding_rule);
    
    // Optimized for reliability and compliance
    let high_reliability_config = Config::high_reliability();  // Uses DER, full validation
    println!("High reliability rule: {:?}", high_reliability_config.encoding_rule);
    
    // Custom configuration
    let mut custom_config = Config::new(EncodingRule::OER);
    custom_config.max_message_size = 16 * 1024;  // 16KB limit
    custom_config.enable_zero_copy = true;
    custom_config.validate_checksums = false;    // Disable for performance
    
    println!("Custom config max size: {} bytes", custom_config.max_message_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_examples() {
        configuration_examples(); // Should run without panicking
    }
}
```

## Performance Considerations

1. **Encoding Rule Selection**:
   - OER: Most compact of supported rules, best for low-latency
   - DER: Deterministic, best for audit trails
   - BER: Most flexible, larger size

2. **Zero-Copy Operations**: Enable with `config.enable_zero_copy = true`

3. **Buffer Management**: Pre-allocate buffers for streaming operations

4. **Validation**: Disable checksum validation in low-latency scenarios

## Integration with SOFH

RustyASN integrates with Simple Open Framing Header (SOFH) for message framing:

```rust
use rustyasn::EncodingRule;

// SOFH encoding type enum for demonstration (would come from rustysofh crate)
#[derive(Debug)]
enum EncodingType {
    Asn1BER,
    Asn1OER,
}

fn sofh_integration_example(rule: EncodingRule) -> EncodingType {
    // SOFH encoding types for ASN.1
    match rule {
        EncodingRule::BER | EncodingRule::DER => EncodingType::Asn1BER,
        EncodingRule::OER => EncodingType::Asn1OER,
    }
}

fn main() {
    let ber_encoding = sofh_integration_example(EncodingRule::BER);
    let oer_encoding = sofh_integration_example(EncodingRule::OER);
    
    println!("BER/DER uses: {:?}", ber_encoding);
    println!("OER uses: {:?}", oer_encoding);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sofh_integration() {
        main(); // Should run without panicking
    }
}
```

## Safety and Security

- Maximum message size limits prevent DoS attacks
- Recursion depth limits prevent stack overflow
- Input validation for all field types
- Safe parsing of untrusted input

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.

