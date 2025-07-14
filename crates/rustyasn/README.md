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
use rustyfix::Dictionary;
use std::sync::Arc;

// Setup
let dict = Arc::new(Dictionary::fix44());
let config = Config::new(EncodingRule::DER);
let encoder = Encoder::new(config.clone(), dict.clone());
let decoder = Decoder::new(config, dict);

// Encode a message
let mut handle = encoder.start_message(
    "D",           // MsgType: NewOrderSingle
    "SENDER001",   // SenderCompID
    "TARGET001",   // TargetCompID
    1,             // MsgSeqNum
    timestamp,     // SendingTime
);

handle
    .add_string(11, "CL001")      // ClOrdID
    .add_string(55, "EUR/USD")    // Symbol
    .add_int(54, 1)               // Side (1=Buy)
    .add_uint(38, 1_000_000);     // OrderQty

let encoded = handle.encode()?;

// Decode the message
let decoded = decoder.decode(&encoded)?;
assert_eq!(decoded.msg_type(), "D");
assert_eq!(decoded.get_string(55), Some("EUR/USD"));
```

### Streaming Decoder

```rust
use rustyasn::{Config, DecoderStreaming, EncodingRule};

let mut decoder = DecoderStreaming::new(config, dict);

// Feed data as it arrives
decoder.feed(&data_chunk1);
decoder.feed(&data_chunk2);

// Process decoded messages
while let Some(message) = decoder.decode_next()? {
    println!("Received: {} from {}", 
        message.msg_type(), 
        message.sender_comp_id()
    );
}
```

### Configuration Profiles

```rust
// Optimized for low-latency trading
let config = Config::low_latency();  // Uses OER, skips validation

// Optimized for reliability and compliance
let config = Config::high_reliability();  // Uses DER, full validation

// Custom configuration
let mut config = Config::new(EncodingRule::OER);
config.max_message_size = 16 * 1024;  // 16KB limit
config.enable_zero_copy = true;
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
use rustysofh::EncodingType;

// SOFH encoding types for ASN.1
let encoding = match rule {
    EncodingRule::BER | EncodingRule::DER => EncodingType::Asn1BER,
    EncodingRule::OER => EncodingType::Asn1OER,
};
```

## Safety and Security

- Maximum message size limits prevent DoS attacks
- Recursion depth limits prevent stack overflow
- Input validation for all field types
- Safe parsing of untrusted input

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for details.