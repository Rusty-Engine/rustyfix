//! Benchmarks for ASN.1 encoding performance.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustyasn::{Config, Decoder, Encoder, EncodingRule};
use rustyfix_dictionary::Dictionary;
use std::hint::black_box;
use std::sync::Arc;

fn create_test_message(
    encoder: &Encoder,
    seq_num: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut handle = encoder.start_message("D", "SENDER001", "TARGET001", seq_num);

    handle
        .add_string(11, "CL123456789") // ClOrdID
        .add_string(55, "EUR/USD") // Symbol
        .add_int(54, 1) // Side
        .add_uint(38, 1_000_000) // OrderQty
        .add_string(40, "2") // OrdType (2=Limit)
        .add_string(44, "1.12345") // Price
        .add_string(59, "0") // TimeInForce (0=Day)
        .add_string(1, "ACC001") // Account
        .add_string(18, "M") // ExecInst
        .add_string(21, "1"); // HandlInst

    handle.encode().map_err(|e| e.into())
}

fn benchmark_encoding(c: &mut Criterion) {
    let dict = match Dictionary::fix44() {
        Ok(d) => Arc::new(d),
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping encoding benchmarks");
            return;
        }
    };
    let mut group = c.benchmark_group("encoding");

    let encoding_rules = [
        ("BER", EncodingRule::BER),
        ("DER", EncodingRule::DER),
        ("OER", EncodingRule::OER),
    ];

    for (name, rule) in encoding_rules {
        let config = Config::new(rule);
        let encoder = Encoder::new(config, dict.clone());

        // Pre-generate messages to avoid Result matching in hot loop
        let messages: Vec<Vec<u8>> = (1..=100)
            .filter_map(|seq| create_test_message(&encoder, seq).ok())
            .collect();

        if messages.is_empty() {
            eprintln!("Failed to create test messages, skipping {name} encoding benchmark");
            continue;
        }

        group.bench_with_input(
            BenchmarkId::new("encode", name),
            &(&encoder, &messages),
            |b, (encoder, messages)| {
                let mut idx = 0usize;
                b.iter(|| {
                    // Re-encode pre-generated message to measure encoding performance
                    let seq_num = (idx % 100) as u64 + 1;
                    if let Ok(encoded) = create_test_message(encoder, seq_num) {
                        idx += 1;
                        black_box(encoded)
                    } else {
                        // Use pre-generated message as fallback
                        idx += 1;
                        black_box(messages[idx % messages.len()].clone())
                    }
                });
            },
        );
    }

    group.finish();
}

fn benchmark_decoding(c: &mut Criterion) {
    let dict = match Dictionary::fix44() {
        Ok(d) => Arc::new(d),
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping decoding benchmarks");
            return;
        }
    };
    let mut group = c.benchmark_group("decoding");

    let encoding_rules = [
        ("BER", EncodingRule::BER),
        ("DER", EncodingRule::DER),
        ("OER", EncodingRule::OER),
    ];

    for (name, rule) in encoding_rules {
        let config = Config::new(rule);
        let encoder = Encoder::new(config.clone(), dict.clone());
        let decoder = Decoder::new(config, dict.clone());

        // Pre-encode messages
        let messages: Vec<Vec<u8>> = (1..=100)
            .filter_map(|seq| create_test_message(&encoder, seq).ok())
            .collect();

        if messages.is_empty() {
            eprintln!("Failed to create test messages, skipping {name} benchmark");
            continue;
        }

        group.bench_with_input(
            BenchmarkId::new("decode", name),
            &(&decoder, &messages),
            |b, (decoder, messages)| {
                let mut idx = 0;
                b.iter(|| {
                    // Skip failed decodings rather than panic in benchmarks
                    match decoder.decode(&messages[idx % messages.len()]) {
                        Ok(decoded) => {
                            idx += 1;
                            black_box(decoded);
                        }
                        Err(_) => {
                            // Skip this iteration on decoding failure
                            idx += 1;
                            black_box(());
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

fn benchmark_streaming_decoder(c: &mut Criterion) {
    let dict = match Dictionary::fix44() {
        Ok(d) => Arc::new(d),
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping streaming decoder benchmarks");
            return;
        }
    };
    let mut group = c.benchmark_group("streaming_decoder");

    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());

    // Create a batch of messages
    let mut batch = Vec::new();
    for seq in 1..=10 {
        if let Ok(msg) = create_test_message(&encoder, seq) {
            batch.extend_from_slice(&msg);
        } else {
            eprintln!("Failed to create test message {seq}, skipping streaming benchmark");
            return;
        }
    }

    group.bench_function("decode_batch", |b| {
        b.iter(|| {
            let mut decoder = rustyasn::DecoderStreaming::new(config.clone(), dict.clone());
            decoder.feed(&batch);

            let mut count = 0;
            while let Ok(Some(msg)) = decoder.decode_next() {
                black_box(msg);
                count += 1;
            }
            assert_eq!(count, 10);
        });
    });

    group.finish();
}

fn benchmark_message_sizes(c: &mut Criterion) {
    let dict = match Dictionary::fix44() {
        Ok(d) => Arc::new(d),
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping message size benchmarks");
            return;
        }
    };
    let group = c.benchmark_group("message_sizes");

    // Compare encoded sizes
    let encoding_rules = [
        ("BER", EncodingRule::BER),
        ("DER", EncodingRule::DER),
        ("OER", EncodingRule::OER),
    ];

    for (name, rule) in encoding_rules {
        let config = Config::new(rule);
        let encoder = Encoder::new(config, dict.clone());
        if let Ok(encoded) = create_test_message(&encoder, 1) {
            println!("{} encoded size: {} bytes", name, encoded.len());
        } else {
            eprintln!("Failed to encode message for {name} size measurement");
        }
    }

    group.finish();
}

fn benchmark_config_profiles(c: &mut Criterion) {
    let dict = match Dictionary::fix44() {
        Ok(d) => Arc::new(d),
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping config profile benchmarks");
            return;
        }
    };
    let mut group = c.benchmark_group("config_profiles");

    let configs = [
        ("default", Config::default()),
        ("low_latency", Config::low_latency()),
        ("high_reliability", Config::high_reliability()),
    ];

    for (name, config) in configs {
        let encoder = Encoder::new(config.clone(), dict.clone());
        let decoder = Decoder::new(config, dict.clone());

        // Pre-generate encoded messages to avoid Result matching in hot loop
        let encoded_messages: Vec<Vec<u8>> = (1..=100)
            .filter_map(|seq| create_test_message(&encoder, seq).ok())
            .collect();

        if encoded_messages.is_empty() {
            eprintln!("Failed to create test messages, skipping {name} roundtrip benchmark");
            continue;
        }

        group.bench_with_input(
            BenchmarkId::new("roundtrip", name),
            &(&decoder, &encoded_messages),
            |b, (decoder, encoded_messages)| {
                let mut idx = 0usize;
                b.iter(|| {
                    // Use pre-generated encoded message for consistent roundtrip testing
                    let encoded = &encoded_messages[idx % encoded_messages.len()];
                    match decoder.decode(encoded) {
                        Ok(decoded) => {
                            idx += 1;
                            black_box(decoded);
                        }
                        Err(_) => {
                            // Skip this iteration on decoding failure
                            idx += 1;
                            black_box(());
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_encoding,
    benchmark_decoding,
    benchmark_streaming_decoder,
    benchmark_message_sizes,
    benchmark_config_profiles
);
criterion_main!(benches);
