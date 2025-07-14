//! Benchmarks for ASN.1 encoding performance.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustyasn::{Config, Decoder, Encoder, EncodingRule};
use rustyfix::Dictionary;
use std::hint::black_box;
use std::sync::Arc;

fn create_test_message(encoder: &Encoder, seq_num: u64) -> Vec<u8> {
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

    handle.encode().expect("Encoding should succeed")
}

fn benchmark_encoding(c: &mut Criterion) {
    let dict =
        Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for benchmark"));
    let mut group = c.benchmark_group("encoding");

    let encoding_rules = [
        ("BER", EncodingRule::BER),
        ("DER", EncodingRule::DER),
        ("OER", EncodingRule::OER),
    ];

    for (name, rule) in encoding_rules {
        let config = Config::new(rule);
        let encoder = Encoder::new(config, dict.clone());

        group.bench_with_input(BenchmarkId::new("encode", name), &encoder, |b, encoder| {
            let mut seq_num = 1;
            b.iter(|| {
                let encoded = create_test_message(encoder, seq_num);
                seq_num += 1;
                black_box(encoded)
            });
        });
    }

    group.finish();
}

fn benchmark_decoding(c: &mut Criterion) {
    let dict =
        Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for benchmark"));
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
            .map(|seq| create_test_message(&encoder, seq))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("decode", name),
            &(&decoder, &messages),
            |b, (decoder, messages)| {
                let mut idx = 0;
                b.iter(|| {
                    let decoded = decoder
                        .decode(&messages[idx % messages.len()])
                        .expect("Decoding should succeed");
                    idx += 1;
                    black_box(decoded)
                });
            },
        );
    }

    group.finish();
}

fn benchmark_streaming_decoder(c: &mut Criterion) {
    let dict =
        Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for benchmark"));
    let mut group = c.benchmark_group("streaming_decoder");

    let config = Config::new(EncodingRule::DER);
    let encoder = Encoder::new(config.clone(), dict.clone());

    // Create a batch of messages
    let mut batch = Vec::new();
    for seq in 1..=10 {
        let msg = create_test_message(&encoder, seq);
        batch.extend_from_slice(&msg);
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
    let dict =
        Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for benchmark"));
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
        let encoded = create_test_message(&encoder, 1);

        println!("{} encoded size: {} bytes", name, encoded.len());
    }

    group.finish();
}

fn benchmark_config_profiles(c: &mut Criterion) {
    let dict =
        Arc::new(Dictionary::fix44().expect("Failed to load FIX 4.4 dictionary for benchmark"));
    let mut group = c.benchmark_group("config_profiles");

    let configs = [
        ("default", Config::default()),
        ("low_latency", Config::low_latency()),
        ("high_reliability", Config::high_reliability()),
    ];

    for (name, config) in configs {
        let encoder = Encoder::new(config.clone(), dict.clone());
        let decoder = Decoder::new(config, dict.clone());

        group.bench_with_input(
            BenchmarkId::new("roundtrip", name),
            &(&encoder, &decoder),
            |b, (encoder, decoder)| {
                let mut seq_num = 1;
                b.iter(|| {
                    let encoded = create_test_message(encoder, seq_num);
                    let decoded = decoder.decode(&encoded).expect("Decoding should succeed");
                    seq_num += 1;
                    black_box(decoded)
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
