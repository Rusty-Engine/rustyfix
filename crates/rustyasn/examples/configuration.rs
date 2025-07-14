//! Configuration examples for different use cases.
//!
//! This example demonstrates the various configuration options available in
//! rustyasn for different performance and reliability requirements.

use rustyasn::{Config, EncodingRule};

fn main() {
    configuration_examples();
}

fn configuration_examples() {
    println!("=== RustyASN Configuration Examples ===\n");

    // Optimized for low-latency trading
    let low_latency_config = Config::low_latency(); // Uses OER, skips validation
    println!("1. Low Latency Configuration:");
    println!("   Encoding rule: {:?}", low_latency_config.encoding_rule);
    println!(
        "   Max message size: {} bytes",
        low_latency_config.max_message_size
    );
    println!(
        "   Zero-copy enabled: {}",
        low_latency_config.enable_zero_copy
    );
    println!(
        "   Validate checksums: {}",
        low_latency_config.validate_checksums
    );

    // Optimized for reliability and compliance
    let high_reliability_config = Config::high_reliability(); // Uses DER, full validation
    println!("\n2. High Reliability Configuration:");
    println!(
        "   Encoding rule: {:?}",
        high_reliability_config.encoding_rule
    );
    println!(
        "   Max message size: {} bytes",
        high_reliability_config.max_message_size
    );
    println!(
        "   Zero-copy enabled: {}",
        high_reliability_config.enable_zero_copy
    );
    println!(
        "   Validate checksums: {}",
        high_reliability_config.validate_checksums
    );

    // Custom configuration
    let mut custom_config = Config::new(EncodingRule::OER);
    custom_config.max_message_size = 16 * 1024; // 16KB limit
    custom_config.enable_zero_copy = true;
    custom_config.validate_checksums = false; // Disable for performance

    println!("\n3. Custom Configuration:");
    println!("   Encoding rule: {:?}", custom_config.encoding_rule);
    println!(
        "   Max message size: {} bytes",
        custom_config.max_message_size
    );
    println!("   Zero-copy enabled: {}", custom_config.enable_zero_copy);
    println!(
        "   Validate checksums: {}",
        custom_config.validate_checksums
    );

    // Show different encoding rules
    println!("\n4. Available Encoding Rules:");
    let rules = [
        (
            EncodingRule::BER,
            "Basic Encoding Rules - Self-describing, flexible",
        ),
        (
            EncodingRule::DER,
            "Distinguished Encoding Rules - Canonical subset of BER",
        ),
        (
            EncodingRule::OER,
            "Octet Encoding Rules - Byte-aligned, efficient",
        ),
    ];

    for (rule, description) in rules {
        println!("   {rule:?}: {description}");
    }

    println!("\n✓ Configuration examples complete!");
}
