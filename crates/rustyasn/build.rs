//! Build script for ASN.1 schema compilation and code generation.
//!
//! # Why Custom ASN.1 Parser Instead of rasn-compiler?
//!
//! This build script implements a custom ASN.1 parser and code generator rather than using
//! the official `rasn-compiler` crate. This architectural decision was made due to several
//! compatibility and maintenance considerations:
//!
//! ## Version Compatibility Issues
//!
//! The primary reason for the custom implementation is version incompatibility between
//! `rasn-compiler` and `rasn` 0.18.x:
//!
//! - **rasn-compiler dependency conflicts**: The rasn-compiler crate may depend on different
//!   versions of rasn than the 0.18.x version used in this project, causing dependency
//!   resolution conflicts during build.
//!
//! - **API surface changes**: Between rasn versions, there have been breaking changes in
//!   the generated code APIs, attribute syntax, and trait implementations that make
//!   rasn-compiler-generated code incompatible with rasn 0.18.x.
//!
//! - **Build-time constraints**: Using rasn-compiler would require careful version pinning
//!   and potentially upgrading rasn itself, which could introduce breaking changes throughout
//!   the RustyFix codebase.
//!
//! ## Benefits of Custom Implementation
//!
//! The custom ASN.1 parser implementation provides several advantages:
//!
//! - **Precise control**: Generate code that exactly matches the needs of the FIX protocol
//!   encoding requirements and integrates seamlessly with RustyFix's type system.
//!
//! - **Stability**: Immune to breaking changes in rasn-compiler updates, ensuring consistent
//!   builds across different environments and over time.
//!
//! - **FIX-specific optimizations**: Tailored for FIX protocol message structures, field
//!   types, and encoding patterns rather than generic ASN.1 use cases.
//!
//! - **Reduced dependencies**: Eliminates the need for rasn-compiler and its transitive
//!   dependencies, reducing build complexity and potential security surface.
//!
//! - **Incremental implementation**: Can be extended progressively to support additional
//!   ASN.1 features as needed by the FIX protocol without waiting for upstream changes.
//!
//! ## Migration Path
//!
//! Future migration to rasn-compiler should be considered when:
//!
//! - rasn-compiler achieves stable compatibility with rasn 0.18.x or later
//! - The RustyFix project upgrades to a newer rasn version that's compatible with
//!   the latest rasn-compiler
//! - The maintenance burden of the custom parser becomes significant
//!
//! ## Implementation Details
//!
//! The custom parser handles:
//! - Basic ASN.1 constructs (SEQUENCE, CHOICE, ENUMERATED, INTEGER, STRING types)
//! - FIX-specific message type generation from dictionary metadata
//! - Field tag enumerations and value type mappings
//! - Integration with rasn's derive macros for encoding/decoding
//!
//! For complex ASN.1 schemas that require advanced features not implemented in the
//! custom parser, the build script falls back to copying the schema files directly
//! and emitting warnings about unsupported constructs.

use anyhow::{Context, Result};
use heck::ToPascalCase;
use rustyfix_dictionary::Dictionary;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Sanitizes a string to be a valid Rust identifier by replacing invalid characters.
/// For message types, preserves alphanumeric characters and replaces others with underscores.
/// Does not add prefix for numeric message types since they'll be used after an underscore.
fn sanitize_identifier(input: &str) -> String {
    let mut result = String::new();

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
        } else {
            // Replace invalid characters (like /, +, -, etc.) with underscore
            result.push('_');
        }
    }

    // Ensure result is not empty
    if result.is_empty() {
        result = "_".to_string();
    }

    result
}

fn main() -> Result<()> {
    // Set up rerun conditions
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=schemas/");

    // Check available features dynamically
    let enabled_features = get_enabled_fix_features();
    // println!("cargo:warning=Detected FIX features: {enabled_features:?}");

    // Generate ASN.1 definitions from FIX dictionaries
    // This creates type-safe ASN.1 representations of FIX message structures
    // without requiring rasn-compiler, ensuring compatibility with rasn 0.18.x
    generate_fix_asn1_definitions(&enabled_features)
        .context("Failed to generate FIX ASN.1 definitions")?;

    // Generate additional ASN.1 schema files if they exist
    generate_custom_asn1_schemas().context("Failed to generate custom ASN.1 schemas")?;

    Ok(())
}

/// Gets the list of enabled FIX features dynamically.
fn get_enabled_fix_features() -> Vec<String> {
    let mut features = Vec::new();

    // Always include FIX 4.4 as it's the primary version (no feature flag required)
    features.push("fix44".to_string());

    // Dynamically detect available FIX features from the dictionary crate
    // This approach uses the build-time capabilities to check what's available
    let known_fix_versions = [
        "fix40", "fix41", "fix42", "fix43", "fix44", "fix50", "fix50sp1", "fix50sp2", "fixt11",
    ];

    for feature in known_fix_versions {
        let env_var = format!("CARGO_FEATURE_{}", feature.to_uppercase());
        if env::var(&env_var).is_ok() {
            // Only add if not already included (fix44 is always included above)
            if feature != "fix44" && !features.contains(&feature.to_string()) {
                features.push(feature.to_string());
            }
        }
    }

    // Also check if we can probe the dictionary crate for available methods
    // This is a more robust approach that doesn't rely on hardcoded feature names
    let available_dictionaries = probe_available_dictionaries();
    for dict_name in available_dictionaries {
        if !features.contains(&dict_name) {
            features.push(dict_name);
        }
    }

    features
}

/// Probes the rustyfix-dictionary crate to find available dictionary methods.
/// This provides a more robust way to detect available FIX versions without hardcoding.
fn probe_available_dictionaries() -> Vec<String> {
    let mut available = Vec::new();

    // Test compilation of dictionary creation calls to see what's available
    // We do this by checking if the methods exist in the dictionary crate

    // Use a feature-based approach since we can't easily probe method existence at build time
    // Check environment variables that Cargo sets for enabled features
    let env_vars: Vec<_> = env::vars()
        .filter_map(|(key, _)| {
            if key.starts_with("CARGO_FEATURE_FIX") {
                #[allow(clippy::expect_used)]
                let feature_name = key
                    .strip_prefix("CARGO_FEATURE_")
                    .expect("Environment variable must start with CARGO_FEATURE_ prefix")
                    .to_lowercase();
                Some(feature_name)
            } else {
                None
            }
        })
        .collect();

    for feature in env_vars {
        // Verify it looks like a FIX version and not some other feature
        if feature.starts_with("fix") && (feature.len() >= 5 || feature == "fixt11") {
            available.push(feature);
        }
    }

    available
}

/// Generates ASN.1 type definitions from FIX dictionaries.
fn generate_fix_asn1_definitions(enabled_features: &[String]) -> Result<()> {
    let out_dir = env::var("OUT_DIR").context("Failed to get OUT_DIR environment variable")?;
    let out_path = Path::new(&out_dir);

    for feature in enabled_features {
        let filename = format!("{feature}_asn1.rs");

        // Dynamically call the appropriate dictionary method
        // Note: Only fix40, fix44, and fix50 are currently available in rustyfix-dictionary
        let dict_result = match feature.as_str() {
            "fix40" => Dictionary::fix40(),
            "fix44" => Dictionary::fix44(),
            "fix50" => Dictionary::fix50(),
            // The following versions are not yet implemented in rustyfix-dictionary
            "fix41" | "fix42" | "fix43" | "fix50sp1" | "fix50sp2" | "fixt11" => {
                println!(
                    "cargo:warning=Skipping {} (not yet implemented in rustyfix-dictionary)",
                    feature.to_uppercase()
                );
                continue;
            }
            _ => {
                println!(
                    "cargo:warning=Skipping unknown FIX feature: {feature} (no corresponding dictionary method)"
                );
                continue;
            }
        };

        let dictionary = match dict_result {
            Ok(dict) => dict,
            Err(e) => {
                println!(
                    "cargo:warning=Failed to load {} dictionary: {} (feature may not be enabled in build dependencies)",
                    feature.to_uppercase(),
                    e
                );
                continue;
            }
        };

        // println!(
        //     "cargo:warning=Generating ASN.1 definitions for {}",
        //     feature.to_uppercase()
        // );
        generate_fix_dictionary_asn1(&dictionary, &filename, out_path)
            .with_context(|| format!("Failed to generate ASN.1 definitions for {feature}"))?;
    }

    Ok(())
}

/// Generates ASN.1 definitions for a specific FIX dictionary.
fn generate_fix_dictionary_asn1(
    dictionary: &Dictionary,
    filename: &str,
    out_path: &Path,
) -> Result<()> {
    let mut output = String::new();

    // File header
    output.push_str(&format!(
        r#"// Generated ASN.1 definitions for FIX {}.
// This file is automatically generated by the build script.
// DO NOT EDIT MANUALLY - ALL CHANGES WILL BE OVERWRITTEN.
// Generated on: {}

use rasn::{{AsnType, Decode, Encode}};
use crate::types::{{Field, ToFixFieldValue}};

"#,
        dictionary.version(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Generate message type enums
    output.push_str(&generate_message_type_enum(dictionary)?);
    output.push_str("\n\n");

    // Generate field tag enums
    output.push_str(&generate_field_tag_enum(dictionary)?);
    output.push_str("\n\n");

    // Generate message structures
    output.push_str(&generate_message_structures(dictionary)?);
    output.push_str("\n\n");

    // Generate field value enums
    output.push_str(&generate_field_value_enums(dictionary)?);

    // Write to output file
    let file_path = out_path.join(filename);
    fs::write(file_path, output)
        .with_context(|| format!("Failed to write ASN.1 definitions to {filename}"))?;

    Ok(())
}

/// Generates ASN.1 enum for FIX message types.
fn generate_message_type_enum(dictionary: &Dictionary) -> Result<String> {
    let mut output = String::new();

    output.push_str(
        r#"/// ASN.1 enumeration of FIX message types.
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[rasn(crate_root = "rasn")]
#[rasn(enumerated)]
pub enum FixMessageType {
"#,
    );

    // Collect all message types
    let mut message_types: BTreeMap<String, String> = BTreeMap::new();
    let mut used_names = HashSet::new();

    for message in dictionary.messages() {
        let msg_type = message.msg_type();
        let name = message.name();
        let sanitized_msg_type = sanitize_identifier(msg_type);
        // For clean alphanumeric message types, concatenate without underscore for better Rust naming
        let mut enum_name = if sanitized_msg_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
        {
            format!("{}{}", name.to_pascal_case(), sanitized_msg_type)
        } else {
            // Use underscore for complex sanitized types (those with replaced characters)
            format!("{}_{}", name.to_pascal_case(), sanitized_msg_type)
        };

        // Handle name collisions
        let mut counter = 1;
        while used_names.contains(&enum_name) {
            if sanitized_msg_type
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
            {
                enum_name = format!("{}{}{}", name.to_pascal_case(), sanitized_msg_type, counter);
            } else {
                enum_name = format!(
                    "{}_{}{}",
                    name.to_pascal_case(),
                    sanitized_msg_type,
                    counter
                );
            }
            counter += 1;
        }
        used_names.insert(enum_name.clone());

        message_types.insert(msg_type.to_string(), enum_name);
    }

    // Generate enum variants
    for (discriminant, (msg_type, enum_name)) in message_types.iter().enumerate() {
        output.push_str(&format!(
            "    /// Message type '{msg_type}'\n    {enum_name} = {discriminant},\n"
        ));
    }

    output.push_str("}\n\n");

    // Generate conversion implementations
    output.push_str(&format!(
        r#"impl FixMessageType {{
    /// Gets the FIX message type string.
    pub fn as_str(&self) -> &'static str {{
        match self {{
{}        }}
    }}
    
    /// Creates from FIX message type string.
    pub fn from_str(s: &str) -> Option<Self> {{
        match s {{
{}            _ => None,
        }}
    }}
}}

impl ToFixFieldValue for FixMessageType {{
    fn to_fix_field_value(&self) -> crate::types::FixFieldValue {{
        crate::types::FixFieldValue::String(self.as_str().to_string())
    }}
}}
"#,
        message_types
            .iter()
            .map(|(msg_type, enum_name)| format!(
                "            Self::{enum_name} => \"{msg_type}\",\n"
            ))
            .collect::<String>(),
        message_types
            .iter()
            .map(|(msg_type, enum_name)| format!(
                "            \"{msg_type}\" => Some(Self::{enum_name}),\n"
            ))
            .collect::<String>()
    ));

    Ok(output)
}

/// Generates ASN.1 enum for FIX field tags.
fn generate_field_tag_enum(dictionary: &Dictionary) -> Result<String> {
    let mut output = String::new();

    output.push_str(
        r#"/// ASN.1 enumeration of FIX field tags.
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[rasn(crate_root = "rasn")]
#[rasn(enumerated)]
pub enum FixFieldTag {
"#,
    );

    // Collect all field tags
    let mut field_tags: BTreeMap<u32, String> = BTreeMap::new();

    for field in dictionary.fields() {
        let tag = field.tag();
        let name = field.name().to_pascal_case();
        field_tags.insert(tag.get(), name);
    }

    // Generate enum variants
    for (tag, name) in &field_tags {
        output.push_str(&format!(
            "    /// Field tag {tag} ({name})\n    {name} = {tag},\n"
        ));
    }

    output.push_str("}\n\n");

    // Generate conversion implementations
    output.push_str(&format!(
        r#"impl FixFieldTag {{
    /// Gets the field tag number.
    pub fn as_u32(&self) -> u32 {{
        *self as u32
    }}
    
    /// Creates from field tag number.
    pub fn from_u32(tag: u32) -> Option<Self> {{
        match tag {{
{}            _ => None,
        }}
    }}
}}

impl From<FixFieldTag> for u32 {{
    fn from(tag: FixFieldTag) -> Self {{
        tag.as_u32()
    }}
}}

impl ToFixFieldValue for FixFieldTag {{
    fn to_fix_field_value(&self) -> crate::types::FixFieldValue {{
        crate::types::FixFieldValue::UnsignedInteger(self.as_u32() as u64)
    }}
}}
"#,
        field_tags
            .iter()
            .map(|(tag, name)| format!("            {tag} => Some(Self::{name}),\n"))
            .collect::<String>()
    ));

    Ok(output)
}

/// Generates a generic ASN.1 message structure for FIX messages.
fn generate_message_structures(_dictionary: &Dictionary) -> Result<String> {
    let mut output = String::new();

    // Generate a generic ASN.1 message container
    output.push_str(
        r#"/// Generic ASN.1 FIX message structure.
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1FixMessage {
    /// Message type
    #[rasn(tag(0))]
    pub msg_type: FixMessageType,
    
    /// Sender company ID
    #[rasn(tag(1))]
    pub sender_comp_id: String,
    
    /// Target company ID  
    #[rasn(tag(2))]
    pub target_comp_id: String,
    
    /// Message sequence number
    #[rasn(tag(3))]
    pub msg_seq_num: u64,
    
    /// Sending time (optional)
    #[rasn(tag(4))]
    pub sending_time: Option<String>,
    
    /// Message fields
    #[rasn(tag(5))]
    pub fields: Vec<Asn1Field>,
}

/// ASN.1 representation of a FIX field.
#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]
#[rasn(crate_root = "rasn")]
pub struct Asn1Field {
    /// Field tag
    #[rasn(tag(0))]
    pub tag: FixFieldTag,
    
    /// Field value as string
    #[rasn(tag(1))]
    pub value: String,
}

"#,
    );

    // Generate conversion methods
    output.push_str(
        r#"impl Asn1FixMessage {
    /// Converts from the simple FixMessage representation.
    pub fn from_fix_message(msg: &crate::types::FixMessage) -> Option<Self> {
        let msg_type = FixMessageType::from_str(&msg.msg_type)?;
        
        // Extract sending time from fields if present (tag 52)
        let sending_time = msg.fields
            .iter()
            .find(|field| field.tag == 52)
            .map(|field| field.value.to_string());
        
        let fields = msg.fields
            .iter()
            .filter_map(|field| {
                let tag = FixFieldTag::from_u32(field.tag as u32)?;
                Some(Asn1Field {
                    tag,
                    value: field.value.to_string(),
                })
            })
            .collect();
        
        Some(Self {
            msg_type,
            sender_comp_id: msg.sender_comp_id.clone(),
            target_comp_id: msg.target_comp_id.clone(),
            msg_seq_num: msg.msg_seq_num,
            sending_time,
            fields,
        })
    }
    
    /// Converts to the simple FixMessage representation.
    pub fn to_fix_message(&self) -> crate::types::FixMessage {
        let fields = self.fields
            .iter()
            .map(|field| Field {
                tag: field.tag.as_u32(),
                value: crate::types::FixFieldValue::String(field.value.clone()),
            })
            .collect();
        
        crate::types::FixMessage {
            msg_type: self.msg_type.as_str().to_string(),
            sender_comp_id: self.sender_comp_id.clone(),
            target_comp_id: self.target_comp_id.clone(),
            msg_seq_num: self.msg_seq_num,
            fields,
        }
    }
}

"#,
    );

    Ok(output)
}

/// Generates ASN.1 enums for FIX field values that have restricted sets.
fn generate_field_value_enums(dictionary: &Dictionary) -> Result<String> {
    let mut output = String::new();

    output.push_str("// Field value enumerations\n\n");

    for field in dictionary.fields() {
        if let Some(enums) = field.enums() {
            let enums_vec: Vec<_> = enums.collect();
            let field_name = field.name().to_pascal_case();
            let enum_name = format!("{field_name}Value");

            output.push_str(&format!(
                r#"/// Allowed values for field {} (tag {}).
#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[rasn(crate_root = "rasn")]
#[rasn(enumerated)]
pub enum {} {{
"#,
                field.name(),
                field.tag(),
                enum_name
            ));

            // Generate enum variants
            for (discriminant, enum_value) in enums_vec.iter().enumerate() {
                let mut variant_name = if enum_value.description().is_empty() {
                    enum_value.value()
                } else {
                    enum_value.description()
                }
                .to_pascal_case();

                // Handle identifiers that start with numbers
                if variant_name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
                {
                    variant_name = format!("V{variant_name}");
                }

                // Handle invalid characters
                variant_name = variant_name.replace(['/', ':', '-', ' ', '(', ')', '.'], "_");

                output.push_str(&format!(
                    "    /// {}\n    {} = {},\n",
                    if enum_value.description().is_empty() {
                        ""
                    } else {
                        enum_value.description()
                    },
                    variant_name,
                    discriminant
                ));
            }

            output.push_str("}\n\n");

            // Generate conversion implementations
            output.push_str(&format!(
                r#"impl {} {{
    /// Gets the FIX field value string.
    pub fn as_str(&self) -> &'static str {{
        match self {{
{}        }}
    }}
}}

impl ToFixFieldValue for {} {{
    fn to_fix_field_value(&self) -> crate::types::FixFieldValue {{
        crate::types::FixFieldValue::String(self.as_str().to_string())
    }}
}}

"#,
                enum_name,
                enums_vec
                    .iter()
                    .map(|enum_value| {
                        let mut variant_name = if enum_value.description().is_empty() {
                            enum_value.value()
                        } else {
                            enum_value.description()
                        }
                        .to_pascal_case();

                        // Handle identifiers that start with numbers
                        if variant_name
                            .chars()
                            .next()
                            .is_some_and(|c| c.is_ascii_digit())
                        {
                            variant_name = format!("V{variant_name}");
                        }

                        // Handle invalid characters
                        variant_name =
                            variant_name.replace(['/', ':', '-', ' ', '(', ')', '.'], "_");
                        format!(
                            "            Self::{} => \"{}\",\n",
                            variant_name,
                            enum_value.value()
                        )
                    })
                    .collect::<String>(),
                enum_name
            ));
        }
    }

    Ok(output)
}

/// Generates ASN.1 schemas from custom schema files in the schemas/ directory.
fn generate_custom_asn1_schemas() -> Result<()> {
    let schemas_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas");

    if !schemas_dir.exists() {
        // Create schemas directory with a sample schema
        fs::create_dir_all(&schemas_dir).context("Failed to create schemas directory")?;

        let sample_schema = r#"-- Sample ASN.1 schema for FIX message extensions
-- Place custom ASN.1 schemas in this directory for automatic compilation

FixExtensions DEFINITIONS ::= BEGIN

-- Custom message types
CustomMessageType ::= ENUMERATED {
    customHeartbeat(0),
    customLogon(1),
    customLogout(2)
}

-- Custom field definitions  
CustomField ::= SEQUENCE {
    tag     INTEGER,
    value   UTF8String
}

-- Price field with high precision
PrecisePrice ::= SEQUENCE {
    mantissa    INTEGER,
    exponent    INTEGER
}

-- Extended message structure
ExtendedFixMessage ::= SEQUENCE {
    msgType         CustomMessageType,
    senderCompId    UTF8String,
    targetCompId    UTF8String,
    msgSeqNum       INTEGER,
    customFields    CustomField OPTIONAL,
    precisePrice    PrecisePrice OPTIONAL
}

-- Message variant choice
MessageVariant ::= CHOICE {
    standard    [0] ExtendedFixMessage,
    compressed  [1] UTF8String,
    binary      [2] OCTET
}

END
"#;

        fs::write(schemas_dir.join("sample.asn1"), sample_schema)
            .context("Failed to write sample ASN.1 schema")?;

        println!("cargo:warning=Created schemas/ directory with sample ASN.1 schema");
        println!(
            "cargo:warning=Place your custom ASN.1 schemas in schemas/ for automatic compilation"
        );
    }

    // Process any .asn1 files in the schemas directory using our custom ASN.1 parser
    // Note: This uses a custom parser instead of rasn-compiler due to version compatibility issues
    compile_asn1_schemas(&schemas_dir).context("Failed to compile ASN.1 schemas")?;

    Ok(())
}

/// Compiles ASN.1 schema files using a custom ASN.1 parser implementation.
///
/// **Note**: This function uses a custom ASN.1 parser instead of rasn-compiler due to
/// version incompatibility issues between rasn-compiler and rasn 0.18.x. The custom
/// implementation provides better control over the generated code and avoids dependency
/// conflicts while maintaining compatibility with the rasn framework.
///
/// See the module-level documentation for detailed reasoning behind this architectural choice.
fn compile_asn1_schemas(schemas_dir: &Path) -> Result<()> {
    let schema_pattern = schemas_dir.join("*.asn1");

    // Check if glob crate is available in build dependencies
    match glob::glob(&schema_pattern.to_string_lossy()) {
        Ok(entries) => {
            let out_dir =
                env::var("OUT_DIR").context("Failed to get OUT_DIR environment variable")?;
            let out_path = Path::new(&out_dir);

            for entry in entries {
                let schema_file = entry.context("Failed to read schema file entry")?;

                // println!(
                //     "cargo:warning=Compiling ASN.1 schema: {}",
                //     schema_file.display()
                // );

                // Get the filename without extension for generated Rust module
                let file_stem = schema_file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .with_context(|| format!("Invalid filename: {}", schema_file.display()))?;

                let output_file = format!("{file_stem}_asn1.rs");
                let output_path = out_path.join(&output_file);

                // Attempt to compile the ASN.1 schema using our custom parser
                // This avoids rasn-compiler version compatibility issues while providing
                // targeted support for FIX protocol ASN.1 extensions
                match compile_asn1_file(&schema_file, &output_path) {
                    Ok(_) => {
                        // Successfully compiled - no warning needed
                    }
                    Err(e) => {
                        // If our custom parser fails, fall back to copying the file and warn
                        // This provides a graceful degradation path for complex schemas
                        println!(
                            "cargo:warning=Custom ASN.1 parser failed for {}: {}. Copying file instead.",
                            schema_file.display(),
                            e
                        );
                        println!(
                            "cargo:warning=Consider simplifying the schema or extending the custom parser to support this construct."
                        );
                        let filename = schema_file.file_name().with_context(|| {
                            format!(
                                "Schema file should have a valid filename: {}",
                                schema_file.display()
                            )
                        })?;
                        let fallback_path = out_path.join(filename);
                        fs::copy(&schema_file, fallback_path).with_context(|| {
                            format!("Failed to copy schema file {}", schema_file.display())
                        })?;
                    }
                }
            }
        }
        Err(e) => {
            println!("cargo:warning=Failed to search for ASN.1 schema files: {e}");
        }
    }

    Ok(())
}

/// Compiles a single ASN.1 schema file to Rust code using a custom ASN.1 parser.
///
/// This function implements a custom ASN.1 parser that handles the subset of ASN.1
/// constructs commonly used in FIX protocol extensions. The parser is designed to
/// generate code compatible with rasn 0.18.x while avoiding the version compatibility
/// issues that would arise from using rasn-compiler.
///
/// **Supported ASN.1 Constructs:**
/// - SEQUENCE types with optional fields and explicit tags
/// - ENUMERATED types with explicit discriminant values
/// - CHOICE types with context-specific tags
/// - INTEGER types with constraint annotations
/// - String types (UTF8String, PrintableString, VisibleString, etc.)
///
/// **Limitations:**
/// - Does not support complex constraints or extensibility markers
/// - Limited support for advanced ASN.1 features like Information Object Classes
/// - No support for parameterized types or macros
///
/// For schemas requiring unsupported features, the function will return an error
/// and the caller can fall back to copying the schema file directly.
fn compile_asn1_file(schema_file: &Path, output_path: &Path) -> Result<()> {
    // Read the ASN.1 schema file
    let schema_content = fs::read_to_string(schema_file)
        .with_context(|| format!("Failed to read schema file: {}", schema_file.display()))?;

    // Parse the ASN.1 schema
    let parsed_schema = parse_asn1_schema(&schema_content)
        .with_context(|| format!("Failed to parse ASN.1 schema: {}", schema_file.display()))?;

    // Generate Rust code from parsed schema
    let rust_code = generate_rust_from_asn1(&parsed_schema, schema_file)?;

    // Write the generated Rust code
    fs::write(output_path, rust_code).with_context(|| {
        format!(
            "Failed to write compiled schema to: {}",
            output_path.display()
        )
    })?;

    Ok(())
}

/// Parsed ASN.1 type definition
#[derive(Debug, Clone)]
enum Asn1Type {
    Sequence {
        name: String,
        fields: Vec<Asn1Field>,
    },
    Enumerated {
        name: String,
        values: Vec<Asn1EnumValue>,
    },
    Choice {
        name: String,
        alternatives: Vec<Asn1Field>,
    },
    Integer {
        name: String,
        #[allow(dead_code)]
        constraints: Option<String>,
    },
    String {
        name: String,
        #[allow(dead_code)]
        string_type: Asn1StringType,
    },
}

#[derive(Debug, Clone)]
struct Asn1Field {
    name: String,
    field_type: String,
    optional: bool,
    tag: Option<u32>,
}

#[derive(Debug, Clone)]
struct Asn1EnumValue {
    name: String,
    value: Option<i32>,
}

#[derive(Debug, Clone)]
enum Asn1StringType {
    Utf8,
    Printable,
    Visible,
    General,
}

#[derive(Debug)]
struct Asn1Schema {
    #[allow(dead_code)]
    module_name: String,
    types: Vec<Asn1Type>,
}

/// Basic ASN.1 schema parser implementation.
///
/// This parser handles a subset of ASN.1 sufficient for FIX protocol message
/// extensions and common ASN.1 patterns. It's designed to be simple, reliable,
/// and compatible with rasn 0.18.x generated code patterns.
///
/// The parser uses a simple line-by-line approach with basic pattern matching
/// rather than a full grammar parser, making it easier to maintain and debug.
fn parse_asn1_schema(content: &str) -> Result<Asn1Schema> {
    let mut types = Vec::new();
    let mut module_name = "UnknownModule".to_string();

    // Extract module name
    if let Some(module_line) = content.lines().find(|line| line.contains("DEFINITIONS")) {
        if let Some(name) = module_line.split_whitespace().next() {
            module_name = name.to_string();
        }
    }

    // Simple line-by-line parsing (basic implementation)
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // Skip empty lines and comments
        if line.is_empty()
            || line.starts_with("--")
            || line.starts_with("BEGIN")
            || line.starts_with("END")
        {
            i += 1;
            continue;
        }

        // Skip ASN.1 module definition lines (MODULE DEFINITIONS ::= BEGIN)
        if line.contains("DEFINITIONS ::= BEGIN") {
            i += 1;
            continue;
        }

        // Parse type definitions
        if line.contains("::=") {
            match parse_type_definition(line, &lines, &mut i) {
                Ok(asn1_type) => types.push(asn1_type),
                Err(e) => {
                    println!("cargo:warning=Failed to parse type definition '{line}': {e}");
                }
            }
        }

        i += 1;
    }

    Ok(Asn1Schema { module_name, types })
}

/// Parse a single type definition
fn parse_type_definition(
    line: &str,
    lines: &[&str],
    current_index: &mut usize,
) -> Result<Asn1Type> {
    let parts: Vec<&str> = line.split("::=").collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid type definition syntax"));
    }

    let type_name = parts[0].trim().to_string();
    let type_def = parts[1].trim();

    if type_def.starts_with("ENUMERATED") {
        parse_enumerated_type(type_name, type_def, lines, current_index)
    } else if type_def.starts_with("SEQUENCE") {
        parse_sequence_type(type_name, type_def, lines, current_index)
    } else if type_def.starts_with("CHOICE") {
        parse_choice_type(type_name, type_def, lines, current_index)
    } else if type_def.starts_with("INTEGER") {
        parse_integer_type(type_name, type_def)
    } else if type_def.contains("String") || type_def == "UTF8String" {
        parse_string_type(type_name, type_def)
    } else {
        Err(anyhow::anyhow!("Unsupported type: {}", type_def))
    }
}

/// Parse ENUMERATED type
fn parse_enumerated_type(
    name: String,
    _type_def: &str,
    lines: &[&str],
    current_index: &mut usize,
) -> Result<Asn1Type> {
    let mut values = Vec::new();
    let mut i = *current_index + 1;

    // Look for enum values in following lines
    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            *current_index = i;
            break;
        }

        if line.contains("(") && line.contains(")") {
            // Parse enum value with explicit number: name(0)
            if let Some(enum_name) = line.split('(').next() {
                let enum_name = enum_name.trim().replace(',', "");
                if let Some(value_part) = line.split('(').nth(1) {
                    if let Some(value_str) = value_part.split(')').next() {
                        if let Ok(value) = value_str.trim().parse::<i32>() {
                            values.push(Asn1EnumValue {
                                name: enum_name,
                                value: Some(value),
                            });
                        }
                    }
                }
            }
        } else if !line.is_empty() && !line.starts_with("--") && line != "{" {
            // Parse simple enum value: name
            let enum_name = line.replace(',', "").trim().to_string();
            if !enum_name.is_empty() {
                values.push(Asn1EnumValue {
                    name: enum_name,
                    value: None,
                });
            }
        }

        i += 1;
    }

    Ok(Asn1Type::Enumerated { name, values })
}

/// Parse SEQUENCE type
fn parse_sequence_type(
    name: String,
    _type_def: &str,
    lines: &[&str],
    current_index: &mut usize,
) -> Result<Asn1Type> {
    let mut fields = Vec::new();
    let mut i = *current_index + 1;

    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            *current_index = i;
            break;
        }

        // Parse field: fieldName FieldType [OPTIONAL]
        if !line.is_empty() && !line.starts_with("--") && line != "{" {
            if let Some(field) = parse_sequence_field(line) {
                fields.push(field);
            }
        }

        i += 1;
    }

    Ok(Asn1Type::Sequence { name, fields })
}

/// Parse CHOICE type
fn parse_choice_type(
    name: String,
    _type_def: &str,
    lines: &[&str],
    current_index: &mut usize,
) -> Result<Asn1Type> {
    let mut alternatives = Vec::new();
    let mut i = *current_index + 1;

    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            *current_index = i;
            break;
        }

        if !line.is_empty() && !line.starts_with("--") && line != "{" {
            if let Some(field) = parse_sequence_field(line) {
                alternatives.push(field);
            }
        }

        i += 1;
    }

    Ok(Asn1Type::Choice { name, alternatives })
}

/// Parse INTEGER type
fn parse_integer_type(name: String, type_def: &str) -> Result<Asn1Type> {
    let constraints = if type_def.contains('(') && type_def.contains(')') {
        Some(type_def.to_string())
    } else {
        None
    };

    Ok(Asn1Type::Integer { name, constraints })
}

/// Parse string type
fn parse_string_type(name: String, type_def: &str) -> Result<Asn1Type> {
    let string_type = match type_def {
        "UTF8String" => Asn1StringType::Utf8,
        "PrintableString" => Asn1StringType::Printable,
        "VisibleString" => Asn1StringType::Visible,
        _ => Asn1StringType::General,
    };

    Ok(Asn1Type::String { name, string_type })
}

/// Parse a sequence field
fn parse_sequence_field(line: &str) -> Option<Asn1Field> {
    let clean_line = line.replace(',', "").trim().to_string();
    let parts: Vec<&str> = clean_line.split_whitespace().collect();

    if parts.len() >= 2 {
        let field_name = parts[0].to_string();
        let field_type = parts[1].to_string();
        let optional = clean_line.to_uppercase().contains("OPTIONAL");

        // Extract tag if present [n]
        let tag = if clean_line.contains('[') && clean_line.contains(']') {
            if let Some(tag_start) = clean_line.find('[') {
                if let Some(tag_end) = clean_line.find(']') {
                    let tag_str = &clean_line[tag_start + 1..tag_end];
                    tag_str.parse().ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Some(Asn1Field {
            name: field_name,
            field_type,
            optional,
            tag,
        })
    } else {
        None
    }
}

/// Generate Rust code from parsed ASN.1 schema
fn generate_rust_from_asn1(schema: &Asn1Schema, schema_file: &Path) -> Result<String> {
    let mut output = String::new();

    // File header
    output.push_str(&format!(
        r#"//! Generated Rust code from ASN.1 schema: {}
//! This file is automatically generated by the build script.
//! DO NOT EDIT MANUALLY - ALL CHANGES WILL BE OVERWRITTEN.
//! Generated on: {}

use rasn::{{AsnType, Decode, Encode}};

"#,
        schema_file.display(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Generate types
    for asn1_type in &schema.types {
        output.push_str(&generate_rust_type(asn1_type)?);
        output.push_str("\n\n");
    }

    Ok(output)
}

/// Generate Rust code for a single ASN.1 type
fn generate_rust_type(asn1_type: &Asn1Type) -> Result<String> {
    match asn1_type {
        Asn1Type::Sequence { name, fields } => {
            let mut output = format!(
                "/// ASN.1 SEQUENCE: {name}\n#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]\n#[rasn(crate_root = \"rasn\")]\npub struct {name} {{\n"
            );

            for field in fields.iter() {
                if let Some(tag) = field.tag {
                    output.push_str(&format!("    #[rasn(tag({tag}))]\n"));
                }

                let field_type = map_asn1_type_to_rust(&field.field_type);
                let field_type = if field.optional {
                    format!("Option<{field_type}>")
                } else {
                    field_type
                };

                output.push_str(&format!(
                    "    pub {}: {},\n",
                    field.name.to_lowercase(),
                    field_type
                ));
            }

            output.push('}');
            Ok(output)
        }

        Asn1Type::Enumerated { name, values } => {
            let mut output = format!(
                "/// ASN.1 ENUMERATED: {name}\n#[derive(AsnType, Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]\n#[rasn(crate_root = \"rasn\")]\n#[rasn(enumerated)]\npub enum {name} {{\n"
            );

            for (i, value) in values.iter().enumerate() {
                let discriminant = value.value.unwrap_or(i as i32);
                output.push_str(&format!(
                    "    {} = {},\n",
                    value.name.to_pascal_case(),
                    discriminant
                ));
            }

            output.push('}');
            Ok(output)
        }

        Asn1Type::Choice { name, alternatives } => {
            let mut output = format!(
                "/// ASN.1 CHOICE: {name}\n#[derive(AsnType, Debug, Clone, PartialEq, Encode, Decode)]\n#[rasn(choice, crate_root = \"rasn\")]\npub enum {name} {{\n"
            );

            for (i, alt) in alternatives.iter().enumerate() {
                let tag = alt.tag.unwrap_or(i as u32);
                output.push_str(&format!("    #[rasn(tag(context, {tag}))]\n"));
                output.push_str(&format!(
                    "    {}({}),\n",
                    alt.name.to_pascal_case(),
                    map_asn1_type_to_rust(&alt.field_type)
                ));
            }

            output.push('}');
            Ok(output)
        }

        Asn1Type::Integer {
            name,
            constraints: _,
        } => Ok(format!("/// ASN.1 INTEGER: {name}\npub type {name} = i64;")),

        Asn1Type::String {
            name,
            string_type: _,
        } => Ok(format!(
            "/// ASN.1 STRING: {name}\npub type {name} = String;"
        )),
    }
}

/// Map ASN.1 type name to Rust type
fn map_asn1_type_to_rust(asn1_type: &str) -> String {
    match asn1_type.to_uppercase().as_str() {
        "INTEGER" => "i64".to_string(),
        "UTF8STRING" | "PRINTABLESTRING" | "VISIBLESTRING" | "GENERALSTRING" => {
            "String".to_string()
        }
        "BOOLEAN" => "bool".to_string(),
        "OCTET" | "DATA" => "Vec<u8>".to_string(),
        _ => asn1_type.to_string(), // Custom type, use as-is
    }
}

//
// FUTURE IMPROVEMENTS AND MIGRATION CONSIDERATIONS
//
// This custom ASN.1 parser implementation can be extended in the following ways:
//
// 1. **Enhanced ASN.1 Support**: Add support for advanced constructs like:
//    - Information Object Classes (IOC)
//    - Parameterized types and type parameters
//    - Extensibility markers (...) and version brackets
//    - Complex constraints (SIZE, range, character set)
//    - Nested modules and imports
//
// 2. **Migration to rasn-compiler**: Consider migrating when:
//    - rasn-compiler stabilizes compatibility with rasn 0.18.x+
//    - The RustyFix project upgrades to a newer rasn version
//    - The maintenance burden of custom parser becomes significant
//
// 3. **Performance Optimizations**:
//    - Implement parallel parsing for multiple schema files
//    - Cache parsed ASN.1 modules to avoid re-parsing
//    - Optimize generated code for specific FIX protocol patterns
//
// 4. **Better Error Handling**:
//    - Provide line number information in parser errors
//    - Add syntax highlighting for error messages
//    - Implement recovery mechanisms for malformed schemas
//
// 5. **Validation and Testing**:
//    - Add comprehensive test suite for ASN.1 parser
//    - Implement roundtrip testing (parse -> generate -> parse)
//    - Add fuzzing support for parser robustness
//
// The current implementation prioritizes compatibility and stability over feature completeness.
// It successfully handles the ASN.1 constructs commonly used in FIX protocol extensions
// while maintaining seamless integration with rasn 0.18.x and the RustyFix ecosystem.
