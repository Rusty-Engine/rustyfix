use rustyfix_dictionary::Dictionary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dict = Dictionary::fix44()?;
    
    if let Some(field) = dict.field_by_tag(95) {
        println\!("Tag 95: {} ({})", field.name(), field.tag().get());
    } else {
        println\!("Tag 95: Not found");
    }
    
    if let Some(field) = dict.field_by_tag(96) {
        println\!("Tag 96: {} ({})", field.name(), field.tag().get());
    } else {
        println\!("Tag 96: Not found");
    }
    
    // Search for SecureData field
    if let Some(field) = dict.field_by_name("SecureData") {
        println\!("SecureData: Tag {} ({})", field.tag().get(), field.name());
    } else {
        println\!("SecureData: Not found");
    }
    
    Ok(())
}
