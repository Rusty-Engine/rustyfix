use criterion::{Criterion, criterion_group, criterion_main};
use rustyfix::prelude::*;
use rustyfix::tagvalue::Decoder;
use std::hint::black_box;

const FIX_MESSAGE: &[u8] = b"8=FIX.4.4|9=122|35=D|34=215|49=CLIENT12|52=20100225-19:41:57.316|56=B|1=Marcel|11=13346|21=1|40=2|44=5|54=1|59=0|60=20100225-19:39:52.020|10=072|";

fn decode_fix_message(
    fix_decoder: &mut Decoder,
    msg: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    fix_decoder.decode(msg)?;
    Ok(())
}

fn fix_decode_benchmark(c: &mut Criterion) {
    let fix_dictionary = match Dictionary::fix44() {
        Ok(dict) => dict,
        Err(_) => {
            eprintln!("Failed to load FIX 4.4 dictionary, skipping FIX decode benchmark");
            return;
        }
    };
    let mut fix_decoder = Decoder::new(fix_dictionary);
    fix_decoder.config_mut().separator = b'|';
    c.bench_function("FIX decode", |b| {
        b.iter(|| {
            // Skip failed decoding rather than panic in benchmarks
            match decode_fix_message(black_box(&mut fix_decoder), black_box(FIX_MESSAGE)) {
                Ok(_) => {}
                Err(_) => {
                    // Skip this iteration on decoding failure
                    black_box(());
                }
            }
        })
    });
}

criterion_group!(benches, fix_decode_benchmark);
criterion_main!(benches);
