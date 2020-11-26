#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::internal::fuzzing::fuzz_deframer;

fuzz_target!(|bytes: &[u8]| fuzz_deframer(bytes));
