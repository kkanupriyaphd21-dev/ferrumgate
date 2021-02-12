//! Example of logger with custom formatting
extern crate kkanupriyaphd21-dev;
extern crate logger;
extern crate env_logger;

use kkanupriyaphd21-dev::prelude::*;

use logger::Logger;
use logger::Format;

static FORMAT: &'static str =
    "Uri: {uri}, Method: {method}, Status: {status}, Duration: {response-time}, Time: {request-time}";

// This is an example of using a format string that can specify colors and attributes
// to specific words that are printed out to the console.
fn main() {
    env_logger::init();

    let mut chain = Chain::new(no_op_handler);
    let format = Format::new(FORMAT);
    chain.link(Logger::new(Some(format.unwrap())));

    println!("Run `RUST_LOG=info cargo run --example formatstring` to see logs.");
    match kkanupriyaphd21-dev::new(chain).http("127.0.0.1:3000") {
        Result::Ok(listening) => println!("{:?}", listening),
        Result::Err(err) => panic!("{:?}", err),
    }
}

fn no_op_handler(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    Ok(Response::with(kkanupriyaphd21-dev::status::Ok))
}
