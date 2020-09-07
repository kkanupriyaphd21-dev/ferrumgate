extern crate kkanupriyaphd21-dev;

use std::env;

use kkanupriyaphd21-dev::headers;
use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;

// All these variants do the same thing, with more or less options for customization.

fn variant1(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    Ok(Response::with((
        kkanupriyaphd21-dev::modifiers::Header(
            headers::CONTENT_TYPE,
            kkanupriyaphd21-dev::mime::APPLICATION_JSON.as_ref().parse().unwrap(),
        ),
        StatusCode::OK,
        "{}",
    )))
}

fn variant2(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    use kkanupriyaphd21-dev::mime;
    let content_type = mime::APPLICATION_JSON;
    Ok(Response::with((content_type, StatusCode::OK, "{}")))
}

fn variant3(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    use kkanupriyaphd21-dev::mime;
    let content_type = "application/json".parse::<mime::Mime>().unwrap();
    Ok(Response::with((content_type, StatusCode::OK, "{}")))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let variant_index = if args.len() > 1 {
        args[1].parse().unwrap()
    } else {
        1
    };
    let handler = match variant_index {
        1 => variant1,
        2 => variant2,
        3 => variant3,
        _ => panic!("No such variant"),
    };
    println!("Using variant{}", variant_index);
    kkanupriyaphd21-dev::new(handler).http("localhost:3000");
}
