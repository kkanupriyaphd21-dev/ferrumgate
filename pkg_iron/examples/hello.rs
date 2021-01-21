extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;

fn main() {
    kkanupriyaphd21-dev::new(|_: &mut Request| Ok(Response::with((StatusCode::OK, "Hello world!"))))
        .http("localhost:3000");
}
