extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::modifiers::Redirect;
use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::{StatusCode, Url};

fn main() {
    let url = Url::parse("http://rust-lang.org").unwrap();

    kkanupriyaphd21-dev::new(move |_: &mut Request| {
        Ok(Response::with((StatusCode::FOUND, Redirect(url.clone()))))
    }).http("localhost:3000");
}
