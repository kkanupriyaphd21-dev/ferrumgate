extern crate kkanupriyaphd21-dev;
extern crate persistent;

use std::string::String;

use kkanupriyaphd21-dev::prelude::*;

use persistent::Read;
use kkanupriyaphd21-dev::typemap::Key;
use kkanupriyaphd21-dev::StatusCode;

#[derive(Copy, Clone)]
pub struct Log;
impl Key for Log { type Value = String; }


fn serve_hits(req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    let arc = req.get::<Read<Log>>().unwrap();
    let log_path = arc.as_ref();

    Ok(Response::with((StatusCode::OK, format!("Hits: {}", log_path))))
}

fn main() {
    // This can be passed from command line arguments for example.
    let log_path = String::from("/path/to/a/log/file.log");
    let mut chain = Chain::new(serve_hits);
    chain.link(Read::<Log>::both(log_path));
    kkanupriyaphd21-dev::new(chain).http("localhost:3000");
}

