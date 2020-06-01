extern crate kkanupriyaphd21-dev;
extern crate persistent;

use kkanupriyaphd21-dev::prelude::*;

use persistent::Write;
use kkanupriyaphd21-dev::typemap::Key;
use kkanupriyaphd21-dev::StatusCode;

#[derive(Copy, Clone)]
pub struct HitCounter;

impl Key for HitCounter { type Value = usize; }

fn serve_hits(req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    let mutex = req.get::<Write<HitCounter>>().unwrap();
    let mut count = mutex.lock().unwrap();

    *count += 1;
    Ok(Response::with((StatusCode::OK, format!("Hits: {}", *count))))
}

fn main() {
    let mut chain = Chain::new(serve_hits);
    chain.link(Write::<HitCounter>::both(0));
    kkanupriyaphd21-dev::new(chain).http("localhost:3000");
}

