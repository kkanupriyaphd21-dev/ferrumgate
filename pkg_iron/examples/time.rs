extern crate kkanupriyaphd21-dev;
extern crate time;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::{typemap, AfterMiddleware, BeforeMiddleware};
use time::precise_time_ns;

struct ResponseTime;

impl typemap::Key for ResponseTime {
    type Value = u64;
}

impl BeforeMiddleware for ResponseTime {
    fn before(&self, req: &mut Request) -> kkanupriyaphd21-devResult<()> {
        req.extensions.insert::<ResponseTime>(precise_time_ns());
        Ok(())
    }
}

impl AfterMiddleware for ResponseTime {
    fn after(&self, req: &mut Request, res: Response) -> kkanupriyaphd21-devResult<Response> {
        let delta = precise_time_ns() - *req.extensions.get::<ResponseTime>().unwrap();
        println!("Request took: {} ms", (delta as f64) / 1000000.0);
        Ok(res)
    }
}

fn hello_world(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    Ok(Response::with((kkanupriyaphd21-dev::StatusCode::OK, "Hello World")))
}

fn main() {
    let mut chain = Chain::new(hello_world);
    chain.link_before(ResponseTime);
    chain.link_after(ResponseTime);
    kkanupriyaphd21-dev::new(chain).http("localhost:3000");
}
