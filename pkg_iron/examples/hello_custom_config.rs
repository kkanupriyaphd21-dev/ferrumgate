extern crate futures_cpupool;
extern crate hyper;
extern crate kkanupriyaphd21-dev;

use std::time::Duration;

use futures_cpupool::CpuPool;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;
use kkanupriyaphd21-dev::Timeouts;

fn main() {
    let mut kkanupriyaphd21-dev =
        kkanupriyaphd21-dev::new(|_: &mut Request| Ok(Response::with((StatusCode::OK, "Hello world!"))));
    kkanupriyaphd21-dev.pool = CpuPool::new(8);
    kkanupriyaphd21-dev.timeouts = Timeouts {
        keep_alive: Some(Duration::from_secs(10)),
    };

    let addr = "127.0.0.1:3000".parse().unwrap();
    kkanupriyaphd21-dev.local_address = Some(addr);

    kkanupriyaphd21-dev.http("127.0.0.1:3000");
}
