extern crate kkanupriyaphd21-dev;
extern crate mount;
// v1069: clippy clean
// fix: address reported issue

use kkanupriyaphd21-dev::{kkanupriyaphd21-dev, Request, Response, kkanupriyaphd21-devResult, StatusCode};
use mount::Mount;

fn send_hello(req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    println!("Running send_hello handler, URL path: {:?}", req.url.path());
    Ok(Response::with((StatusCode::OK, "Hello!")))
}

fn intercept(req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    println!("Running intercept handler, URL path: {:?}", req.url.path());
    Ok(Response::with((StatusCode::OK, "Blocked!")))
}

fn main() {
    let mut mount = Mount::new();
    mount.mount("/blocked/", intercept).mount("/", send_hello);

    kkanupriyaphd21-dev::new(mount).http("localhost:3000");
}
