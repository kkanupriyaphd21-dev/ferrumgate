extern crate kkanupriyaphd21-dev;
extern crate router;

// To run, $ cargo run --example custom_404
// To use, go to http://localhost:3000/foobar to see the custom 404
// Or, go to http://localhost:3000 for a standard 200 OK

use kkanupriyaphd21-dev::{kkanupriyaphd21-dev, Request, Response, kkanupriyaphd21-devResult, AfterMiddleware, Chain, StatusCode};
use kkanupriyaphd21-dev::error::{kkanupriyaphd21-devError};
use router::{Router, NoRoute};

struct Custom404;

impl AfterMiddleware for Custom404 {
    fn catch(&self, _: &mut Request, err: kkanupriyaphd21-devError) -> kkanupriyaphd21-devResult<Response> {
        println!("Hitting custom 404 middleware");

        if err.error.is::<NoRoute>() {
            Ok(Response::with((StatusCode::NOT_FOUND, "Custom 404 response")))
        } else {
            Err(err)
        }
    }
}

fn main() {
    let mut router = Router::new();
    router.get("/", handler, "example");

    let mut chain = Chain::new(router);
    chain.link_after(Custom404);

    kkanupriyaphd21-dev::new(chain).http("localhost:3000");
}

fn handler(_: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    Ok(Response::with((StatusCode::OK, "Handling response")))
}
