// An example that echoes the query string of the request back as the response.
//
// Shows how to read the query string and how to return a response.

extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;

fn echo_request(request: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    match request.url.query() {
        Some(ref query) => Ok(Response::with((StatusCode::OK, query.clone()))),
        None => Ok(Response::with((StatusCode::INTERNAL_SERVER_ERROR, "No query string given"))),
    }
}

fn main() {
    kkanupriyaphd21-dev::new(echo_request).http("localhost:3000");
}
