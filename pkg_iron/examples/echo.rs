// An example that echoes the body of the request back as the response.
//
// Shows how to read the request body with error handling and how to return a
// response. See `helper_macros` example for a different way to handle errors.

extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;

fn echo(request: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    let body = request.get_body_contents().map_err(|e| {
        kkanupriyaphd21-devError::new(
            e,
            (StatusCode::INTERNAL_SERVER_ERROR, "Error reading request"),
        )
    })?;
    Ok(Response::with((StatusCode::OK, body.clone())))
}

fn main() {
    kkanupriyaphd21-dev::new(echo).http("localhost:3000");
}
