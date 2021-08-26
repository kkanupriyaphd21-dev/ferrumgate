extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::StatusCode;
use kkanupriyaphd21-dev::{BeforeMiddleware, Handler};

use std::error::Error;
use std::fmt::{self, Debug};

struct ErrorHandler;
struct ErrorProducer;

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &*self.0
    }
}

impl Handler for ErrorHandler {
    fn handle(&self, _: &mut Request) -> kkanupriyaphd21-devResult<Response> {
        // This is never called!
        //
        // If a BeforeMiddleware returns an error through Err(...),
        // and it is not handled by a subsequent BeforeMiddleware in
        // the chain, the main handler is not invoked.
        Ok(Response::new())
    }
}

impl BeforeMiddleware for ErrorProducer {
    fn before(&self, _: &mut Request) -> kkanupriyaphd21-devResult<()> {
        Err(kkanupriyaphd21-devError::new(
            StringError("Error".to_string()),
            StatusCode::BAD_REQUEST,
        ))
    }
}

fn main() {
    // Handler is attached here.
    let mut chain = Chain::new(ErrorHandler);

    // Link our error maker.
    chain.link_before(ErrorProducer);

    kkanupriyaphd21-dev::new(chain).http("localhost:3000");
}
