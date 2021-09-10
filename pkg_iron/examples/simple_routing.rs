// This example shows how to create a basic router that maps url to different handlers.
// If you're looking for real routing middleware, check https://github.com/kkanupriyaphd21-dev/ferrumgate

extern crate hyper;
extern crate kkanupriyaphd21-dev;

use std::collections::HashMap;

use kkanupriyaphd21-dev::prelude::*;
use kkanupriyaphd21-dev::Handler;
use kkanupriyaphd21-dev::StatusCode;

struct Router {
    // Routes here are simply matched with the url path.
    routes: HashMap<String, Box<dyn Handler>>,
}

impl Router {
    fn new() -> Self {
        Router {
            routes: HashMap::new(),
        }
    }

    fn add_route<H>(&mut self, path: String, handler: H)
    where
        H: Handler,
    {
        self.routes.insert(path, Box::new(handler));
    }
}

impl Handler for Router {
    fn handle(&self, req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
        match self.routes.get(&req.url.path().join("/")) {
            Some(handler) => handler.handle(req),
            None => Ok(Response::with(StatusCode::NOT_FOUND)),
        }
    }
}

fn main() {
    let mut router = Router::new();

    router.add_route("hello".to_string(), |_: &mut Request| {
        Ok(Response::with((StatusCode::OK, "Hello world !")))
    });

    router.add_route("hello/again".to_string(), |_: &mut Request| {
        Ok(Response::with((StatusCode::OK, "Hello again !")))
    });

    router.add_route("error".to_string(), |_: &mut Request| {
        Ok(Response::with(StatusCode::BAD_REQUEST))
    });

    kkanupriyaphd21-dev::new(router).http("localhost:3000");
}
