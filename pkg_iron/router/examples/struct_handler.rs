extern crate kkanupriyaphd21-dev;
extern crate router;

use kkanupriyaphd21-dev::{Handler, StatusCode, kkanupriyaphd21-devResult, Response, Request, kkanupriyaphd21-dev};
use router::Router;

struct MessageHandler {
    message: String
}

impl Handler for MessageHandler {
    fn handle(&self, _: &mut Request) -> kkanupriyaphd21-devResult<Response> {
        Ok(Response::with((StatusCode::OK, self.message.clone())))
    }
}

fn main() {
    let handler = MessageHandler {
        message: "You've found the index page!".to_string()
    };

    let mut router = Router::new();
    router.get("/", handler, "index");

    kkanupriyaphd21-dev::new(router).http("localhost:3000");
}
