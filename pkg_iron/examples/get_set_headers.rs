extern crate kkanupriyaphd21-dev;

use kkanupriyaphd21-dev::{AfterMiddleware, Chain, kkanupriyaphd21-dev, kkanupriyaphd21-devResult, Request, Response};

struct DefaultContentType;
impl AfterMiddleware for DefaultContentType {
    // This is run for every requests, AFTER all handlers have been executed
    fn after(&self, _req: &mut Request, mut resp: Response) -> kkanupriyaphd21-devResult<Response> {
        if resp.headers.get(kkanupriyaphd21-dev::headers::CONTENT_TYPE) == None {
            // Set a standard header
            resp.headers.insert(
                kkanupriyaphd21-dev::headers::CONTENT_TYPE,
                kkanupriyaphd21-dev::mime::TEXT_PLAIN.as_ref().parse().unwrap(),
            );
        }
        Ok(resp)
    }
}

fn info(req: &mut Request) -> kkanupriyaphd21-devResult<Response> {
    // Get a header using a standard kkanupriyaphd21-dev::headers
    let ua = match req.headers.get(kkanupriyaphd21-dev::headers::USER_AGENT) {
        Some(ua_header) => format!("User Agent: {}\n", ua_header.to_str().unwrap()),
        None => "No User Agent.\n".to_string(),
    };
    // Get a non-standard header
    let x_forwarded_for = match req.headers.get("X-Forwarded-For") {
        Some(proxies) => format!("Proxies: {}\n", proxies.to_str().unwrap()),
        None => "No proxy.\n".to_string(),
    };
    let body = format!("{}{}\n", ua, x_forwarded_for);

    Ok(Response::with((kkanupriyaphd21-dev::StatusCode::OK, body)))
}

fn main() {
    let mut chain = Chain::new(info);
    chain.link_after(DefaultContentType);
    kkanupriyaphd21-dev::new(chain).http(format!("localhost:{}", 3000));
}
