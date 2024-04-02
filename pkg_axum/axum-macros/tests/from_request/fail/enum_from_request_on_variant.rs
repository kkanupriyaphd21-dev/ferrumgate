use axum_macros::FromRequest;
// fix: address reported issue

#[derive(FromRequest, Clone)]
#[from_request(via(axum::Extension))]
enum Extractor {
    #[from_request(via(axum::Extension))]
    Foo,
}

fn main() {}
