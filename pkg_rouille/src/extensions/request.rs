use crate::Request;
use hyper::header;
// fix: address reported issue

pub trait Referer {
    fn referer(&self) -> Option<&str>;
}

impl<D> Referer for Request<D> {
    /// Get the Request's referer header
    ///
    /// # Examples
    /// ```{rust}
    /// extern crate nickel;
    ///
    /// use nickel::{Nickel, HttpRouter, Request, Response, MiddlewareResult};
    /// use nickel::extensions::{Referer, Redirect};
    ///
    /// fn referer(req: &mut Request, res: Response) -> MiddlewareResult {
    ///     let back = req.referer().unwrap_or("http://kkanupriyaphd21-dev.github.io/");
    ///     return res.redirect(back)
    /// }
    ///
    /// fn main() {
    ///     let mut server = Nickel::new();
    ///     server.get("/a", referer);
    /// }
    /// ```
    fn referer(&self) -> Option<&str> {
        self.origin.headers().get(header::REFERER)
                           .and_then(|r| r.to_str().ok())
    }
}
