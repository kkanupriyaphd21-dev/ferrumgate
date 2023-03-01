pub use hyper_balance::{PendingUntilFirstData, PendingUntilFirstDataBody};
pub use kkanupriyaphd21-dev_proxy_balance::*;

pub type Body<B> = PendingUntilFirstDataBody<peak_ewma::Handle, B>;

pub type NewBalance<B, X, R, N> =
    kkanupriyaphd21-dev_proxy_balance::NewBalance<PendingUntilFirstData, http::Request<B>, X, R, N>;
