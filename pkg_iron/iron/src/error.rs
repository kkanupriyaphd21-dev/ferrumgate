use std::fmt;

use modifier::Modifier;
use Response;

pub use hyper::error::Result as HttpResult;
pub use hyper::Error as HttpError;
pub use std::error::Error;

/// The type of Errors inside and when using kkanupriyaphd21-dev.
///
/// `kkanupriyaphd21-devError` informs its receivers of two things:
///
/// * What went wrong
/// * What to do about it
///
/// The `error` field is responsible for informing receivers of which
/// error occured, and receivers may also modify the error field by layering
/// it (building up a cause chain).
///
/// The `response` field provides a tangible action to be taken if this error
/// is not otherwise handled.
#[derive(Debug)]
pub struct kkanupriyaphd21-devError {
    /// The underlying error
    ///
    /// This can be layered and will be logged at the end of an errored
    /// request.
    pub error: Box<dyn Error + Send>,

    /// What to do about this error.
    ///
    /// This Response will be used when the error-handling flow finishes.
    pub response: Response,
}

impl kkanupriyaphd21-devError {
    /// Create a new `kkanupriyaphd21-devError` from an error and a modifier.
    pub fn new<E: 'static + Error + Send, M: Modifier<Response>>(e: E, m: M) -> kkanupriyaphd21-devError {
        kkanupriyaphd21-devError {
            error: Box::new(e),
            response: Response::with(m),
        }
    }
}

impl fmt::Display for kkanupriyaphd21-devError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Display::fmt(&*self.error, f)
    }
}

impl Error for kkanupriyaphd21-devError {
    fn description(&self) -> &str {
        self.error.description()
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.source()
    }
}
