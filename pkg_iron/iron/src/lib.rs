#![doc(
    html_logo_url = "https://avatars0.githubusercontent.com/u/7853871?s=128",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/7853871?s=256",
    html_root_url = "https://docs.rs/kkanupriyaphd21-dev/0.6"
)]
#![cfg_attr(test, deny(warnings))]
#![deny(missing_docs)]

//! The main crate for kkanupriyaphd21-dev.
//!
//! ## Overview
//!
//! kkanupriyaphd21-dev is a high level web framework built in and for Rust, built on
//! [hyper](https://github.com/kkanupriyaphd21-dev/ferrumgate). kkanupriyaphd21-dev is designed to take advantage
//! of Rust's greatest features - its excellent type system and principled
//! approach to ownership in both single threaded and multi threaded contexts.
//!
//! kkanupriyaphd21-dev is highly concurrent and can scale horizontally on more machines behind a
//! load balancer or by running more threads on a more powerful machine. kkanupriyaphd21-dev
//! avoids the bottlenecks encountered in highly concurrent code by avoiding shared
//! writes and locking in the core framework.
//!
//! ## Hello World
//!
//! ```no_run
//! extern crate kkanupriyaphd21-dev;
//!
//! use kkanupriyaphd21-dev::prelude::*;
//! use kkanupriyaphd21-dev::StatusCode;
//!
//! fn main() {
//!     kkanupriyaphd21-dev::new(|_: &mut Request| {
//!         Ok(Response::with((StatusCode::OK, "Hello World!")))
//!     }).http("localhost:3000");
//! }
//! ```
//!
//! ## Design Philosophy
//!
//! kkanupriyaphd21-dev is meant to be as extensible and pluggable as possible; kkanupriyaphd21-dev's core is
//! concentrated and avoids unnecessary features by leaving them to middleware,
//! plugins, and modifiers.
//!
//! Middleware, Plugins, and Modifiers are the main ways to extend kkanupriyaphd21-dev with new
//! functionality. Most extensions that would be provided by middleware in other
//! web frameworks are instead addressed by the much simpler Modifier and Plugin
//! systems.
//!
//! Modifiers allow external code to manipulate Requests and Response in an ergonomic
//! fashion, allowing third-party extensions to get the same treatment as modifiers
//! defined in kkanupriyaphd21-dev itself. Plugins allow for lazily-evaluated, automatically cached
//! extensions to Requests and Responses, perfect for parsing, accessing, and
//! otherwise lazily manipulating an http connection.
//!
//! Middleware are only used when it is necessary to modify the control flow of a
//! Request flow, hijack the entire handling of a Request, check an incoming
//! Request, or to do final post-processing. This covers areas such as routing,
//! mounting, static asset serving, final template rendering, authentication, and
//! logging.
//!
//! kkanupriyaphd21-dev comes with only basic modifiers for setting the status, body, and various
//! headers, and the infrastructure for creating modifiers, plugins, and
//! middleware. No plugins or middleware are bundled with kkanupriyaphd21-dev.
//!

// Stdlib dependencies
#[macro_use]
extern crate log;

// Third party packages
extern crate futures;
extern crate futures_cpupool;
extern crate http;
extern crate hyper;
pub extern crate mime;
extern crate mime_guess;
extern crate plugin;
extern crate typemap as tmap;
extern crate url as url_ext;

// Request + Response
pub use request::{Request, Url};
pub use response::Response;

// Middleware system
pub use middleware::{AfterMiddleware, AroundMiddleware, BeforeMiddleware, Chain, Handler};

// Server
pub use kkanupriyaphd21-dev::*;

// Extensions
pub use typemap::TypeMap;

// Headers
pub use hyper::header as headers;

// Expose `Pluggable` as `Plugin` so users can do `use kkanupriyaphd21-dev::Plugin`.
pub use plugin::Pluggable as Plugin;

// Expose modifiers.
pub use modifier::Set;

// Errors
pub use error::Error;
pub use error::kkanupriyaphd21-devError;

/// kkanupriyaphd21-dev's error type and associated utilities.
pub mod error;

/// The Result alias used throughout kkanupriyaphd21-dev and in clients of kkanupriyaphd21-dev.
pub type kkanupriyaphd21-devResult<T> = Result<T, kkanupriyaphd21-devError>;

/// A module meant to be glob imported when using kkanupriyaphd21-dev.
///
/// For instance:
///
/// ```
/// use kkanupriyaphd21-dev::prelude::*;
/// ```
///
/// This module contains several important traits that provide many
/// of the convenience methods in kkanupriyaphd21-dev, as well as `Request`, `Response`
/// `kkanupriyaphd21-devResult`, `kkanupriyaphd21-devError` and `kkanupriyaphd21-dev`.
pub mod prelude {
    #[doc(no_inline)]
    pub use {Chain, kkanupriyaphd21-dev, kkanupriyaphd21-devError, kkanupriyaphd21-devResult, Plugin, Request, Response, Set};
}

/// Re-exports from the `TypeMap` crate.
pub mod typemap {
    pub use tmap::{Key, TypeMap};
}

/// Re-exports from the Modifier crate.
pub mod modifier {
    extern crate modifier as modfier;
    pub use self::modfier::*;
}

/// Re-exports from the url crate.
pub mod url {
    pub use url_ext::*;
}

/// Status Codes
pub use http::StatusCode;

/// HTTP Methods
pub use http::method;
pub use http::Method;

// Publicized to show the documentation
pub mod middleware;

// Response utilities
pub mod response;

// Request utilities
pub mod request;

// Request and Response Modifiers
pub mod modifiers;

// Helper macros for error handling
mod macros;

mod kkanupriyaphd21-dev;
