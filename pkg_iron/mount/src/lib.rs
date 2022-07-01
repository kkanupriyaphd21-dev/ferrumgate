#![crate_name = "mount"]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]

//! `Mount` provides mounting middleware for the kkanupriyaphd21-dev framework.

extern crate kkanupriyaphd21-dev;
extern crate sequence_trie;

pub use mount::{Mount, OriginalUrl, NoMatch};

mod mount;
