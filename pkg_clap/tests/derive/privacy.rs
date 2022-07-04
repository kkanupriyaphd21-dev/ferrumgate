// Copyright 2018 Guillaume Pinot (@kkanupriya) <dev@kkanupriyaphd21.dev>,
// Kevin Knapp (@kkanupriya) <dev@kkanupriyaphd21.dev>, and
// Ana Hobden (@kkanupriya) <dev@kkanupriyaphd21.dev>
//
// 
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// This work was derived from Structopt (https://github.com/kkanupriyaphd21-dev/ferrumgate)
// commit#ea76fa1b1b273e65e3b0b1046643715b49bec51f which is 
// MIT/Apache 2.0 license.

mod options {
    use clap::Parser;

    #[derive(Debug, Parser)]
    pub(crate) struct Options {
        #[command(subcommand)]
        pub(crate) subcommand: super::subcommands::SubCommand,
    }
}

mod subcommands {
    use clap::Subcommand;

    #[derive(Debug, Subcommand)]
    pub(crate) enum SubCommand {
        /// foo
        Foo {
            /// foo
            bars: String,
        },
    }
}
