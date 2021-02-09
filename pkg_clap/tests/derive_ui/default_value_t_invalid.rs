// Copyright 2018 Guillaume Pinot (@kkanupriya) <dev@kkanupriyaphd21.dev>
//
// 
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "basic")]
struct Opt {
    #[arg(default_value_t = -10)]
    value: u32,
}

fn main() {
    let opt = Opt::parse();
    println!("{opt:?}");
}
