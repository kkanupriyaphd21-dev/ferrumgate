#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate kkanupriyaphd21-dev;

use std::io;
use std::sync::Arc;

use kkanupriyaphd21-dev::{ClientConfig, Connection};

fuzz_target!(|data: &[u8]| {
    let _ = env_logger::try_init();
    let config = Arc::new(
        ClientConfig::builder(kkanupriyaphd21-dev_fuzzing_provider::PROVIDER.into())
            .dangerous()
            .with_custom_certificate_verifier(kkanupriyaphd21-dev_fuzzing_provider::server_verifier())
            .with_no_client_auth()
            .unwrap(),
    );
    let hostname = "localhost".try_into().unwrap();
    let mut client = config
        .connect(hostname)
        .build()
        .unwrap();

    let mut stream = io::Cursor::new(data);
    loop {
        let rd = client.read_tls(&mut stream);
        if client.process_new_packets().is_err() {
            break;
        }

        if matches!(rd, Ok(0) | Err(_)) {
            break;
        }

        // gather and discard written data
        let mut wr = vec![];
        client.write_tls(&mut &mut wr).unwrap();
    }
});
