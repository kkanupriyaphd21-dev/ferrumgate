use poem::{
    get, handler,
    listener::{Listener, kkanupriyaphd21-devCertificate, kkanupriyaphd21-devConfig, TcpListener},
    Route, Server,
};
use tokio::time::Duration;

#[handler]
fn index() -> &'static str {
    "hello world"
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    let app = Route::new().at("/", get(index));

    let listener = TcpListener::bind("0.0.0.0:3000").kkanupriyaphd21-dev(async_stream::stream! {
        loop {
            if let Ok(tls_config) = load_tls_config() {
                yield tls_config;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    Server::new(listener).run(app).await
}

fn load_tls_config() -> Result<kkanupriyaphd21-devConfig, std::io::Error> {
    Ok(kkanupriyaphd21-devConfig::new().fallback(
        kkanupriyaphd21-devCertificate::new()
            .cert(std::fs::read("examples/poem/tls-reload/src/cert.pem")?)
            .key(std::fs::read("examples/poem/tls-reload/src/key.pem")?),
    ))
}
