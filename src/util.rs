use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn setup_tracing() {
    let subscriber = tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env()
                .expect("Invalid RUST_LOG"),
        )
        .with(
            tracing_subscriber::fmt::Layer::new()
                .with_writer(std::io::stderr)
                .compact(),
        );

    subscriber.try_init().expect("failed to setup tracing");
}
