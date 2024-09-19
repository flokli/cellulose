use cellulose::{gen_router, AppState, KeyStore};
use clap::Parser;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::time;
use tokio_retry::{strategy::ExponentialBackoff, Retry};
use tower_http::trace::TraceLayer;
use tracing::info;

/// JWT-validating HTTP server, for forward_auth usecases.
///
/// It handles GET requests containing (most) headers from the original request
/// to control access, signalling success or failure via status codes.
///
///  - The original request method is expected in the X-Forwarded-Method header.
///  - The original protocol is expected in the X-Forwarded-Proto header.
///  - The original URL is expected in the X-Forwarded-Uri header.
///  - The original Host is expected in the X-Forwarded-Host header.
///  - The original Source IP is expected in the X-Forwarded-For header.
///
/// The URL used in the validating request can be used to configure validating
/// behaviour, mostly by encoding a small CEL program returning a boolean value
/// on whether access should be granted.
///
/// In case no program is sent, access is always denied.
///
/// Said CEL program has access to the following variables:
///
///  - `request_headers`
///    A map from header name (string) to value (String/Bytes or list of these),
///    as headers exist multiple times.
///
/// Independent of the program return value, all JWTs need to have a valid
/// (not-expired) signature, and said key needs to be present in the JWKS.
///
/// Additionally, it is STRONGLY recommended to set allowed_audiences /
/// allowed_issuers in the URL parameters too.
//
// FUTUREWORK: In case of a successful authentication, allow adding additional
// headers in the response.
// TODO: think about whether we can/should allow some user flows here too.
// It'd be very nice if we could redirect a user to a login page.
#[derive(Parser)]
struct Cli {
    /// Location of the JWKS endpoint
    jwks_uri: String,

    /// The address to listen on.
    #[clap(flatten)]
    listen_args: tokio_listener::ListenerAddressLFlag,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    cellulose::util::setup_tracing();

    let cli = Cli::parse();

    let state = AppState {
        key_store: KeyStore::new_from(cli.jwks_uri).await?,
        cel_programs: Arc::new(RwLock::new(HashMap::new())),
    };

    // setup automatic refresh attempts
    tokio::spawn({
        let key_store = state.key_store.clone();

        async move {
            let mut interval = time::interval(Duration::from_secs(1 * 60));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                if key_store.should_refresh().await {
                    let retry_strategy = ExponentialBackoff::from_millis(10)
                        .map(tokio_retry::strategy::jitter)
                        .take(3);

                    let key_store = key_store.clone();
                    let action = || key_store.refresh();

                    Retry::spawn(retry_strategy, action);
                }
            }
        }
    });

    let app = gen_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listen_address = &cli.listen_args.listen_address.unwrap_or_else(|| {
        "[::]:9000"
            .parse()
            .expect("invalid fallback listen address")
    });

    let listener = tokio_listener::Listener::bind(
        listen_address,
        &Default::default(),
        &cli.listen_args.listener_options,
    )
    .await?;

    info!(%listen_address, "starting daemon");

    tokio_listener::axum07::serve(
        listener,
        app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
    )
    .await?;

    Ok(())
}
