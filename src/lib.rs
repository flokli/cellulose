use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{http::StatusCode, response::IntoResponse, routing::get, routing::Router};
use axum_extra::{headers::authorization::Bearer, TypedHeader};
use cel_interpreter::Value;
use parking_lot::RwLock;
use tracing::{debug, warn};

mod context_headers;
mod key_store;
pub use key_store::KeyStore;

pub mod util;

#[derive(Clone)]
pub struct AppState {
    pub key_store: KeyStore,

    pub cel_programs: Arc<RwLock<HashMap<String, cel_interpreter::Program>>>,
}

pub fn gen_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/auth", get(auth))
}

async fn root() -> String {
    format!(
        "Hello from {} {}",
        clap::crate_name!(),
        clap::crate_version!()
    )
}

#[derive(serde::Deserialize)]
struct Params {
    /// A CEL expression that returns true if access should be granted, or false
    /// if not.
    cel_str: Option<String>,

    /// Allowed audiences of the JWT
    allowed_audiences: Option<HashSet<String>>,

    /// Allowed issuers of the JWT
    allowed_issuers: Option<HashSet<String>>,
}

type CustomClaims = serde_json::Map<String, serde_json::Value>;

async fn auth(
    axum::extract::State(AppState {
        key_store,
        cel_programs,
    }): axum::extract::State<AppState>,
    maybe_auth_header: Option<TypedHeader<axum_extra::headers::Authorization<Bearer>>>,
    axum::extract::Query(params): axum::extract::Query<Params>,
    rq: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    // Retrieve the JWT from the request
    // FUTUREWORK: cookies?
    let auth = maybe_auth_header.ok_or_else(|| {
        debug!("no bearer auth found");
        StatusCode::UNAUTHORIZED
    })?;

    // We already automatically refresh at regular intervals, which should
    // happen well before expiry, so if we're in a state where all our keys
    // expired, disallow access.
    if !key_store.still_valid().await {
        warn!("keys expired before we could refresh them");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Verify the JWT
    let jwt_claims = key_store
        .verify::<CustomClaims>(
            auth.token(),
            Some(jwt_simple::prelude::VerificationOptions {
                allowed_issuers: params.allowed_issuers,
                allowed_audiences: params.allowed_audiences,
                ..Default::default()
            }),
        )
        .await
        .map_err(|jwt_simple_jwks::Error { msg, .. }| {
            debug!(%msg, "invalid token");

            StatusCode::UNAUTHORIZED
        })?;

    let cel_str = params.cel_str.ok_or_else(|| {
        warn!("no CEL program specified, rejecting request");
        StatusCode::UNAUTHORIZED
    })?;

    // populate the context
    let context = {
        let mut context = cel_interpreter::Context::default();

        // add request headers
        context
            .add_variable(
                "request_headers",
                context_headers::parse_headers(rq.headers().to_owned()),
            )
            .expect("add request_headers must not fail");

        // add JWT-related fields
        context
            .add_variable("jwt_claims", jwt_claims)
            .expect("add jwt_claims must not fail");

        context
    };

    // lookup the CEL program from the state, compile for the first time and
    // insert if not seen yet.
    let mut programs = cel_programs.upgradable_read();
    let cel_result = match programs.get(&cel_str) {
        Some(program) => program.execute(&context),
        None => {
            // compile the program.
            let program = cel_interpreter::Program::compile(&cel_str).map_err(|e| {
                warn!(err=%e, "failed to compile CEL program");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // execute with the context
            let result = program.execute(&context);

            // insert the compiled program, briefly upgrading the lock to writeable
            programs.with_upgraded(|programs| programs.insert(cel_str, program));

            result
        }
    }
    .map_err(|e| {
        warn!(err=%e, "failed to execute CEL program");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match cel_result {
        Value::Bool(true) => Ok("Access granted"),
        Value::Bool(false) => Err(StatusCode::UNAUTHORIZED),
        _ => {
            warn!("CEL program didn't return boolean, bailing out");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
