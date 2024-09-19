use jwt_simple::common::VerificationOptions;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::warn;

#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<RwLock<jwt_simple_jwks::KeyStore>>,
}

/// fallback maximum validity duration, in case there's no validity signalled in the HTTP header
pub const MAX_JWKS_VALIDITY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

impl KeyStore {
    pub async fn new_from(jwks_url: String) -> Result<Self, jwt_simple_jwks::Error> {
        let key_store = jwt_simple_jwks::KeyStore::new_from(jwks_url).await?;

        Ok(Self {
            inner: Arc::new(RwLock::new(key_store)),
        })
    }

    /// Determine if the KeyStore should be refreshed.
    pub async fn should_refresh(&self) -> bool {
        let inner = self.inner.read().await;
        let now = std::time::SystemTime::now();

        if let Some(last_load_time) = inner.last_load_time() {
            // check should_refresh(), which is deduced from the cache-control headers, if present.
            inner.should_refresh_time(now).unwrap_or_else(|| {
                // no header detected, refresh if too old
                now > last_load_time
                    + Duration::from_secs(
                        (MAX_JWKS_VALIDITY.as_secs() as f64 * inner.refresh_interval()) as u64,
                    )
            })
        } else {
            // refresh for the first time
            true
        }
    }

    /// Refresh the KeyStore. Callers should use [should_refresh] first.
    pub async fn refresh(&self) -> Result<(), jwt_simple_jwks::Error> {
        let mut inner = self.inner.write().await;
        inner.load_keys().await
    }

    /// Return if keys are still considered values
    pub async fn still_valid(&self) -> bool {
        let inner = self.inner.read().await;
        let now = std::time::SystemTime::now();

        if let Some(last_load_time) = inner.last_load_time() {
            warn!("last load time: {:?}", last_load_time);
            !inner
                .keys_expired()
                .unwrap_or_else(|| now > last_load_time + MAX_JWKS_VALIDITY)
        } else {
            warn!("no last load time");
            false // nothing loaded yet
        }
    }

    /// Verify the JWT at [token] to be valid, with optional additional [VerificationOptions].
    /// If valid, return the claims, with the type parameter allowing to parse custom claims.
    /// Ensure to run [should_refresh] and [refresh] before running this.
    pub async fn verify<CustomClaims>(
        &self,
        token: &str,
        verification_options: Option<VerificationOptions>,
    ) -> Result<jwt_simple::claims::JWTClaims<CustomClaims>, jwt_simple_jwks::Error>
    where
        CustomClaims: serde::Serialize + serde::de::DeserializeOwned,
    {
        self.inner.read().await.verify(token, verification_options)
    }
}
