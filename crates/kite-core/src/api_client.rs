use std::{fmt, sync::Arc, time::Duration};

use reqwest::{Client, Response};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{DeviceInfo, EngineError, Result};

#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: [u8; 32],
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate fingerprint mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    client: Client,
}

impl fmt::Debug for ApiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
pub struct BundleDto {
    pub ik: String,
    pub spk: String,
    pub spk_sig: String,
    pub opk_id: Option<u32>,
    pub opk: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MailEntry {
    pub seq: i64,
    pub from: String,
    pub kind: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

impl ApiClient {
    pub fn new(base_url: &str, server_fingerprint: &str) -> Result<Self> {
        let fingerprint: [u8; 32] = hex::decode(server_fingerprint.trim())
            .map_err(|error| EngineError::Configuration(error.to_string()))?
            .try_into()
            .map_err(|_| EngineError::Configuration("fingerprint must be SHA-256 hex".into()))?;
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let tls = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|error| EngineError::Configuration(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
                fingerprint,
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth();
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(35))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
        })
    }

    async fn json<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            let message = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| value["error"]["message"].as_str().map(str::to_owned))
                .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
            return Err(EngineError::Server { status, message });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn register(&self, body: Value) -> Result<String> {
        let response = self
            .client
            .post(format!("{}/api/v1/register", self.base_url))
            .json(&body)
            .send()
            .await?;
        Ok(self.json::<TokenResponse>(response).await?.token)
    }

    pub async fn devices(&self, token: &str) -> Result<Vec<DeviceInfo>> {
        let response = self
            .client
            .get(format!("{}/api/v1/devices", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;
        self.json(response).await
    }

    pub async fn bundle(&self, token: &str, peer: &str) -> Result<BundleDto> {
        let response = self
            .client
            .get(format!("{}/api/v1/bundles/{peer}", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;
        self.json(response).await
    }

    pub async fn send(&self, token: &str, to: &str, kind: &str, payload: String) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/api/v1/send", self.base_url))
            .bearer_auth(token)
            .json(&json!({"to": to, "kind": kind, "payload": payload, "ts": unix_time()?}))
            .send()
            .await?;
        self.json::<Value>(response).await?;
        Ok(())
    }

    pub async fn pair_request(&self, token: &str, to: &str, payload: String) -> Result<()> {
        self.pair(token, "/api/v1/pair/request", to, true, payload)
            .await
    }

    pub async fn pair_response(
        &self,
        token: &str,
        to: &str,
        accept: bool,
        payload: String,
    ) -> Result<()> {
        self.pair(token, "/api/v1/pair/respond", to, accept, payload)
            .await
    }

    async fn pair(
        &self,
        token: &str,
        path: &str,
        to: &str,
        accept: bool,
        payload: String,
    ) -> Result<()> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(&json!({"to": to, "accept": accept, "payload": payload}))
            .send()
            .await?;
        self.json::<Value>(response).await?;
        Ok(())
    }

    pub async fn sync(&self, token: &str, since: i64) -> Result<Vec<MailEntry>> {
        let response = self
            .client
            .get(format!("{}/api/v1/sync", self.base_url))
            .bearer_auth(token)
            .query(&[("since", since)])
            .send()
            .await?;
        self.json(response).await
    }

    pub async fn ack(&self, token: &str, until_seq: i64) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/api/v1/ack", self.base_url))
            .bearer_auth(token)
            .json(&json!({"until_seq": until_seq}))
            .send()
            .await?;
        self.json::<Value>(response).await?;
        Ok(())
    }
}

fn unix_time() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| EngineError::Configuration(error.to_string()))?
        .as_secs() as i64)
}
