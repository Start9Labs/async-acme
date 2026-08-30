/*! Automatic Certificate Management Environment (ACME) acording to [rfc8555](https://datatracker.ietf.org/doc/html/rfc8555)

*/
use generic_async_http_client::{Error as HTTPError, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryInto;
use std::net::IpAddr;
use thiserror::Error;

pub(crate) mod account;
pub use account::Account;

use crate::cache::CacheError;

/// URI of <https://letsencrypt.org/> staging Directory. Use this for tests. See <https://letsencrypt.org/docs/staging-environment/>
pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
/// URI of <https://letsencrypt.org/> prod Directory. Certificates aquired from this are trusted by most Browsers.
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
/// ALPN string used by ACME-TLS challanges
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

/// An ACME directory. Containing the REST endpoints of an ACME provider
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl Directory {
    ///query the endpoints from a discovery url
    pub async fn discover(url: &str) -> Result<Self, AcmeError> {
        Ok(Request::get(url).exec().await?.json().await?)
    }
    pub async fn nonce(&self) -> Result<String, AcmeError> {
        let response = Request::get(self.new_nonce.as_str()).exec().await?;
        get_header(&response, "replay-nonce")
    }
}

/// Challange used to prove ownership over a domain
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// State of an ACME request
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Order {
    /// [`Auth`] for authorizations must be completed
    Pending {
        /// URLs for ([`Account::check_auth`](./struct.Account.html#method.check_auth))
        authorizations: Vec<String>,
        /// URL to send CSR to
        finalize: String,
    },
    /// [`Auth`] is done. CSR can be sent ([`Account::send_csr`](./struct.Account.html#method.send_csr))
    Ready {
        /// URL to send CSR to
        finalize: String,
    },
    /// CSR is done. Certificate can be downloaded ([`Account::obtain_certificate`](./struct.Account.html#method.obtain_certificate))
    Valid {
        /// URL to fetch the final Certificate
        certificate: String,
    },
    Invalid,
    Processing {
        authorizations: Vec<String>,
        finalize: String,
    },
}

///Authentication status for a particular challange
///
/// Can be obtained by [`Account::check_auth`](./struct.Account.html#method.check_auth)
/// and is driven by triggering and completing challanges
#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Auth {
    /// challange must be triggered
    Pending {
        /// host to authenticate
        identifier: Identifier,
        /// challenges to complete in order to authenticate
        challenges: Vec<Challenge>,
    },
    /// ownership is proven
    Valid,
    /// a challenge failed; the reason is that challenge's [`Challenge::error`]
    Invalid {
        /// host that could not be authenticated
        identifier: Identifier,
        #[serde(default)]
        challenges: Vec<Challenge>,
        /// RFC 8555 §7.1.4 defines no `error` here, but keep whatever a server sends
        #[serde(default)]
        error: Value,
    },
    Revoked,
    Expired,
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending { identifier, .. } => {
                write!(f, "authorization for {identifier} is pending")
            }
            Self::Valid => f.write_str("authorization is valid"),
            Self::Invalid {
                identifier,
                challenges,
                error,
            } => {
                write!(f, "authorization for {identifier} failed")?;
                if let Some(problem) = challenges.iter().find_map(|c| c.error.as_ref()) {
                    write!(f, ": {problem}")
                } else if !error.is_null() {
                    write!(f, ": {error}")
                } else {
                    Ok(())
                }
            }
            Self::Revoked => f.write_str("authorization was revoked"),
            Self::Expired => f.write_str("authorization has expired"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
    Ip(IpAddr),
}
impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns(a) => a.fmt(f),
            Self::Ip(a) => a.fmt(f),
        }
    }
}

/// State of a [`Challenge`] (RFC 8555 §7.1.6)
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// Problem document (RFC 7807) an ACME server attaches to a failed challenge (RFC 8555 §6.7)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Problem {
    #[serde(rename = "type", default)]
    pub typ: String,
    #[serde(default)]
    pub detail: Option<String>,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail.as_deref() {
            Some(detail) => f.write_str(detail),
            None if self.typ.is_empty() => f.write_str("no detail given"),
            None => f.write_str(&self.typ),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub token: String,
    /// RFC 8555 §8; `None` if the server omitted it
    #[serde(default)]
    pub status: Option<ChallengeStatus>,
    /// why validation failed, set once `status` is `invalid` (RFC 8555 §8)
    #[serde(default)]
    pub error: Option<Problem>,
}

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http request error: {0}")]
    HttpRequest(#[from] HTTPError),
    #[error("acme service response is missing {0} header")]
    MissingHeader(&'static str),
    #[error("no tls-alpn-01 challenge found")]
    NoTlsAlpn01Challenge,
    #[error("HTTP Status {0} indicates error")]
    HttpStatus(u16),
    /// The ACME server returned `429 Too Many Requests`. When the
    /// response included a `Retry-After` header (RFC 7231 §7.1.3) the
    /// parsed cooldown is surfaced here so callers can wait the
    /// requested duration before retrying instead of hammering the
    /// server. Both forms the RFC permits are accepted: delta-seconds
    /// (a non-negative integer) and HTTP-date (resolved to the duration
    /// from "now" until that moment, or [`Duration::ZERO`] if that
    /// moment has already passed).
    ///
    /// `None` means the server didn't supply a `Retry-After` (or the
    /// value was unparseable), and the caller should fall back to its
    /// own default — not that the cooldown is zero.
    ///
    /// [`Duration::ZERO`]: std::time::Duration::ZERO
    #[error(
        "HTTP Status 429 (Too Many Requests){}",
        match retry_after {
            Some(d) => format!(" (Retry-After: {}s)", d.as_secs()),
            None => String::new(),
        }
    )]
    RateLimited {
        retry_after: Option<std::time::Duration>,
    },
    #[cfg(feature = "use_rustls")]
    #[error("Could not create Certificate: {0}")]
    RcgenError(#[from] rcgen::Error),
    #[error("error from cache: {0}")]
    Cache(Box<dyn CacheError>),
}

impl AcmeError {
    pub fn cache<E: CacheError>(err: E) -> Self {
        Self::Cache(Box::new(err))
    }
}

/// parse a HTTP header as String or fail
fn get_header(response: &Response, header: &'static str) -> Result<String, AcmeError> {
    response
        .header(header)
        .and_then(|hv| hv.try_into().ok())
        .ok_or(AcmeError::MissingHeader(header))
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::test::*;
    #[test]
    fn discover() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            let (mut stream, _) = listener.accept().await?;
            assert_stream(&mut stream, b"GET /directory HTTP").await?;

            let body = format!(
                r##"{{
                "keyChange": "host/key-change",
                "meta": {{
                  "caaIdentities": [
                    "letsencrypt.org"
                  ],
                  "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf",
                  "website": "https://letsencrypt.org/docs/staging-environment/"
                }},
                "newAccount": "host/new-acct",
                "newNonce": "host/new-nonce",
                "newOrder": "host/new-order",
                "q3Eo-_fidjY": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
                "renewalInfo": "https://acme-staging-v02.api.letsencrypt.org/draft-ietf-acme-ari-02/renewalInfo/",
                "revokeCert": "host/revoke-cert"
              }}"##
            );

            stream
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type:  application/json\r\n\r\n{}", body.len(),body).as_bytes())
                .await?;

            Ok(true)
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let t = spawn(server(listener));

            let d = Directory::discover(&format!("http://{}:{}/directory", host, port)).await?;
            assert_eq!(d.new_account, "host/new-acct");
            assert_eq!(d.new_nonce, "host/new-nonce");
            assert_eq!(d.new_order, "host/new-order");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
    pub async fn return_nounce(listener: &TcpListener) -> std::io::Result<bool> {
        let (mut stream, _) = listener.accept().await?;
        assert_stream(&mut stream, b"GET /acme/new-nonce HTTP").await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nreplay-nonce: abc\r\n\r\n")
            .await?;
        close(stream).await?;
        Ok(true)
    }
    pub fn new_dir(host: &str, port: u16) -> Directory {
        let new_nonce = format!("http://{}:{}/acme/new-nonce", host, port);
        let new_account = format!("http://{}:{}/acme/new-acct", host, port);
        let new_order = format!("http://{}:{}/acme/new-order", host, port);
        Directory {
            new_nonce,
            new_account,
            new_order,
        }
    }
    #[test]
    fn nonce() {
        async fn server(listener: TcpListener) -> std::io::Result<bool> {
            return_nounce(&listener).await
        }
        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let t = spawn(server(listener));

            let d = new_dir(&host, port);
            assert_eq!(d.nonce().await?, "abc");

            assert!(t.await?, "not cool");
            Ok(())
        });
    }
    #[test]
    fn lets_encrypt_staging() {
        block_on(async {
            let d = Directory::discover(LETS_ENCRYPT_STAGING_DIRECTORY).await?;
            assert!(!d.new_account.is_empty());
            assert!(!d.new_order.is_empty());
            assert!(!d.nonce().await.unwrap().is_empty());
            Ok(())
        });
    }
}
