use crate::acme::{AcmeError, Problem};
use crate::crypto::{sha256, EcdsaP256SHA256KeyPair};
use crate::B64_URL_SAFE_NO_PAD;
use base64::Engine;
use generic_async_http_client::{Request, Response};
use serde::Serialize;

/// Send a signed JOSE request to an endpoint
pub async fn jose_req(
    key: &EcdsaP256SHA256KeyPair,
    kid: Option<&str>,
    nonce: &str,
    url: &str,
    payload: &str,
) -> Result<Response, AcmeError> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, nonce, url)?;
    let payload = B64_URL_SAFE_NO_PAD.encode(payload);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = match key.sign(combined.as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not sign jose request",
            )
            .into());
        }
    };
    let signature = B64_URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    let req = Request::post(url)
        .json(&body)?
        .set_header("Content-Type", "application/jose+json")?;
    log::debug!("{:?}", req);
    let mut response = req.exec().await?;
    if response.status_code() > 299 {
        let status = response.status_code();
        let retry_after = if status == 429 {
            Some(
                response
                    .header("Retry-After")
                    .and_then(|hv| TryInto::<String>::try_into(hv).ok())
                    .and_then(|s| parse_retry_after(s.trim())),
            )
        } else {
            None
        };
        let problem = match response.text().await {
            Ok(body) => {
                log::error!("{}: HTTP {} - {}", url, status, body);
                serde_json::from_str::<Problem>(&body).ok()
            }
            Err(_) => {
                log::error!("{}: HTTP {}", url, status);
                None
            }
        };
        return Err(match retry_after {
            Some(retry_after) => AcmeError::RateLimited {
                retry_after,
                problem,
            },
            None => AcmeError::HttpStatus(status),
        });
    }
    Ok(response)
}

/// Parse a `Retry-After` header value per RFC 7231 §7.1.3.
///
/// Accepts both forms:
///
///   * `delta-seconds` — a non-negative integer number of seconds.
///   * `HTTP-date`     — an absolute moment in time (IMF-fixdate, the
///     RFC 850 obsolete form, or asctime). Returned as the duration from
///     "now" until that moment, or [`Duration::ZERO`] if the date is in
///     the past ("you can retry now" — distinct from `None`, which
///     means the server didn't supply a cooldown at all).
fn parse_retry_after(s: &str) -> Option<std::time::Duration> {
    if let Ok(secs) = s.parse::<u64>() {
        return Some(std::time::Duration::from_secs(secs));
    }
    let when = httpdate::parse_http_date(s).ok()?;
    Some(
        when.duration_since(std::time::SystemTime::now())
            .unwrap_or(std::time::Duration::ZERO),
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{jose_req, parse_retry_after};
    use crate::acme::AcmeError;
    use crate::crypto::EcdsaP256SHA256KeyPair;
    use crate::test::block_on;

    fn request_error(status: u16, body: &str, retry_after: Option<&str>) -> AcmeError {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/new-order", listener.local_addr().unwrap());
        let retry_after = retry_after
            .map(|value| format!("Retry-After: {value}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nContent-Type: application/problem+json\r\n{retry_after}Connection: close\r\n\r\n{body}",
            body.len(),
        );
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; content_length]).unwrap();
            reader.get_mut().write_all(response.as_bytes()).unwrap();
        });
        let mut error = None;
        block_on(async {
            let pkcs8 = EcdsaP256SHA256KeyPair::generate().unwrap();
            let key = EcdsaP256SHA256KeyPair::load(pkcs8.as_ref()).unwrap();
            error = Some(jose_req(&key, None, "nonce", &url, "{}").await.unwrap_err());
            Ok(())
        });
        server.join().unwrap();
        error.unwrap()
    }

    #[test]
    fn rate_limit_preserves_unpause_link() {
        let body = r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"Your account is temporarily prevented from requesting certificates for example.test. Please visit: https://portal.letsencrypt.org/sfe/v1/unpause?jwt=test-token","status":429}"#;
        let error = request_error(429, body, None);
        let AcmeError::RateLimited {
            retry_after,
            problem,
        } = &error
        else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(*retry_after, None);
        assert_eq!(
            problem.as_ref().unwrap().typ,
            "urn:ietf:params:acme:error:rateLimited"
        );
        assert!(error
            .to_string()
            .contains("https://portal.letsencrypt.org/sfe/v1/unpause?jwt=test-token"));
    }

    #[test]
    fn rate_limit_preserves_detail_and_retry_after() {
        let error = request_error(429, r#"{"detail":"Try again later"}"#, Some("120"));
        let AcmeError::RateLimited { retry_after, .. } = &error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(*retry_after, Some(Duration::from_secs(120)));
        assert_eq!(
            error.to_string(),
            "HTTP Status 429 (Too Many Requests) (Retry-After: 120s): Try again later"
        );
    }

    #[test]
    fn rate_limit_without_detail_preserves_problem_type() {
        let error = request_error(
            429,
            r#"{"type":"urn:ietf:params:acme:error:rateLimited"}"#,
            None,
        );
        assert_eq!(
            error.to_string(),
            "HTTP Status 429 (Too Many Requests): urn:ietf:params:acme:error:rateLimited"
        );
    }

    #[test]
    fn malformed_rate_limit_body_keeps_status_and_retry_after() {
        for body in ["not JSON", "", r#"{"detail":123}"#] {
            let error = request_error(429, body, Some("60"));
            assert!(
                matches!(error, AcmeError::RateLimited { retry_after: Some(duration), problem: None } if duration == Duration::from_secs(60))
            );
            assert_eq!(
                error.to_string(),
                "HTTP Status 429 (Too Many Requests) (Retry-After: 60s)"
            );
        }
    }

    #[test]
    fn non_rate_limit_status_is_unchanged() {
        let error = request_error(409, r#"{"detail":"Already processing"}"#, Some("120"));
        assert!(matches!(error, AcmeError::HttpStatus(409)));
    }

    #[test]
    fn delta_seconds_parses() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
    }

    #[test]
    fn http_date_in_future_yields_positive_duration() {
        let target = SystemTime::now() + Duration::from_secs(3600);
        let header = httpdate::fmt_http_date(target);
        let parsed = parse_retry_after(&header).expect("formatted future HTTP-date should parse");
        assert!(parsed > Duration::from_secs(60 * 30));
        assert!(parsed <= Duration::from_secs(3600));
    }

    #[test]
    fn http_date_in_past_resolves_to_zero() {
        let past = SystemTime::now() - Duration::from_secs(3600);
        let header = httpdate::fmt_http_date(past);
        assert_eq!(parse_retry_after(&header), Some(Duration::ZERO));
    }

    #[test]
    fn unparseable_returns_none() {
        assert_eq!(parse_retry_after("not a date"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("-1"), None);
    }
}
pub(crate) fn key_authorization_sha256(
    key: &EcdsaP256SHA256KeyPair,
    token: &str,
) -> Result<impl AsRef<[u8]>, AcmeError> {
    let jwk = Jwk::new(key);
    let key_authorization = format!("{}.{}", token, jwk.thumb_sha256_base64()?);
    Ok(sha256(key_authorization.as_bytes()))
}

#[derive(Serialize)]
struct Body {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn base64(
        jwk: Option<Jwk>,
        kid: Option<&'a str>,
        nonce: &'a str,
        url: &'a str,
    ) -> Result<String, AcmeError> {
        let protected = Self {
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(B64_URL_SAFE_NO_PAD.encode(protected))
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaP256SHA256KeyPair) -> Self {
        let (x, y) = key.public_key()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: B64_URL_SAFE_NO_PAD.encode(x),
            y: B64_URL_SAFE_NO_PAD.encode(y),
        }
    }
    pub(crate) fn thumb_sha256_base64(&self) -> Result<String, AcmeError> {
        let jwk_thumb = JwkThumb {
            crv: self.crv,
            kty: self.kty,
            x: &self.x,
            y: &self.y,
        };
        let json = serde_json::to_vec(&jwk_thumb)?;
        let hash = sha256(&json);
        Ok(B64_URL_SAFE_NO_PAD.encode(hash))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}
