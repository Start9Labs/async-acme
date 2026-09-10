use crate::acme::AcmeError;
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
        // For `429 Too Many Requests` we capture `Retry-After` before
        // reading/discarding the body so the caller can honour the
        // server-supplied cooldown instead of guessing a backoff. Both
        // forms permitted by RFC 7231 §7.1.3 are accepted: delta-seconds
        // (a non-negative integer) and HTTP-date (IMF-fixdate / obs-date).
        // An HTTP-date in the past, or any unparseable value, is reported
        // as `None` so callers can fall back to a sensible default.
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
        if let Ok(s) = response.text().await {
            log::error!("{}: HTTP {} - {}", url, status, s);
        } else {
            log::error!("{}: HTTP {}", url, status);
        }
        return Err(match retry_after {
            Some(retry_after) => AcmeError::RateLimited { retry_after },
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

    use super::parse_retry_after;

    #[test]
    fn delta_seconds_parses() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
    }

    #[test]
    fn http_date_in_future_yields_positive_duration() {
        // Round-trip through `httpdate::fmt_http_date` so the test isn't
        // tied to a hard-coded date whose weekday could drift; the
        // parser is strict about day-of-week matching the date.
        let target = SystemTime::now() + Duration::from_secs(3600);
        let header = httpdate::fmt_http_date(target);
        let parsed = parse_retry_after(&header).expect("formatted future HTTP-date should parse");
        // We don't pin the exact value (it depends on "now" inside
        // `parse_retry_after`), just bracket it generously.
        assert!(parsed > Duration::from_secs(60 * 30));
        assert!(parsed <= Duration::from_secs(3600));
    }

    #[test]
    fn http_date_in_past_resolves_to_zero() {
        // RFC 7231 permits a date in the past. We treat that as "you can
        // retry now" — `Some(Duration::ZERO)` — distinct from `None`,
        // which means the server didn't supply a cooldown at all.
        let past = SystemTime::now() - Duration::from_secs(3600);
        let header = httpdate::fmt_http_date(past);
        assert_eq!(parse_retry_after(&header), Some(Duration::ZERO));
    }

    #[test]
    fn unparseable_returns_none() {
        assert_eq!(parse_retry_after("not a date"), None);
        assert_eq!(parse_retry_after(""), None);
        // Negative integers are not delta-seconds (which is non-negative)
        // and aren't HTTP-dates either.
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
