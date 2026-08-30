/*! utilities to help with rustls.

```
use async_acme::{
    acme::{Identifier, LETS_ENCRYPT_STAGING_DIRECTORY},
    rustls_helper::order,
};
async fn get_new_cert(){
    let cache = "./cachedir/".to_string();
    let new_cert = order(
        |_sni, _cert| Ok(()),
        LETS_ENCRYPT_STAGING_DIRECTORY,
        &[Identifier::Dns("example.com".to_string())],
        Some(&cache),
        &vec!["mailto:admin@example.com".to_string()],
    )
    .await
    .unwrap();
}
```

*/

use futures_util::future::try_join_all;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    sign::CertifiedKey,
};
use std::time::Duration;
use thiserror::Error;

use crate::{
    acme::{Account, AcmeError, Auth, Directory, Identifier, Order},
    cache::AcmeCache,
    crypto::{gen_acme_cert, get_cert_duration_left, CertBuilder},
};

#[cfg(feature = "use_async_std")]
use async_std::task::sleep;
#[cfg(feature = "use_tokio")]
use tokio::time::sleep;

/// Obtain a signed certificate from the ACME provider at `directory_url` for the DNS `domains`.
///
/// The secret for the challenge is passed as a ready to use certificate to `set_auth_key(domain, certificate)?`.
/// This certificate has to be presented upon a TLS request with ACME ALPN and SNI for that domain.
///
/// Provide your email in `contact` in the form *mailto:admin@example.com* to receive warnings regarding your certificate.
/// Set a `cache` to remember your account.
pub async fn order<C, F>(
    set_auth_key: F,
    directory_url: &str,
    identifiers: &[Identifier],
    cache: Option<&C>,
    contact: &[String],
) -> Result<CertifiedKey, OrderError>
where
    C: AcmeCache,
    F: Fn(Identifier, CertifiedKey) -> Result<(), AcmeError>,
{
    if let Some(dir) = cache {
        if let Some((key_pem, cert_pem)) = dir
            .read_certificate(identifiers, directory_url)
            .await
            .map_err(AcmeError::cache)?
        {
            let c = CertifiedKey::new(
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(AcmeError::cache)?,
                rustls::crypto::ring::sign::any_supported_type(
                    &rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                        .map_err(AcmeError::cache)?,
                )
                .map_err(AcmeError::cache)?,
            );
            if duration_until_renewal_attempt(Some(&c), 0) > Duration::ZERO {
                log::info!("Cached cert found");
                return Ok(c);
            }
        }
    }

    let directory = Directory::discover(directory_url).await?;
    let account = Account::load_or_create(directory, cache, contact).await?;

    let (c, key_pem, cert_pem) = drive_order(set_auth_key, identifiers.to_vec(), account).await?;

    if let Some(dir) = cache {
        dir.write_certificate(identifiers, directory_url, &key_pem, &cert_pem)
            .await
            .map_err(AcmeError::cache)?;
    };

    Ok(c)
}

/// Obtain a signed certificate for the DNS `domains` using `account`.
///
/// The secret for the challenge is passed as a ready to use certificate to `set_auth_key(domain, certificate)?`.
/// This certificate has to be presented upon a TLS request with ACME ALPN and SNI for that domain.
///
/// Returns the signed Certificate, its private key as pem, and the certificate as pem again
pub async fn drive_order<F>(
    set_auth_key: F,
    identifiers: Vec<Identifier>,
    account: Account,
) -> Result<(CertifiedKey, String, String), OrderError>
where
    F: Fn(Identifier, CertifiedKey) -> Result<(), AcmeError>,
{
    let cert = CertBuilder::gen_new(identifiers.clone())?;
    let mut order = account.new_order(identifiers).await?;
    loop {
        order = match order {
            Order::Pending {
                authorizations,
                finalize,
            } => {
                let auth_futures = authorizations
                    .iter()
                    .map(|url| authorize(&set_auth_key, &account, url));
                try_join_all(auth_futures).await?;
                log::info!("completed all authorizations");
                Order::Ready { finalize }
            }
            Order::Processing { finalize, .. } => account.check_status(finalize).await?,
            Order::Ready { finalize } => {
                log::info!("sending csr");
                let csr = cert.get_csr()?;
                account.send_csr(finalize, csr).await?
            }
            Order::Valid { certificate } => {
                log::info!("download certificate");
                let acme_cert_pem = account.obtain_certificate(certificate).await?;
                let rd = acme_cert_pem.as_bytes();
                let pkey_pem = cert.private_key_as_pem_pkcs8();
                let cert_key = cert.sign(rd).map_err(|_| {
                    AcmeError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "could not parse certificate",
                    ))
                })?;
                return Ok((cert_key, pkey_pem, acme_cert_pem));
            }
            Order::Invalid => return Err(OrderError::BadOrder(Order::Invalid)),
        }
    }
}
async fn authorize<F>(set_auth_key: &F, account: &Account, url: &str) -> Result<(), OrderError>
where
    F: Fn(Identifier, CertifiedKey) -> Result<(), AcmeError>,
{
    let identifier = match account.check_auth(url).await? {
        Auth::Pending {
            identifier,
            challenges,
        } => {
            log::info!("trigger challenge for {identifier}");
            let (challenge, key_auth) = account.tls_alpn_01(&challenges)?;
            let auth_key = gen_acme_cert(vec![identifier.clone()], key_auth.as_ref())?;
            set_auth_key(identifier.clone(), auth_key)?;
            // Boulder answers a new order for an identifier set it already
            // holds a pending order for with that same order, hence the same
            // authorization. If an earlier attempt's validation is still
            // running, the trigger gets 409 `conflict` (its beganProcessing
            // guard): validation is under way, so poll rather than fail.
            match account.trigger_challenge(&challenge.url).await {
                Ok(()) => {}
                Err(AcmeError::HttpStatus(409)) => {
                    log::warn!("challenge for {identifier} is already being validated; polling")
                }
                Err(e) => return Err(e.into()),
            }
            identifier
        }
        Auth::Valid => return Ok(()),
        auth => return Err(OrderError::BadAuth(auth)),
    };
    // RFC 8555 §7.5.1: the challenge is triggered once and the client then
    // polls the authorization. It stays `pending` for as long as its challenge
    // is `processing`, so a re-POST here would race the validation the server
    // is already performing and be rejected with 409.
    for i in 0u8..5 {
        sleep(Duration::from_secs(1u64 << i)).await;
        match account.check_auth(url).await? {
            Auth::Pending { .. } => {
                log::info!("authorization for {identifier} still pending")
            }
            Auth::Valid => return Ok(()),
            auth => return Err(OrderError::BadAuth(auth)),
        }
    }
    Err(OrderError::TooManyAttemptsAuth(identifier))
}

/// get the duration until the next ACME refresh should be done
pub fn duration_until_renewal_attempt(cert_key: Option<&CertifiedKey>, err_cnt: usize) -> Duration {
    let valid_until = cert_key
        .and_then(|cert_key| cert_key.cert.first())
        .and_then(|cert| get_cert_duration_left(cert).ok())
        .unwrap_or_default();

    let wait_secs = valid_until / 2;
    match err_cnt {
        0 => wait_secs,
        err_cnt => wait_secs.max(Duration::from_secs(1 << err_cnt)),
    }
}

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[cfg(feature = "use_rustls")]
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("{0}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(Identifier),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::acme::account::test::{new_account, parse_req};
    use crate::acme::test::{new_dir, return_nounce};
    use crate::test::*;

    async fn respond_with(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {len}\r\nContent-Type: application/json\r\n\r\n{body}",
                    len = body.len()
                )
                .as_bytes(),
            )
            .await
    }

    async fn respond(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
        respond_with(stream, "200 OK", body).await
    }

    /// Read one JWS request and return its target path.
    async fn take_req(listener: &TcpListener) -> std::io::Result<(TcpStream, String)> {
        return_nounce(listener).await?;
        let (mut stream, _) = listener.accept().await?;
        // The client may write headers and body separately; read until the
        // body the headers announce has arrived.
        let mut req = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let n = stream.read(&mut chunk[..]).await?;
            assert!(n > 0, "connection closed mid-request");
            req.extend_from_slice(&chunk[..n]);
            let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = std::str::from_utf8(&req[..end]).expect("headers not utf8");
            let len: usize = head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse().ok())
                .expect("no content-length");
            if req.len() >= end + 4 + len {
                break;
            }
        }
        let (header, _, _) = parse_req(req);
        let path = header
            .split_whitespace()
            .nth(1)
            .expect("no path in request line")
            .to_string();
        Ok((stream, path))
    }

    fn pending_authz(host: &str, port: u16) -> String {
        format!(
            r##"{{"status":"pending","challenges":[{{"token":"t","type":"tls-alpn-01","url":"http://{host}:{port}/chall"}}],"identifier":{{"type":"dns","value":"example.com"}}}}"##
        )
    }

    /// The authorization stays `pending` while its challenge is `processing`,
    /// so a client that re-POSTs the challenge on each poll races the
    /// validation already under way and Boulder rejects it with 409. Pin that
    /// the challenge is triggered exactly once however long validation takes.
    #[test]
    fn challenge_is_triggered_once_while_validation_runs() {
        async fn server(listener: TcpListener, host: String, port: u16) -> std::io::Result<bool> {
            // 1. the initial authorization fetch
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/authz");
            let pending = pending_authz(&host, port);
            respond(&mut stream, &pending).await?;

            // 2. the one legitimate trigger
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/chall", "challenge must be triggered first");
            respond(&mut stream, r##"{"status":"processing"}"##).await?;

            // 3. first poll — still validating. A re-POST would land here.
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(
                path, "/authz",
                "poll the authorization; do not re-POST the challenge"
            );
            respond(&mut stream, &pending).await?;

            // 4. second poll — validation finished.
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(
                path, "/authz",
                "poll the authorization; do not re-POST the challenge"
            );
            respond(&mut stream, r##"{"status":"valid"}"##).await?;

            close(stream).await?;
            Ok(true)
        }

        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let authz = format!("http://{host}:{port}/authz");
            let t = spawn(server(listener, host.clone(), port));

            let account = new_account(directory);
            authorize(&|_, _| Ok(()), &account, &authz).await?;

            assert!(t.await?, "server script did not run to completion");
            Ok(())
        });
    }

    /// A failed validation names the reason the server attached to the
    /// challenge (RFC 8555 §8), not merely that the authorization is invalid.
    #[test]
    fn a_failed_validation_reports_the_servers_reason() {
        async fn server(listener: TcpListener, host: String, port: u16) -> std::io::Result<bool> {
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/authz");
            respond(&mut stream, &pending_authz(&host, port)).await?;

            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/chall");
            respond(&mut stream, r##"{"status":"processing"}"##).await?;

            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/authz");
            respond(
                &mut stream,
                &format!(
                    r##"{{"status":"invalid","identifier":{{"type":"dns","value":"example.com"}},"challenges":[{{"type":"tls-alpn-01","status":"invalid","url":"http://{host}:{port}/chall","token":"t","validated":"2026-08-30T01:07:38Z","error":{{"type":"urn:ietf:params:acme:error:connection","detail":"192.0.2.1: Timeout during connect (likely firewall problem)","status":400}}}}]}}"##
                ),
            )
            .await?;

            close(stream).await?;
            Ok(true)
        }

        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let authz = format!("http://{host}:{port}/authz");
            let t = spawn(server(listener, host.clone(), port));

            let account = new_account(directory);
            let err = authorize(&|_, _| Ok(()), &account, &authz)
                .await
                .expect_err("the authorization is invalid");
            assert!(
                matches!(err, OrderError::BadAuth(Auth::Invalid { .. })),
                "{err:?}"
            );
            assert_eq!(
                err.to_string(),
                "authorization for example.com failed: 192.0.2.1: Timeout during connect (likely firewall problem)"
            );

            assert!(t.await?, "server script did not run to completion");
            Ok(())
        });
    }

    /// Boulder hands a repeat order the same pending order and authorization.
    /// If the earlier attempt's validation is still running, the trigger is
    /// refused with 409 — validation is under way, not failed — so the
    /// authorization is polled as if the trigger had been accepted.
    #[test]
    fn a_refused_trigger_is_followed_by_polling() {
        async fn server(listener: TcpListener, host: String, port: u16) -> std::io::Result<bool> {
            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/authz");
            respond(&mut stream, &pending_authz(&host, port)).await?;

            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/chall");
            respond_with(
                &mut stream,
                "409 Conflict",
                r##"{"type":"urn:ietf:params:acme:error:conflict","detail":"Unable to update challenge :: Authorization is already being validated. This may indicate your client attempted the same challenge multiple times, possibly due to a client bug.","status":409}"##,
            )
            .await?;

            let (mut stream, path) = take_req(&listener).await?;
            assert_eq!(path, "/authz", "a refused trigger is followed by polling");
            respond(&mut stream, r##"{"status":"valid"}"##).await?;

            close(stream).await?;
            Ok(true)
        }

        block_on(async {
            let (listener, port, host) = listen_somewhere().await?;
            let directory = new_dir(&host, port);
            let authz = format!("http://{host}:{port}/authz");
            let t = spawn(server(listener, host.clone(), port));

            let account = new_account(directory);
            authorize(&|_, _| Ok(()), &account, &authz).await?;

            assert!(t.await?, "server script did not run to completion");
            Ok(())
        });
    }
}
