/*! utilities to help with rustls.

```
use async_acme::{
    acme::LETS_ENCRYPT_STAGING_DIRECTORY,
    rustls_helper::order,
};
async fn get_new_cert(){
    let cache = "./cachedir/".to_string();
    let new_cert = order(
        |_sni, _cert| Ok(()),
        LETS_ENCRYPT_STAGING_DIRECTORY,
        &vec!["example.com".to_string()],
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
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0:?} failed too many times")]
    TooManyAttemptsAuth(Identifier),
}
