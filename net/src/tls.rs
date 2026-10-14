use crate::{PeerKey, Peers};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use quinn::{
    ClientConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

pub const ALPN: &[u8] = b"portal-rpc/1";

/// Derives the device's Ed25519 key and creates its self-signed TLS certificate.
pub fn identity(
    seed: &[u8; 32],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let key = ed25519_dalek::SigningKey::from_bytes(seed)
        .to_pkcs8_der()
        .map_err(|e| e.to_string())?;
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key.as_bytes()),
        &rcgen::PKCS_ED25519,
    )
    .map_err(|e| e.to_string())?;
    let cert = rcgen::CertificateParams::new(vec!["portal".into()])
        .map_err(|e| e.to_string())?
        .self_signed(&pair)
        .map_err(|e| e.to_string())?;
    Ok((
        cert.der().clone(),
        PrivatePkcs8KeyDer::from(key.as_bytes().to_vec()).into(),
    ))
}

/// Extracts an Ed25519 public key from a peer certificate's SPKI.
pub fn certificate_key(cert: &CertificateDer<'_>) -> Result<PeerKey, Error> {
    let (rest, cert) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|_| Error::General("invalid peer certificate".into()))?;
    let spki = cert.public_key();
    if !rest.is_empty()
        || spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || spki.algorithm.parameters.is_some()
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(Error::General("peer identity must be Ed25519".into()));
    }
    spki.subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::General("invalid peer key".into()))
}

#[derive(Debug)]
pub struct Verifier {
    pub expected: Option<PeerKey>,
    pub peers: Weak<RwLock<HashMap<PeerKey, Arc<crate::Peer>>>>,
}
impl Verifier {
    // Accepts a single certificate whose key is registered and, when set, expected.
    fn check(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), Error> {
        if !intermediates.is_empty() {
            return Err(Error::General(
                "peer certificate must contain one pinned key".into(),
            ));
        }
        let key = certificate_key(cert)?;
        let peers = self
            .peers
            .upgrade()
            .ok_or_else(|| Error::General("network stopped".into()))?;
        if self.expected.is_some_and(|expected| key != expected)
            || !peers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&key)
        {
            return Err(Error::General("untrusted peer key".into()));
        }
        // Trust is assigned to the Ed25519 key, not a CA/name. rustls verifies
        // CertificateVerify below: the remote side must prove possession of this key.
        Ok(())
    }
}

// Verifies the TLS 1.3 handshake signature and requires Ed25519.
fn signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(Error::General("expected Ed25519 signature".into()));
    }
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}
impl ServerCertVerifier for Verifier {
    // Pins the remote server certificate to the registered, expected peer key.
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(cert, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    // TLS 1.2 is not available in the configured QUIC connection.
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }
    // Confirms that the server owns the private key in its certificate.
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        signature(msg, cert, dss)
    }
    // Advertises the only signature scheme accepted for peer identity.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for Verifier {
    // No CA names are advertised because peers are trusted by public key.
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    // Accepts a client certificate only if its key is registered.
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(cert, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }
    // TLS 1.2 is not available in the configured QUIC connection.
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }
    // Confirms that the client owns the private key in its certificate.
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        signature(msg, cert, dss)
    }
    // Advertises the only signature scheme accepted for peer identity.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Builds a QUIC server that requires a registered peer's client certificate.
pub fn server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    peers: Peers,
) -> Result<ServerConfig, String> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| e.to_string())?
    .with_client_cert_verifier(Arc::new(Verifier {
        expected: None,
        peers: Arc::downgrade(&peers),
    }))
    .with_single_cert(vec![cert], key)
    .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(config).map_err(|e| e.to_string())?;
    Ok(ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Builds a QUIC client that authenticates as this device and pins the server key.
pub fn client(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    peer: PeerKey,
    peers: Peers,
) -> Result<ClientConfig, String> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| e.to_string())?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Verifier {
        expected: Some(peer),
        peers: Arc::downgrade(&peers),
    }))
    .with_client_auth_cert(vec![cert], key)
    .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = false;
    Ok(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).map_err(|e| e.to_string())?,
    )))
}
