//! Agent PKI: a self-signed CA, persisted under `{data_dir}/pki`, that signs
//! agent certificate-signing requests on enrollment. The agent keeps its
//! private key; only the CSR is sent to the server, and the server returns the
//! CA-signed client certificate used for mutual TLS / connection auth.
use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedKey, DnType,
    IsCa, KeyPair,
};
use sha2::{Digest, Sha256};

pub struct Pki {
    ca: CertifiedKey,
    ca_pem: String,
}

impl Pki {
    /// Load the CA from disk, or generate and persist a fresh one.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("pki");
        std::fs::create_dir_all(&dir).context("create pki dir")?;
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key.pem");

        if cert_path.exists() && key_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path).context("read ca key")?;
            let ca_pem = std::fs::read_to_string(&cert_path).context("read ca cert")?;
            let key = KeyPair::from_pem(&key_pem).context("parse ca key")?;
            // Rebuild the issuer params (DN, key usage) from the stored cert so
            // signed children carry the same issuer identity across restarts.
            let params =
                CertificateParams::from_ca_cert_pem(&ca_pem).context("parse ca cert params")?;
            let cert = params.self_signed(&key).context("rebuild ca cert")?;
            return Ok(Self {
                ca: CertifiedKey {
                    cert,
                    key_pair: key,
                },
                ca_pem,
            });
        }

        let key = KeyPair::generate().context("generate ca key")?;
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "flamejob agent CA");
        let cert = params.self_signed(&key).context("self-sign ca")?;
        let ca_pem = cert.pem();
        std::fs::write(&cert_path, &ca_pem).context("write ca cert")?;
        std::fs::write(&key_path, key.serialize_pem()).context("write ca key")?;
        tracing::info!(dir = %dir.display(), "generated new agent CA");
        Ok(Self {
            ca: CertifiedKey {
                cert,
                key_pair: key,
            },
            ca_pem,
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Sign an agent CSR (PEM). Returns `(cert_pem, fingerprint_hex)` where the
    /// fingerprint is the SHA-256 of the issued certificate's DER.
    pub fn sign_csr(&self, csr_pem: &str) -> Result<(String, String)> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).context("parse csr")?;
        let issued = csr
            .signed_by(&self.ca.cert, &self.ca.key_pair)
            .context("sign csr")?;
        let cert_pem = issued.pem();
        let fingerprint = sha256_hex(issued.der().as_ref());
        Ok((cert_pem, fingerprint))
    }
}

/// SHA-256 (hex) of the DER inside a certificate PEM.
pub fn fingerprint_of_pem(cert_pem: &str) -> Result<String> {
    let parsed = pem::parse(cert_pem).context("parse cert pem")?;
    Ok(sha256_hex(parsed.contents()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
