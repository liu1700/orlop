use std::sync::Arc;

use parking_lot::RwLock;

/// Client-side mTLS identity used to dial the per-tenant `orlop-server`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

/// Renewal-aware identity source shared by every data-plane connection for a
/// hosted mount. Existing TLS sessions keep their negotiated identity; the
/// next dial snapshots the latest cert/key pair.
pub type SharedTlsIdentity = Arc<RwLock<TlsIdentity>>;

pub fn shared_tls_identity(identity: TlsIdentity) -> SharedTlsIdentity {
    Arc::new(RwLock::new(identity))
}

impl TlsIdentity {
    /// PEM bundle accepted by [`reqwest::Identity::from_pem`]: private key,
    /// then leaf cert, then any intermediates from the tenant CA chain.
    pub fn pem_bundle(&self) -> Vec<u8> {
        let mut bundle =
            Vec::with_capacity(self.key_pem.len() + self.cert_pem.len() + self.ca_pem.len());
        push_pem(&mut bundle, &self.key_pem);
        push_pem(&mut bundle, &self.cert_pem);
        push_pem(&mut bundle, &self.ca_pem);
        bundle
    }
}

fn push_pem(buf: &mut Vec<u8>, pem: &[u8]) {
    buf.extend_from_slice(pem);
    if !pem.ends_with(b"\n") {
        buf.push(b'\n');
    }
}
