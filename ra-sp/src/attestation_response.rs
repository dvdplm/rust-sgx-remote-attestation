use crate::error::AttestationError;
use hyper::header::{HeaderMap, HeaderValue};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sgx_crypto::certificate::X509Cert;

#[derive(Deserialize, Debug)]
pub struct AttestationResponse {
    // header
    pub advisory_url: Option<String>,
    pub advisory_ids: Option<String>,
    pub request_id: String,
    // body
    pub id: String,
    pub timestamp: String,
    pub version: u16,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
}

impl AttestationResponse {
    pub fn from_response(
        root_ca_cert: &X509Cert,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<Self, AttestationError> {
        Self::verify_response(root_ca_cert, &headers, &body[..])?;

        let body = serde_json::from_slice::<Value>(&body).map_err(|_| AttestationError::BadPayload )?;

        let h = |x: &HeaderValue| x.to_str().unwrap().to_owned();
        let b = |x: &str| x.to_owned();

        // TODO: deserialization into a proper struct
        Ok(Self {
            // header
            advisory_ids: headers.get("advisory-ids").map(h),
            advisory_url: headers.get("advisory-url").map(h),
            request_id: headers.get("request-id").map(h).ok_or(AttestationError::BadPayload)?,
            // body
            id: body["id"].as_str().unwrap().to_owned(),
            timestamp: body["timestamp"].as_str().unwrap().to_owned(),
            version: body["version"].as_u64().unwrap() as u16,
            isv_enclave_quote_status: body["isvEnclaveQuoteStatus"].as_str().unwrap().to_owned(),
            isv_enclave_quote_body: body["isvEnclaveQuoteBody"].as_str().unwrap().to_owned(),
            revocation_reason: body["revocationReason"].as_str().map(b),
            pse_manifest_status: body["pseManifestStatus"].as_str().map(b),
            pse_manifest_hash: body["pseManifestHash"].as_str().map(b),
            platform_info_blob: body["platformInfoBlob"].as_str().map(b),
            nonce: body["nonce"].as_str().map(b),
            epid_pseudonym: body["epidPseudonym"].as_str().map(b),
        })
    }

    fn verify_response(
        root_ca_cert: &X509Cert,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), AttestationError> {
        // Split certificates
        let re = Regex::new(
            "(-----BEGIN .*-----\\n)\
                ((([A-Za-z0-9+/]{4})*\
                ([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\\n)+)\
                (-----END .*-----)",
        ).expect("expecting the regex to be correct");
        let (mut certificate, mut ca_certificate) = {
            let c = headers
                .get("x-iasreport-signing-certificate")
                .ok_or(AttestationError::MissingIASHeader)?
                .to_str()
                .map_err(|_| AttestationError::BadPayload)
                .map(|header_str| {
                    percent_encoding::percent_decode_str(header_str)
                        .decode_utf8()
                        .map_err(|_| AttestationError::BadPayload)
                })??;

            let mut c = re
                .find_iter(&c)
                .take(2)
                .map(|m| {
                    let mut s = m.as_str().to_owned();
                    s.push('\0');
                    X509Cert::new_from_pem(s.as_bytes()).map_err(|_| AttestationError::InvalidIASCertificate)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (c.remove(0), c.remove(0))
        };

        // Check if the root certificate is the same as the SP-provided certificate
        if root_ca_cert != &ca_certificate {
            return Err(AttestationError::MismatchedIASRootCertificate);
        }

        // Check that the certificate is signed by root CA
        certificate
            .verify_this_certificate(&mut ca_certificate)
            .map_err(|_| AttestationError::InvalidIASCertificate)?;

        // Check that the signature is correct
        let signature = base64::decode(
            headers
                .get("x-iasreport-signature")
                .ok_or(AttestationError::MissingIASHeader)?
                .to_str()
                .map_err(|_| AttestationError::BadPayload)?
        ).map_err(|_| AttestationError::BadPayload)?;

        certificate
            .verify_signature(body, &signature[..])
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(())
    }
}
