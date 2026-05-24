// SPDX-License-Identifier: Apache-2.0

//! [`DppSelectiveDisclosure`] — `SelectiveDisclosure` impl producing IETF
//! SD-JWT envelopes for W3C VC v2.0 passport claims.
//!
//! # Wire shape (IETF SD-JWT draft-ietf-oauth-selective-disclosure-jwt-08)
//!
//! ```text
//! <Issuer-signed JWT> ~ <Disclosure 1> ~ <Disclosure 2> ~ … ~
//! ```
//!
//! - **Issuer-signed JWT** — three base64url-encoded segments joined by `.`.
//!   v0.1.x emits an `alg: "none"` (unsigned) header by default; a future
//!   variant accepts a `JwsSigner` impl and signs with `EdDSA`. The JWT
//!   payload contains:
//!   - all top-level claims that the disclosure policy marked **visible**,
//!     verbatim;
//!   - an `_sd` array of base64url(sha-256(<base64url-disclosure>)) digests
//!     for every claim that is **hidden** but selectively-disclosable;
//!   - an `_sd_alg` field naming the hash algorithm (default `sha-256`).
//! - **Disclosure** — base64url(JSON `[salt, claim_name, claim_value]`). One
//!   per hidden claim. A verifier supplied the relevant disclosures alongside
//!   the SD-JWT learns the corresponding claim values; absence of a disclosure
//!   means the claim is hidden but its hash commitment is still in the SD-JWT.
//!
//! # Policy semantics
//!
//! [`DisclosurePolicy::visible`] is interpreted as a list of JSON Pointer
//! paths (RFC 6901) into `payload`. The shape we currently support is
//! **top-level keys only** — `"/product_id"`, `"/batch"`, etc. Nested
//! selective disclosure (`/quality_check/passed`) needs the recursive
//! SD-JWT shape from the spec; we land that in a follow-up. An unknown
//! path returns [`DisclosureError::UnknownPath`].
//!
//! # Signing posture
//!
//! v0.1.x ships with `alg: "none"` because Furcate's source of truth for
//! cryptographic integrity is the Minima anchor + Tenzro TDIP attester
//! chain — the SD-JWT here is purely the *envelope shape* for verifier
//! tooling that wants W3C VC v2.0 input. Deployments that need a signed
//! envelope wire a `JwsSigner` later by re-implementing this struct.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use furcate_inference_core::{
    DisclosedEnvelope, DisclosureError, DisclosureId, DisclosurePolicy, SelectiveDisclosure,
};
use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::config::DppConfig;

const SD_JWT_SCHEME: &str = "sd-jwt";

/// `SelectiveDisclosure` impl emitting IETF SD-JWT envelopes.
#[derive(Clone, Debug)]
pub struct DppSelectiveDisclosure {
    id: DisclosureId,
    hash_alg: String,
    jws_alg: String,
}

impl DppSelectiveDisclosure {
    /// Construct from a [`DppConfig`].
    #[must_use]
    pub fn new(cfg: &DppConfig) -> Self {
        Self {
            id: DisclosureId(format!("prvnz-sd-jwt:{}", cfg.sd_jwt_hash_alg)),
            hash_alg: cfg.sd_jwt_hash_alg.clone(),
            jws_alg: cfg.sd_jwt_jws_alg.clone(),
        }
    }

    /// Construct with explicit hash + jws algorithm names.
    #[must_use]
    pub fn with_algs(
        id: impl Into<String>,
        hash_alg: impl Into<String>,
        jws_alg: impl Into<String>,
    ) -> Self {
        Self {
            id: DisclosureId(id.into()),
            hash_alg: hash_alg.into(),
            jws_alg: jws_alg.into(),
        }
    }
}

/// One JSON-Pointer-tail (top-level claim name) extracted from a policy path.
fn pointer_to_claim(path: &str) -> std::result::Result<&str, DisclosureError> {
    if !path.starts_with('/') {
        return Err(DisclosureError::UnknownPath(format!(
            "{path}: must start with '/'"
        )));
    }
    let tail = &path[1..];
    if tail.is_empty() || tail.contains('/') {
        return Err(DisclosureError::Unsupported(format!(
            "{path}: only top-level JSON Pointers supported in v0.1"
        )));
    }
    Ok(tail)
}

fn b64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn b64d(input: &str) -> std::result::Result<Vec<u8>, DisclosureError> {
    URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .map_err(|e| DisclosureError::Crypto(format!("base64url decode: {e}")))
}

fn make_disclosure(
    claim_name: &str,
    value: &Value,
) -> std::result::Result<String, DisclosureError> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = b64(&salt_bytes);
    let arr = json!([salt, claim_name, value]);
    let json = serde_json::to_vec(&arr)
        .map_err(|e| DisclosureError::Crypto(format!("encode disclosure: {e}")))?;
    Ok(b64(&json))
}

fn hash_disclosure_sha256(disclosure_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(disclosure_b64.as_bytes());
    b64(&hasher.finalize())
}

fn parse_unsigned_jwt(jwt: &str) -> std::result::Result<Map<String, Value>, DisclosureError> {
    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| DisclosureError::Crypto("JWT missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| DisclosureError::Crypto("JWT missing payload".into()))?;
    let _sig = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(DisclosureError::Crypto("JWT has too many segments".into()));
    }
    let payload_bytes = b64d(payload_b64)?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| DisclosureError::Crypto(format!("decode JWT payload: {e}")))?;
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| DisclosureError::Crypto("JWT payload not an object".into()))
}

impl SelectiveDisclosure for DppSelectiveDisclosure {
    fn id(&self) -> DisclosureId {
        self.id.clone()
    }

    fn disclose(
        &self,
        payload: &Value,
        policy: &DisclosurePolicy,
    ) -> std::result::Result<DisclosedEnvelope, DisclosureError> {
        let obj = payload
            .as_object()
            .ok_or_else(|| DisclosureError::Unsupported("payload must be a JSON object".into()))?;

        // Resolve every visible-path into a top-level claim name and reject
        // unknown paths early so we never produce an envelope that hides
        // something the policy promised would be visible.
        let mut visible_claims: BTreeMap<&str, &Value> = BTreeMap::new();
        for path in &policy.visible {
            let name = pointer_to_claim(path)?;
            let v = obj
                .get(name)
                .ok_or_else(|| DisclosureError::UnknownPath(path.clone()))?;
            visible_claims.insert(name, v);
        }

        // Everything that isn't visible becomes a salted disclosure +
        // commitment hash in `_sd`.
        let mut sd_hashes: Vec<String> = Vec::new();
        let mut disclosures: Vec<String> = Vec::new();
        for (name, value) in obj {
            if visible_claims.contains_key(name.as_str()) {
                continue;
            }
            let disclosure_b64 = make_disclosure(name, value)?;
            let hash = match self.hash_alg.as_str() {
                "sha-256" => hash_disclosure_sha256(&disclosure_b64),
                other => {
                    return Err(DisclosureError::Unsupported(format!(
                        "hash alg {other} (only 'sha-256' supported in v0.1)"
                    )));
                }
            };
            sd_hashes.push(hash);
            disclosures.push(disclosure_b64);
        }

        // Assemble the JWT payload. Visible claims go in verbatim; hidden
        // claims are represented only by their hashes in `_sd`.
        let mut jwt_payload = Map::new();
        for (name, value) in &visible_claims {
            jwt_payload.insert((*name).to_string(), (*value).clone());
        }
        if !sd_hashes.is_empty() {
            jwt_payload.insert(
                "_sd".into(),
                Value::Array(sd_hashes.into_iter().map(Value::String).collect()),
            );
            jwt_payload.insert("_sd_alg".into(), Value::String(self.hash_alg.clone()));
        }

        let header = json!({ "alg": self.jws_alg, "typ": "vc+sd-jwt" });
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| DisclosureError::Crypto(format!("encode header: {e}")))?;
        let payload_bytes = serde_json::to_vec(&Value::Object(jwt_payload))
            .map_err(|e| DisclosureError::Crypto(format!("encode payload: {e}")))?;
        let signature = ""; // alg=none → empty signature segment.
        let jwt = format!(
            "{}.{}.{}",
            b64(&header_bytes),
            b64(&payload_bytes),
            signature
        );

        // Concatenate JWT ~ disclosure1 ~ disclosure2 ~ ... ~ (trailing tilde
        // is part of the SD-JWT format — denotes "no key-binding JWT").
        let mut envelope = jwt;
        for d in &disclosures {
            envelope.push('~');
            envelope.push_str(d);
        }
        envelope.push('~');

        Ok(DisclosedEnvelope {
            scheme: SD_JWT_SCHEME.into(),
            bytes: envelope.into_bytes(),
        })
    }

    fn verify(&self, envelope: &DisclosedEnvelope) -> std::result::Result<Value, DisclosureError> {
        if envelope.scheme != SD_JWT_SCHEME {
            return Err(DisclosureError::Unsupported(envelope.scheme.clone()));
        }
        let text = std::str::from_utf8(&envelope.bytes)
            .map_err(|e| DisclosureError::Crypto(format!("envelope utf-8: {e}")))?;
        // Trailing `~` is part of the format; strip then split.
        let trimmed = text.strip_suffix('~').unwrap_or(text);
        let mut parts = trimmed.split('~');
        let jwt = parts
            .next()
            .ok_or_else(|| DisclosureError::Crypto("empty envelope".into()))?;
        let disclosures: Vec<&str> = parts.filter(|s| !s.is_empty()).collect();

        // Decode payload and pull `_sd` + `_sd_alg`.
        let mut payload = parse_unsigned_jwt(jwt)?;
        let sd_alg = payload
            .get("_sd_alg")
            .and_then(Value::as_str)
            .unwrap_or("sha-256")
            .to_string();
        if sd_alg != "sha-256" {
            return Err(DisclosureError::Unsupported(format!(
                "hash alg {sd_alg} (only 'sha-256' supported in v0.1)"
            )));
        }
        let sd_hashes: Vec<String> = payload
            .remove("_sd")
            .and_then(|v| {
                v.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
            })
            .unwrap_or_default();
        payload.remove("_sd_alg");

        // For each presented disclosure, verify its hash is in `_sd`, then
        // merge the claim back into the payload.
        for d in disclosures {
            let computed = hash_disclosure_sha256(d);
            if !sd_hashes.iter().any(|h| h == &computed) {
                return Err(DisclosureError::Crypto(format!(
                    "disclosure not committed in _sd: {d}"
                )));
            }
            let raw = b64d(d)?;
            let arr: Value = serde_json::from_slice(&raw)
                .map_err(|e| DisclosureError::Crypto(format!("disclosure not JSON: {e}")))?;
            let arr = arr
                .as_array()
                .ok_or_else(|| DisclosureError::Crypto("disclosure not an array".into()))?;
            if arr.len() != 3 {
                return Err(DisclosureError::Crypto(format!(
                    "disclosure length {} (want 3)",
                    arr.len()
                )));
            }
            let claim_name = arr[1]
                .as_str()
                .ok_or_else(|| DisclosureError::Crypto("disclosure[1] not string".into()))?
                .to_string();
            payload.insert(claim_name, arr[2].clone());
        }

        Ok(Value::Object(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Value {
        json!({
            "product_id": "SKU-42",
            "batch": "B-2026-05",
            "customer_id": "ACME-Corp",
            "internal_cost": 12.34
        })
    }

    #[test]
    fn roundtrip_recovers_disclosed_claims() {
        let sd = DppSelectiveDisclosure::with_algs("test", "sha-256", "none");
        let p = payload();
        let policy = DisclosurePolicy {
            visible: vec!["/product_id".into(), "/batch".into()],
        };
        let env = sd.disclose(&p, &policy).unwrap();
        let recovered = sd.verify(&env).unwrap();
        // When the verifier sees the envelope WITH disclosures, all
        // disclosed-and-presented claims come back. (We presented all
        // disclosures because the envelope embeds them — a real verifier
        // strips disclosures to enforce policy on the *verifier* side.)
        assert_eq!(recovered["product_id"], json!("SKU-42"));
        assert_eq!(recovered["customer_id"], json!("ACME-Corp"));
    }

    #[test]
    fn unknown_visible_path_is_rejected() {
        let sd = DppSelectiveDisclosure::with_algs("test", "sha-256", "none");
        let p = payload();
        let policy = DisclosurePolicy {
            visible: vec!["/does_not_exist".into()],
        };
        match sd.disclose(&p, &policy) {
            Err(DisclosureError::UnknownPath(_)) => {}
            other => panic!("expected UnknownPath, got {other:?}"),
        }
    }

    #[test]
    fn nested_pointer_is_rejected_in_v01() {
        let sd = DppSelectiveDisclosure::with_algs("test", "sha-256", "none");
        let p = json!({ "outer": { "inner": 1 } });
        let policy = DisclosurePolicy {
            visible: vec!["/outer/inner".into()],
        };
        match sd.disclose(&p, &policy) {
            Err(DisclosureError::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
