// SPDX-License-Identifier: Apache-2.0

//! Runtime configuration for the PRVNZ DPP trait impls.
//!
//! Every knob a deployment is likely to tune lives here, so wiring code can
//! keep one struct in scope instead of threading a dozen fields through each
//! impl constructor. The defaults are chosen to "just work" against the
//! Tenzro Ledger + Minima Integritas + local JSONL event feed combination
//! described in the PRVNZ Library Architecture Specification.

use furcate_inference_core::{AttesterId, SinkId};
use serde::{Deserialize, Serialize};

/// JSON-LD context URL emitted by [`crate::DppSchemaProfile`].
///
/// The CEN/CLC JTC 24 + GS1 EPCIS 2.0 joint context lives at
/// `https://furcate.xyz/prvnz/context/v1.jsonld` once that domain is live.
/// Deployments running against a private mirror should point this at their
/// own host.
pub const DEFAULT_PRVNZ_CONTEXT_URL: &str = "https://furcate.xyz/prvnz/context/v1.jsonld";

/// Configuration shared across the four DPP trait impls.
///
/// Constructed by deployment glue and handed to each impl's `new` /
/// `with_config` constructor. Cheap to clone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DppConfig {
    /// JSON-LD `@context` URL the schema profile emits.
    pub schema_context_url: String,
    /// Schema profile identifier — what shows up in `SchemaProfileId`. Lets
    /// a deployment run multiple PRVNZ schemas side-by-side (e.g. a
    /// dev-profile and prod-profile) if needed.
    pub schema_profile_id: String,
    /// Policy classification: which `StepReceipt.tag` values mark a receipt
    /// as carrying sensitive (B2B / private) data. Sensitive receipts route
    /// to the Tenzro DAML sink; everything else routes to the public EVM/SVM
    /// sink. Default: `["sensitive", "private", "b2b"]`.
    pub sensitive_tags: Vec<String>,
    /// Policy classification: `StepReceipt.meta` keys whose presence marks
    /// a receipt sensitive even when no sensitive tag is set. Useful for
    /// schemas that carry a `customer_id` or `serial_number` in `meta` without
    /// the producer remembering to tag it. Default: empty.
    pub sensitive_meta_keys: Vec<String>,
    /// `SinkId` of the Minima anchoring sink (typically `"minima:anchor"`).
    /// Always selected — the digest is anchored regardless of sensitivity.
    pub minima_anchor_sink: SinkId,
    /// `SinkId` of the Tenzro public-VM (EVM/SVM) sink for non-sensitive
    /// receipts (typically `"tenzro:public"`).
    pub tenzro_public_sink: SinkId,
    /// `SinkId` of the Tenzro private-VM (DAML / Canton) sink for sensitive
    /// receipts (typically `"tenzro:private"`).
    pub tenzro_private_sink: SinkId,
    /// Optional attester to invoke alongside the routing decision.
    /// Typically `"minima:local"` — produces an `Attestation` the agent loop
    /// can persist alongside the receipt. `None` skips attestation.
    pub default_attester: Option<AttesterId>,
    /// SD-JWT disclosure-hash algorithm name. The IETF SD-JWT spec defaults
    /// to `sha-256`; deployments mirroring an Issuer-Stack that supports
    /// `sha-384` / `sha-512` can override here.
    pub sd_jwt_hash_alg: String,
    /// SD-JWT JWS algorithm name written into the envelope header.
    /// v0.1.x ships an unsigned envelope (`"none"`) — a future revision wires
    /// a `JwsSigner`-backed variant. The field is recorded so verifiers can
    /// fail closed when they don't recognise the algorithm.
    pub sd_jwt_jws_alg: String,
}

impl Default for DppConfig {
    fn default() -> Self {
        Self {
            schema_context_url: DEFAULT_PRVNZ_CONTEXT_URL.to_string(),
            schema_profile_id: "prvnz-dpp:v1".to_string(),
            sensitive_tags: vec![
                "sensitive".to_string(),
                "private".to_string(),
                "b2b".to_string(),
            ],
            sensitive_meta_keys: Vec::new(),
            minima_anchor_sink: SinkId("minima:anchor".to_string()),
            tenzro_public_sink: SinkId("tenzro:public".to_string()),
            tenzro_private_sink: SinkId("tenzro:private".to_string()),
            default_attester: Some(AttesterId("minima:local".to_string())),
            sd_jwt_hash_alg: "sha-256".to_string(),
            sd_jwt_jws_alg: "none".to_string(),
        }
    }
}
