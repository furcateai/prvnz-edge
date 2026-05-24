// SPDX-License-Identifier: Apache-2.0

//! [`DppSchemaProfile`] — `SchemaProfile` impl that shapes a `StepReceipt`
//! into a JSON-LD payload aligned with **CEN/CLC JTC 24** (DPP harmonised
//! data model) and **GS1 EPCIS 2.0** (event capture).
//!
//! # Wire shape
//!
//! Each encoded receipt is one JSON-LD document of the form:
//!
//! ```jsonc
//! {
//!   "@context": "<config.schema_context_url>",
//!   "type": "ObjectEvent",                       // EPCIS 2.0 event class
//!   "eventID": "blake3:<hex-digest-of-canon-receipt>",
//!   "eventTime": "<finished_at, RFC3339>",
//!   "recordTime": "<started_at, RFC3339>",       // EPCIS recordTime
//!   "stepId": "<receipt.step_id>",               // Furcate-specific extension
//!   "inputDigest": "blake3:<hex>",
//!   "outputDigest": "blake3:<hex>",
//!   "bizStep": [ "<tag>", ... ],                 // routed from receipt.tags
//!   "model": { "name": ..., "digest": ..., "engineKind": ... },
//!   "passportClaims": { /* receipt.meta, verbatim */ }
//! }
//! ```
//!
//! `decode` is the inverse: parses the JSON-LD back into a `StepReceipt`
//! and validates that the required EPCIS fields are present. Round-trip is
//! lossless for the fields the spec defines; unknown JSON-LD keys are
//! ignored, which matches the EPCIS 2.0 "additional fields are out-of-scope"
//! convention.

use chrono::{DateTime, Utc};
use furcate_inference_core::{
    ArtefactSnapshot, ReceiptDigest, SchemaError, SchemaProfile, SchemaProfileId, StepReceipt,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use crate::config::DppConfig;

/// `SchemaProfile` impl shaping `StepReceipt` into a CEN/CLC JTC 24 +
/// GS1 EPCIS 2.0 JSON-LD passport.
#[derive(Clone, Debug)]
pub struct DppSchemaProfile {
    id: SchemaProfileId,
    context_url: String,
}

impl DppSchemaProfile {
    /// Construct a DPP schema profile from a [`DppConfig`].
    #[must_use]
    pub fn new(cfg: &DppConfig) -> Self {
        Self {
            id: SchemaProfileId(cfg.schema_profile_id.clone()),
            context_url: cfg.schema_context_url.clone(),
        }
    }

    /// Construct directly with an explicit id + context URL. Useful for
    /// tests and for deployments that don't want a full [`DppConfig`].
    #[must_use]
    pub fn with_parts(id: impl Into<String>, context_url: impl Into<String>) -> Self {
        Self {
            id: SchemaProfileId(id.into()),
            context_url: context_url.into(),
        }
    }
}

fn hex_digest(d: &ReceiptDigest) -> String {
    let mut s = String::with_capacity(2 + d.len() * 2);
    s.push_str("blake3:");
    for b in d {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn parse_hex_digest(s: &str) -> std::result::Result<ReceiptDigest, SchemaError> {
    let hex = s
        .strip_prefix("blake3:")
        .ok_or_else(|| SchemaError::Validation(format!("digest missing 'blake3:' prefix: {s}")))?;
    if hex.len() != 64 {
        return Err(SchemaError::Validation(format!(
            "digest hex length {} (want 64)",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = &hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(chunk, 16)
            .map_err(|e| SchemaError::Validation(format!("digest hex parse: {e}")))?;
    }
    Ok(out)
}

fn artefact_to_json(snap: &ArtefactSnapshot) -> Value {
    json!({
        "name": snap.name,
        "digest": hex_digest(&snap.digest),
        "engineKind": snap.engine_kind,
    })
}

fn artefact_from_json(v: &Value) -> std::result::Result<ArtefactSnapshot, SchemaError> {
    let obj = v
        .as_object()
        .ok_or_else(|| SchemaError::Validation("model: not an object".into()))?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::Validation("model.name missing".into()))?
        .to_string();
    let digest = obj
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::Validation("model.digest missing".into()))
        .and_then(parse_hex_digest)?;
    let engine_kind = obj
        .get("engineKind")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::Validation("model.engineKind missing".into()))?
        .to_string();
    Ok(ArtefactSnapshot {
        name,
        digest,
        engine_kind,
    })
}

fn parse_rfc3339(s: &str, field: &str) -> std::result::Result<DateTime<Utc>, SchemaError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| SchemaError::Validation(format!("{field}: not RFC3339: {e}")))
}

impl SchemaProfile for DppSchemaProfile {
    fn id(&self) -> SchemaProfileId {
        self.id.clone()
    }

    fn encode(&self, receipt: &StepReceipt) -> std::result::Result<Vec<u8>, SchemaError> {
        // Canonicalise the receipt to get a stable eventID. We hash the
        // serde_json canonical form rather than the eventual JSON-LD to keep
        // the eventID aligned with what `Attester::sign_receipt` would sign.
        let canon = serde_json::to_vec(receipt)
            .map_err(|e| SchemaError::Encode(format!("canonicalise receipt: {e}")))?;
        let event_digest = blake3::hash(&canon);
        let event_id = format!("blake3:{}", event_digest.to_hex());

        let mut doc = Map::new();
        doc.insert("@context".into(), Value::String(self.context_url.clone()));
        doc.insert("type".into(), Value::String("ObjectEvent".into()));
        doc.insert("eventID".into(), Value::String(event_id));
        doc.insert(
            "eventTime".into(),
            Value::String(receipt.finished_at.to_rfc3339()),
        );
        doc.insert(
            "recordTime".into(),
            Value::String(receipt.started_at.to_rfc3339()),
        );
        doc.insert("stepId".into(), Value::String(receipt.step_id.clone()));
        doc.insert(
            "inputDigest".into(),
            Value::String(hex_digest(&receipt.input_digest)),
        );
        doc.insert(
            "outputDigest".into(),
            Value::String(hex_digest(&receipt.output_digest)),
        );
        doc.insert(
            "bizStep".into(),
            Value::Array(receipt.tags.iter().cloned().map(Value::String).collect()),
        );
        if let Some(model) = &receipt.model {
            doc.insert("model".into(), artefact_to_json(model));
        }
        if !receipt.meta.is_empty() {
            let claims: Map<String, Value> = receipt
                .meta
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            doc.insert("passportClaims".into(), Value::Object(claims));
        }

        serde_json::to_vec(&Value::Object(doc))
            .map_err(|e| SchemaError::Encode(format!("serialise JSON-LD: {e}")))
    }

    fn decode(&self, bytes: &[u8]) -> std::result::Result<StepReceipt, SchemaError> {
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|e| SchemaError::Encode(format!("parse JSON-LD: {e}")))?;
        let obj = v
            .as_object()
            .ok_or_else(|| SchemaError::Validation("top-level not an object".into()))?;

        // Validate the EPCIS event class — we only emit ObjectEvent today.
        match obj.get("type").and_then(Value::as_str) {
            Some("ObjectEvent") => {}
            Some(other) => {
                return Err(SchemaError::Validation(format!(
                    "unexpected EPCIS event class: {other}"
                )));
            }
            None => return Err(SchemaError::Validation("missing 'type' field".into())),
        }

        let step_id = obj
            .get("stepId")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::Validation("stepId missing".into()))?
            .to_string();
        let started_at = obj
            .get("recordTime")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::Validation("recordTime missing".into()))
            .and_then(|s| parse_rfc3339(s, "recordTime"))?;
        let finished_at = obj
            .get("eventTime")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::Validation("eventTime missing".into()))
            .and_then(|s| parse_rfc3339(s, "eventTime"))?;
        let input_digest = obj
            .get("inputDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::Validation("inputDigest missing".into()))
            .and_then(parse_hex_digest)?;
        let output_digest = obj
            .get("outputDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| SchemaError::Validation("outputDigest missing".into()))
            .and_then(parse_hex_digest)?;
        let tags = obj
            .get("bizStep")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let model = obj.get("model").map(artefact_from_json).transpose()?;
        let meta: BTreeMap<String, Value> = obj
            .get("passportClaims")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        Ok(StepReceipt {
            step_id,
            started_at,
            finished_at,
            model,
            input_digest,
            output_digest,
            tags,
            meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_receipt() -> StepReceipt {
        let mut meta = BTreeMap::new();
        meta.insert("product_id".into(), json!("SKU-42"));
        meta.insert("batch".into(), json!("B-2026-05"));
        StepReceipt {
            step_id: "agent:assemble:run-1".into(),
            started_at: Utc.with_ymd_and_hms(2026, 5, 23, 10, 0, 0).unwrap(),
            finished_at: Utc.with_ymd_and_hms(2026, 5, 23, 10, 0, 5).unwrap(),
            model: Some(ArtefactSnapshot {
                name: "llama-3-8b-q4".into(),
                digest: [7u8; 32],
                engine_kind: "llama".into(),
            }),
            input_digest: [1u8; 32],
            output_digest: [2u8; 32],
            tags: vec!["public".into(), "compliance:DPP-CEN-JTC24".into()],
            meta,
        }
    }

    #[test]
    fn roundtrip_preserves_required_fields() {
        let profile = DppSchemaProfile::with_parts("prvnz-dpp:v1", "https://example/ctx.jsonld");
        let r = sample_receipt();
        let bytes = profile.encode(&r).unwrap();
        let r2 = profile.decode(&bytes).unwrap();
        assert_eq!(r.step_id, r2.step_id);
        assert_eq!(r.started_at, r2.started_at);
        assert_eq!(r.finished_at, r2.finished_at);
        assert_eq!(r.input_digest, r2.input_digest);
        assert_eq!(r.output_digest, r2.output_digest);
        assert_eq!(r.tags, r2.tags);
        assert_eq!(r.meta, r2.meta);
        assert_eq!(
            r.model.as_ref().map(|m| &m.name),
            r2.model.as_ref().map(|m| &m.name),
        );
    }

    #[test]
    fn decode_rejects_unknown_event_class() {
        let profile = DppSchemaProfile::with_parts("prvnz-dpp:v1", "https://example/ctx.jsonld");
        let bad = json!({"type":"TransformationEvent","stepId":"x"}).to_string();
        assert!(profile.decode(bad.as_bytes()).is_err());
    }
}
