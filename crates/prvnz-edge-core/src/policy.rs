// SPDX-License-Identifier: Apache-2.0

//! [`DppPolicyRouter`] — `PolicyRouter` impl implementing the PRVNZ
//! "sensitive → DAML, public → EVM/SVM, anchor → Minima" routing rule.
//!
//! # Classification
//!
//! A `StepReceipt` is **sensitive** if either:
//!
//! 1. It carries any tag listed in [`DppConfig::sensitive_tags`], **or**
//! 2. Its `meta` map contains any key listed in
//!    [`DppConfig::sensitive_meta_keys`].
//!
//! Otherwise it is **public**.
//!
//! # Routing
//!
//! | Classification | Sinks selected |
//! |---|---|
//! | Sensitive | `minima_anchor_sink` + `tenzro_private_sink` |
//! | Public    | `minima_anchor_sink` + `tenzro_public_sink`  |
//!
//! The Minima anchor is unconditional — every receipt's BLAKE3 digest gets
//! anchored on chain so an external verifier can re-prove integrity. The
//! sensitive-vs-public distinction only changes *where the receipt body
//! goes* (a DAML/Canton private contract vs an EVM/SVM public log).
//!
//! [`DppConfig::sensitive_tags`]: crate::config::DppConfig::sensitive_tags
//! [`DppConfig::sensitive_meta_keys`]: crate::config::DppConfig::sensitive_meta_keys

use async_trait::async_trait;
use furcate_inference_core::{
    AttesterId, PolicyError, PolicyRouter, RoutingDecision, SinkId, StepReceipt,
};

use crate::config::DppConfig;

/// `PolicyRouter` impl routing sensitive vs public DPP claims.
#[derive(Clone, Debug)]
pub struct DppPolicyRouter {
    sensitive_tags: Vec<String>,
    sensitive_meta_keys: Vec<String>,
    minima_anchor_sink: SinkId,
    tenzro_public_sink: SinkId,
    tenzro_private_sink: SinkId,
    default_attester: Option<AttesterId>,
}

impl DppPolicyRouter {
    /// Construct a router from a [`DppConfig`].
    #[must_use]
    pub fn new(cfg: &DppConfig) -> Self {
        Self {
            sensitive_tags: cfg.sensitive_tags.clone(),
            sensitive_meta_keys: cfg.sensitive_meta_keys.clone(),
            minima_anchor_sink: cfg.minima_anchor_sink.clone(),
            tenzro_public_sink: cfg.tenzro_public_sink.clone(),
            tenzro_private_sink: cfg.tenzro_private_sink.clone(),
            default_attester: cfg.default_attester.clone(),
        }
    }

    /// Classify a receipt as sensitive (`true`) or public (`false`).
    #[must_use]
    pub fn is_sensitive(&self, receipt: &StepReceipt) -> bool {
        let by_tag = receipt
            .tags
            .iter()
            .any(|t| self.sensitive_tags.iter().any(|s| s == t));
        if by_tag {
            return true;
        }
        receipt
            .meta
            .keys()
            .any(|k| self.sensitive_meta_keys.iter().any(|s| s == k))
    }
}

#[async_trait]
impl PolicyRouter for DppPolicyRouter {
    async fn route(
        &self,
        receipt: &StepReceipt,
    ) -> std::result::Result<RoutingDecision, PolicyError> {
        let mut sinks = vec![self.minima_anchor_sink.clone()];
        if self.is_sensitive(receipt) {
            sinks.push(self.tenzro_private_sink.clone());
        } else {
            sinks.push(self.tenzro_public_sink.clone());
        }
        let attesters = self.default_attester.clone().into_iter().collect();
        Ok(RoutingDecision { sinks, attesters })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn receipt_with(tags: Vec<&str>, meta_keys: Vec<&str>) -> StepReceipt {
        let mut meta = BTreeMap::new();
        for k in meta_keys {
            meta.insert(k.into(), json!("v"));
        }
        StepReceipt {
            step_id: "s".into(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            model: None,
            input_digest: [0u8; 32],
            output_digest: [0u8; 32],
            tags: tags.into_iter().map(String::from).collect(),
            meta,
        }
    }

    #[tokio::test]
    async fn public_receipt_routes_to_public_sink() {
        let router = DppPolicyRouter::new(&DppConfig::default());
        let r = receipt_with(vec!["public"], vec![]);
        let d = router.route(&r).await.unwrap();
        assert!(d.sinks.iter().any(|s| s.0 == "minima:anchor"));
        assert!(d.sinks.iter().any(|s| s.0 == "tenzro:public"));
        assert!(!d.sinks.iter().any(|s| s.0 == "tenzro:private"));
    }

    #[tokio::test]
    async fn sensitive_tag_routes_to_private_sink() {
        let router = DppPolicyRouter::new(&DppConfig::default());
        let r = receipt_with(vec!["sensitive", "compliance:DPP"], vec![]);
        let d = router.route(&r).await.unwrap();
        assert!(d.sinks.iter().any(|s| s.0 == "tenzro:private"));
        assert!(!d.sinks.iter().any(|s| s.0 == "tenzro:public"));
    }

    #[tokio::test]
    async fn sensitive_meta_key_overrides_public_tag() {
        let cfg = DppConfig {
            sensitive_meta_keys: vec!["customer_id".into()],
            ..DppConfig::default()
        };
        let router = DppPolicyRouter::new(&cfg);
        let r = receipt_with(vec!["public"], vec!["customer_id"]);
        let d = router.route(&r).await.unwrap();
        assert!(d.sinks.iter().any(|s| s.0 == "tenzro:private"));
    }
}
