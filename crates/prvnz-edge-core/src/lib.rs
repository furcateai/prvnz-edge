// SPDX-License-Identifier: Apache-2.0

//! # `prvnz-edge-core`
//!
//! Pi-class PRVNZ Digital Product Passport (DPP) participation runtime.
//! Composes `minima-attest` (on-chain anchoring) and `tenzro-edge` (multi-VM
//! settlement + agent network) behind Tier-1 trait impls specialised for the
//! DPP vertical.
//!
//! ## Tier-1 trait impls (DPP specialisation)
//!
//! | Trait | Impl | Backed by |
//! |---|---|---|
//! | `SchemaProfile` | [`DppSchemaProfile`] | JSON-LD encoder (CEN/CLC JTC 24 + GS1 EPCIS 2.0) |
//! | `TriggerSource` | [`DppLifecycleTrigger`] | `notify` file-watch on a JSONL event feed |
//! | `PolicyRouter` | [`DppPolicyRouter`] | Tag/meta classification — sensitive → DAML, public → EVM/SVM, anchor → Minima |
//! | `SelectiveDisclosure` | [`DppSelectiveDisclosure`] | IETF SD-JWT envelope (salted-hash disclosures) |
//!
//! ## Composition rule
//!
//! prvnz-edge **composes** `minima-attest` (via its `furcate` feature) and
//! `tenzro-edge-core` — it never reimplements either. The Tier-2 sinks
//! (`MinimaReceiptSink`, `TenzroReceiptSink`) are referenced via their
//! `SinkId`s in [`DppPolicyRouter`]'s [`RoutingDecision`]; the agent loop
//! dispatches based on those ids.
//!
//! ## Hard rule
//!
//! Zero PRVNZ-specific knowledge ever flows back into Tier 1. The kernel
//! doesn't know what a DPP is. This crate implements generic traits with
//! DPP-shaped impls.
//!
//! ## Standards
//!
//! - CEN/CLC JTC 24 — DPP harmonised data model
//! - GS1 EPCIS 2.0 — event capture
//! - EN 18246 — DPP integrity (audit logging of every action)
//! - `OpenSSF` Model Signing v1.0 — AI-derived passport claims (upstream, via `furcate-inference-registry`)
//! - W3C VCs v2.0 — passport envelope shape
//! - W3C DIDs — issuer identification (upstream, via `TenzroAttester` TDIP proofs)
//!
//! [`RoutingDecision`]: furcate_inference_core::RoutingDecision

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use thiserror::Error;

pub mod config;
pub mod disclosure;
pub mod policy;
pub mod schema;
pub mod trigger;

pub use disclosure::DppSelectiveDisclosure;
pub use policy::DppPolicyRouter;
pub use schema::DppSchemaProfile;
pub use trigger::DppLifecycleTrigger;

/// Errors common across PRVNZ DPP edge participation.
///
/// Most code paths translate this into a Tier-1 trait error
/// (`SchemaError`, `TriggerError`, `PolicyError`, `DisclosureError`) before
/// returning to the agent loop; this enum is exposed for callers that wire
/// the impls into their own application surface.
#[derive(Debug, Error)]
pub enum PrvnzEdgeError {
    /// Failed to shape the receipt into a CEN/CLC JTC 24 + GS1 passport.
    #[error("schema: {0}")]
    Schema(String),
    /// Lifecycle trigger failed.
    #[error("trigger: {0}")]
    Trigger(String),
    /// Policy router failed to classify or route a claim.
    #[error("policy: {0}")]
    Policy(String),
    /// Selective disclosure (SD-JWT) failed.
    #[error("disclosure: {0}")]
    Disclosure(String),
    /// Upstream Minima failure.
    #[error("minima: {0}")]
    Minima(String),
    /// Upstream Tenzro failure.
    #[error("tenzro: {0}")]
    Tenzro(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, PrvnzEdgeError>;
