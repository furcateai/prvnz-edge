# prvnz-edge

**A Pi-class runtime for issuing and verifying PRVNZ Digital Product Passports.**

`prvnz-edge` makes a Pi-class node a first-class participant in the [PRVNZ](https://prvnz.com)
Digital Product Passport (DPP) vertical: it composes `minima-attest` (on-chain
anchoring) and `tenzro-edge` (multi-VM settlement + agent network) into a
CEN/CLC JTC 24 + GS1 EPCIS + EN 18246 + OpenSSF Model Signing v1.0 + W3C VCs
compliant DPP issuer/verifier.

```bash
prvnz-edge issue   --product-id <GTIN> --batch <batch-id>
prvnz-edge verify  --passport <vc-jws>
prvnz-edge replay                       # flush offline-buffered passports
```

---

## Where it sits

```
github.com/furcateai/
├── furcate-protocol                   wire-format specs + schemas
├── furcate-inference                  edge inference kernel
├── furcate-mesh                       LAN peer fabric for edge nodes
├── minima-attest                      Rust client for anchoring hashes on a local Minima node
├── tenzro-edge                        runtime for participating in the Tenzro Network
├── prvnz-edge        ← you are here   runtime for issuing PRVNZ Digital Product Passports
├── furcate-pi-hat                     Pi 5 HAT hardware support (GPIO, 1-Wire, OPC UA triggers)
└── furcate-pi-minima                  supervisor for running a Minima full node on a Pi
```

`prvnz-edge` is the **first documented vertical application** built on this set
of crates. It composes the participation crates (`minima-attest` + `tenzro-edge`)
rather than implementing low-level network participation itself.

## The hard rule

**Zero PRVNZ-specific knowledge ever flows back into the kernel.** The
inference and mesh kernels (`furcate-inference-core`, `furcate-mesh-core`)
don't know what a DPP is, don't know what GS1 is, never will.

`prvnz-edge` implements kernel traits that *happen to be specialised* for DPP:

| Trait | Where | PRVNZ specialisation |
|---|---|---|
| `SchemaProfile` | `furcate-inference-core` | CEN/CLC JTC 24 + GS1 EPCIS JSON-LD shape |
| `TriggerSource` | `furcate-inference-core` | DPP lifecycle events (`onProductionComplete`, `onRepairDetected`, …) |
| `PolicyRouter` | `furcate-inference-core` | Sensitive → DAML private contracts; public → EVM/SVM |
| `SelectiveDisclosure` | `furcate-inference-core` | BBS+ / SD-JWT envelope for VC claims |

That's it. Generic traits, DPP-specialised impls. The kernel stays vertical-agnostic forever.

## What it composes

```
prvnz-edge
  ├── implements kernel traits (SchemaProfile, TriggerSource, PolicyRouter,
  │   SelectiveDisclosure)
  ├── depends on minima-attest  (on-chain anchoring of DPP receipts)
  └── depends on tenzro-edge    (multi-VM settlement, agent network for
                                 inter-org DPP coordination)
```

A PRVNZ-edge node configured with all three running gets:

- **DPP issuance** — sign a VC, write its hash to Minima, optionally settle multi-org claims via Tenzro
- **DPP verification** — re-verify VC signature, prove Minima anchoring, check Tenzro settlement record
- **Lifecycle events** — `onProductionComplete` fires → run quality-check agent → issue passport → anchor
- **Selective disclosure** — share only the claims the verifier is authorised to see (BBS+ / SD-JWT)

## What this is **not**

- **Not the PRVNZ spec.** The PRVNZ DPP standard lives in its own org / spec repo. This is only the Pi-class participation crate.
- **Not the PRVNZ server / issuer-of-last-resort.** Server-side infrastructure lives in PRVNZ's own repos. This is the edge-issuer/edge-verifier.
- **Not a generic VC framework.** It's specifically the DPP shape (CEN/CLC JTC 24 + GS1 EPCIS).

## Quick start

```bash
cargo build --workspace

# Issue a passport
cargo run -p prvnz-edge-cli -- issue --product-id 01234567890128 --batch 2026-W21-A

# Verify a passport
cargo run -p prvnz-edge-cli -- verify --passport @passport.jws

# Flush any offline-buffered passports
cargo run -p prvnz-edge-cli -- replay
```

In `furcate.toml`:

```toml
[schema.dpp]
type = "prvnz-dpp-jsonld"

[triggers.production_complete]
type = "prvnz-lifecycle"
event = "onProductionComplete"

[policy_router.prvnz]
type = "prvnz-dpp-router"
rules = [
  { tag = "sensitive", sinks = ["tenzro-daml"] },
  { tag = "public",    sinks = ["minima", "tenzro-evm"] },
]

[selective_disclosure.bbs]
type = "prvnz-bbs"
```

## Standards compliance

- **CEN/CLC JTC 24** — DPP harmonised data model
- **GS1 EPCIS 2.0** — event capture
- **EN 18246** — DPP integrity
- **OpenSSF Model Signing v1.0** — for AI-derived passport claims
- **W3C VCs (Verifiable Credentials Data Model v2.0)** — passport envelope
- **W3C DIDs** — issuer identification (via Tenzro TDIP)

## Crate layout

```
crates/
├── prvnz-edge-core    # SchemaProfile / TriggerSource / PolicyRouter /
│                       SelectiveDisclosure impls for DPP
└── prvnz-edge-cli     # `prvnz-edge` binary (issue / verify / replay)
```

## Pi-class concerns we handle

- **Offline issuance** — generate signed passports when offline, queue for anchoring on reconnect
- **Selective disclosure pre-computed** — BBS+ proof generation cached so verifier flows stay fast
- **Battery-friendly** — lifecycle event polling is opportunistic, not pinned wake
- **Local-first verification** — verify VCs without network when issuer DID + chain receipts are cached

## Status

- Version: **0.1.0** (scaffold)
- Depends on `minima-attest` and `tenzro-edge` (both participation crates)
- Real wiring lands in v0.1.x

## Versioning

- Releases **independently** of the `furcate-inference` kernel
- Pins `furcate-inference-core` to a specific major version
- Pins `minima-attest` and `tenzro-edge` to specific major versions

MSRV, 1.0 timing, and deprecation windows are roadmap decisions and are not set here.

## Sibling repos

- [`furcate-protocol`](https://github.com/furcateai/furcate-protocol) — wire-format specs + schemas (DPP receipt shape extends `StepReceipt`)
- [`furcate-inference`](https://github.com/furcateai/furcate-inference) — edge inference kernel (provides the trait surface this implements)
- [`furcate-mesh`](https://github.com/furcateai/furcate-mesh) — LAN peer fabric for edge nodes
- [`minima-attest`](https://github.com/furcateai/minima-attest) — Rust client for anchoring hashes on a local Minima node (PRVNZ-edge depends on this for on-chain anchoring)
- [`tenzro-edge`](https://github.com/furcateai/tenzro-edge) — runtime for participating in the Tenzro Network (PRVNZ-edge depends on this for multi-VM settlement + agent network)
- [`furcate-pi-hat`](https://github.com/furcateai/furcate-pi-hat) — Pi 5 HAT hardware support
- [`furcate-pi-minima`](https://github.com/furcateai/furcate-pi-minima) — supervisor for running a Minima full node on a Pi (run a local node for `minima-attest`)

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
