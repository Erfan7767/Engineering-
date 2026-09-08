# D0-05 · Threat Model (STRIDE per plane)

Status: **ACCEPTED (D0), living document** · Trace: §18, §3 (L11)
Scope: platform planes (Security, Evidence, Control, Agent, Egress, Physical
interface to the customer network). Every mitigation names its enforcement
point; mitigations without code targets become Open Items.

## Assets
A1 Credentials (device & platform) · A2 Evidence integrity (ledger) ·
A3 Change authority (who/what can arm a change) · A4 Customer network
continuity · A5 Audit completeness · A6 Platform update integrity.

## Trust boundaries
TB1 PC ↔ device (serial/L2/L3) · TB2 Engines ↔ adapters · TB3 Agents ↔
everything (agents are **untrusted input producers**) · TB4 Platform ↔
cloud LLM/licensing/CVE feeds · TB5 Human ↔ platform (RBAC) ·
TB6 Platform ↔ OS (keychain, filesystem).

## Threat register (initial)

| ID | Threat (STRIDE) | Boundary | Impact on asset | Mitigation (enforcement point) | Residual |
|---|---|---|---|---|---|
| TH-01 | Credential theft via agent prompts/logs (Info disclosure) | TB3/TB4 | A1 | L11: agents receive only references; egress redaction pipeline (ADR-0005); secret classifier before artifact storage; harness `credential_exposure` counter | Low |
| TH-02 | Forged/tampered evidence to force a decision (Spoofing/Tampering) | TB2 | A2 | Ed25519-signed Events, hash-chained ledger, startup integrity self-test (ADR-0002); relevance guard (D0-04 §5) | Low |
| TH-03 | LLM-driven unauthorized change (Elevation) | TB3 | A3 | Intent Objects only (L17); Entity Guard; gates per §13; HUMAN_ONLY frozen set (ADR-0007); allowlist at executor | Low |
| TH-04 | Management-plane lockout during autonomous change (DoS to ops) | TB1 | A4 | ADR-0004 lock-out plan gate; mgmt path PROTECTED_FOUNDATION (L15); rollback target content check; direct-connect risk disclosure | Medium → mitigated per site by OOB rollout |
| TH-05 | Stale evidence used at deploy (Tampering-by-time) | TB2 | A2/A4 | Freshness-per-Decision at decision time (ADR-0010); counter `stale_evidence_deployments` | Low |
| TH-06 | Gate bypass via crafted policy file (Elevation) | TB5 | A3 | Policies signed (Ed25519) with RBAC identity + MFA; schema forbids removing HUMAN_ONLY; all activations audited | Low |
| TH-07 | Rogue device impersonating identity (Spoofing) | TB1 | A2 | Identity Claims require DEVICE_IDENTITY scope evidence from multiple fields (version+inventory+serial cross-check); conflicts ⇒ CONFLICTING state, never auto-resolved | Medium |
| TH-08 | Parser exploit via crafted device output (Tampering) | TB1/TB2 | A2/A6 | Deterministic parsers with budgets (output size/time), sandboxed parse process, parse_status typed failures; golden-fixture regression | Low |
| TH-09 | Denial of service via command floods/broadcasts from probes (DoS) | TB1 | A4 | Per-command/per-device budgets + circuit breakers (§10 collector), probe rate caps, gated active evidence only (FSM-4 4.7) | Low |
| TH-10 | Supply-chain: malicious dependency/adapter (Tampering) | TB6 | A6 | Pinned deps + hashes, adapter import boundary lint, signed autonomy policies; update channel signature verification (D6) | Medium until D6 signing lands |
| TH-11 | Egress data exfiltration disguised as telemetry (Info disclosure) | TB4 | A1/A4 | Connector allowlist of endpoints (egress policy), payload field projection, logged payload hashes | Low |
| TH-12 | Replay of old signed Events to resurrect states (Spoofing) | TB2 | A2 | Hash chain monotonicity + freshness at decision time; replayed old evidence fails freshness for decisions | Low |
| TH-13 | Session hijack / parallel human session conflict (Tampering) | TB1 | A4 | Session locking per vendor + human-session detection (§10); lock failure ⇒ BLOCKED | Low |
| TH-14 | Insider overrides BLOCKED via waiver abuse (Elevation) | TB5 | A3 | Waivers are explicit audit events, identity-bound, scope-bound, downgrade autonomy for that scope (ADR-0009 alt-note); weekly waiver review report (D5) | Medium (organizational) |
| TH-15 | Clock manipulation to defeat freshness (Tampering) | TB2 | A2 | Time Authority: collector clock status recorded; UNSYNCED ⇒ conservative/BLOCKED (ADR-0010 §5); device clock never trusted | Low |
| TH-16 | Temporary resource leak becomes attack surface (Elevation) | TB1 | A4 | Temporary Resource Manager MANDATORY cleanup; change cannot CLOSE with open resources (FSM-2 2.12); counter `cleanup_leaks` | Low |
| TH-17 | Destructive recovery executed without gate (DoS) | TB1 | A4 | §9: destructive class separate, gate DESTRUCTIVE, never auto-selected; FSM-5 5.4 human-only | Low |
| TH-18 | Agent RAG poisoning via local vendor docs (Tampering) | TB3 | A3 | RAG corpus is curated/versioned local files; agent output still passes Entity Guard + deterministic validation; RAG source cited in rationale | Low |

## Rules
1. New feature ⇒ new threat review row before its phase exits (D-gate
   checklist item).
2. Any mitigation marked "docs only" is an Open Item until code exists.
3. TH-14 (waiver abuse) has an organizational residual: weekly waiver digest
   (D5) is the compensating control.
