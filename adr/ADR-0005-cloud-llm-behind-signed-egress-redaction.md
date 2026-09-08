# ADR-0005 · Cloud LLM behind signed egress policy with secret redaction

Status: **Accepted** · Trace: §18, §19, §5 · Resolves OI-0004

## Context
Sponsor answer (d): LLM runs via cloud API. L11 forbids secrets reaching the
LLM, and §19 requires every connector to carry an explicit availability
state so that offline operation degrades gracefully.

## Decision
1. LLM access is a **Connector** (`LLM_CLOUD`): states
   AVAILABLE/UNAVAILABLE/NOT_CONFIGURED; classification per task
   REQUIRED/OPTIONAL. Agents must define behavior for UNAVAILABLE
   (A1–A5 fall back to BLOCKED-with-recommendation-template; nothing
   executes).
2. All outbound agent payloads pass the **Egress Policy**: a signed policy
   names allowed provider endpoints; anything else is refused before DNS.
3. **Secret redaction pipeline** (ordered): credential store references
   stripped → secret classifier (patterns + entropy + known-credential
   registry) → allowlisted field projection (only schema-declared agent
   input fields leave the machine) → logged hash of the sent payload (audit,
   no content).
4. Provider abstraction: `LLMProvider` interface with `CloudAPIProvider`
   (v1) and `OllamaProvider` (delivered in the same release as the offline
   fallback; selecting it is a policy toggle).
5. No device output ever goes to the LLM raw (L17/§10): only Observations,
   Claims, Twin projections, and local RAG snippets of vendor documentation.

## Consequences
* `credential_exposure` counter is fed by a harness scanner over recorded
  egress payloads of every scenario.
* Cloud outage ⇒ agents UNAVAILABLE ⇒ platform continues in M0/M1-deterministic
  modes; documented, tested.

## Alternatives considered
* Local-only in v1 (rejected by sponsor; kept as first-class option).
* Sending raw CLI output to the model for parsing (rejected: §10).
