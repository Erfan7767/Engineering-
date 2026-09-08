# ADR-0006 · Real-hardware lab as the test substrate for v1

Status: **Accepted** · Trace: §21 · Resolves OI-0005

## Context
Sponsor answer (e): no containerlab/GNS3/EVE-NG; a real-hardware lab is
available. The §21 pyramid requires integration, failure-injection, and
hardware-in-the-loop tiers anyway; emulation would have been an extra
substrate to maintain.

## Decision
1. Harness tiers implemented against: unit/parser golden fixtures (no
   hardware) → **physical lab devices** (integration, protocol, failure
   injection, network emulation via real topology) → hardware-in-the-loop
   dedicated bench → Shadow Mode on live customer networks (M0 only).
2. Lab devices are managed by the platform itself from D1 (self-hosting):
   the lab IS the first MANAGED site, which forces Day-0/Collector/Parsers
   to be real, not mocked.
3. Destructive scenarios (NETINSTALL, ROMMON, factory reset) run only on
   explicitly designated sacrificial units; designation is a signed lab
   policy (ties into §9 destructive gating).
4. Golden fixtures per vendor/version remain mandatory (parser tests must
   run in CI without hardware); hardware tests are scheduled bench runs.

## Consequences
* Test matrix must encode device availability: a scenario requiring absent
   hardware reports NOT_TESTED (never skipped-silently, L03).
* Timing: hardware runs are slower ⇒ tiered CI policy (unit/parser on every
   commit; hardware nightly + on-demand).
* Emulators may be added later as an OPTIONAL connector tier without
   changing the pyramid contract.

## Alternatives considered
* containerlab-first (rejected: sponsor has real hardware; dual substrate
  doubles fixture maintenance for v1).
