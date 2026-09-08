# ADR-0008 · Windows (MSI) packaging first

Status: **Accepted** · Trace: §20, §23 (D6) · Resolves OI-0003

## Context
Sponsor answer (c): the engineer's machine runs Windows. The stack is
Tauri (Rust shell) + React/TS frontend + Python core sidecar.

## Decision
1. Release 1 packages: MSI (with optional silent install flags for fleets).
   AppImage/deb and DMG follow as additive CI targets (same Tauri pipeline).
2. The Python core ships as an embedded distribution inside the package
   (no external interpreter requirement); adapters and golden fixtures are
   data files inside the bundle.
3. Secrets use Windows Credential Manager as the OS keychain provider
   (§18), behind a `KeychainProvider` interface so Linux/macOS providers
   slot in later.
4. Serial access targets COM ports via pySerial; the app requests no admin
   rights beyond what device drivers require; UAC elevation is never needed
   for normal operation (documented constraint).

## Consequences
* CI matrix prioritizes a Windows runner; Linux runner kept green for the
  core (unit/parser tiers) since harness CI is cross-platform.
* File paths, line endings, and shell assumptions are Windows-first tested.

## Alternatives considered
* Electron (rejected: spec mandates Tauri).
* Linux-first (rejected: sponsor environment is Windows).
