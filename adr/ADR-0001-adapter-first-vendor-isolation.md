# ADR-0001 · Adapter-first vendor isolation; Python 3.11+ core

Status: **Accepted** · Trace: §6, §20 · Resolves part of OI-0001

## Context
Six vendors ship in v1 at equal priority (Cisco IOS/IOS-XE, RouterOS, Junos,
FortiOS, Aruba/HP, UniFi). Each exposes different transports (CLI, NETCONF,
RESTCONF, API, MAC-layer, controller adoption) and different rollback
mechanisms. Vendor libraries (Scrapli, Netmiko, NAPALM, ncclient, …) must
stay swappable and never leak into engine logic.

## Decision
1. Core language: Python 3.11+.
2. All vendor interaction flows through **Adapter Interfaces**
   (§6): `AccessAdapter, DiscoveryAdapter, ConfigAdapter, RollbackAdapter,
   RecoveryAdapter, VerificationAdapter, MonitoringAdapter,
   LifecycleAdapter, WirelessControlPlaneAdapter`.
3. Binding is by **Capability → Interface → Vendor implementation**
   (e.g. `RollbackAdapter → CiscoIOSXERollbackAdapter`), resolved at runtime
   from the identified (vendor, platform, OS, version) tuple — never by
   string checks like `if vendor == "X"`.
4. Every vendor surface ships a `NOT_SUPPORTED` stub that announces itself
   explicitly; a missing implementation is a typed state, not an exception.
5. Engines import only adapter interfaces; CI enforces the import boundary.

## Consequences
* New vendor = new adapter package; no engine change.
* Capability Matrices (§11) are the runtime source for "can we?" — adapters
  never self-declare coverage beyond what the matrix records.
* Slightly more indirection upfront; acceptable given six-vendor breadth.

## Alternatives considered
* Direct library calls in engines (rejected: coupling, untestable).
* Plugin marketplace model (rejected for v1: signed-but-monorepo adapters
  keep the harness deterministic).
