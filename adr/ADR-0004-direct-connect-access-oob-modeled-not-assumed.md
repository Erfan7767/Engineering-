# ADR-0004 · v1 physical access: direct PC connection; OOB modeled, not assumed

Status: **Accepted** · Trace: §9, §10 (OOB Model) · Resolves OI-0002

## Context
Sponsor answer (b): no console server, no hub, no second NIC initially — the
engineer's PC connects directly to each device (Serial/Ethernet). §10 still
requires OOB to be a first-class model (`primary_path`, `secondary_path`,
`recovery_path`).

## Decision
1. Day-0 access plans assume **direct connect only**: SERIAL_CONSOLE and
   ETHERNET_DEFAULT_PROFILE are the baseline methods; MAC_LAYER
   (MNDP/MAC-Telnet/WinBox) available for RouterOS; CONTROLLER_ADOPT for
   UniFi/Aruba when their controller software runs locally.
2. The OOB model exists from day one (schema + Twin layer), but for any
   device without a configured OOB, `secondary_path`/`recovery_path`
   entries are recorded as `NOT_CONFIGURED` — never guessed.
3. Recovery Hierarchy levels L3 (OOB) and L6/L7 are therefore
   NOT_SUPPORTED/HUMAN_REQUIRED by default in v1 deployments; escalation
   skips them with recorded matrix lookups (FSM-5 guard 5.2).
4. Risk consequence made explicit to the user before ARMED: **a lockout on a
   direct-connected device without console reachability is a manual
   physical intervention** (HUMAN_TASK instructions are generated
   automatically).

## Consequences
* Changes touching the management plane on direct-connected devices are
  classified at least HIGH_RISK and require the lock-out plan gate artifact.
* Adding a console server later is purely additive (new RecoveryAdapter
  binding + paths move NOT_CONFIGURED → VERIFIED after test).

## Alternatives considered
* Deferring the OOB model entirely (rejected: §10 mandates it; retrofitting
  would break Twin layering).
