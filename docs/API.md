# NetOps Autopilot — Public API Reference

**Status:** generated from the actual source on disk (every signature in
this file is importable in the current release).

**Constitution reminder:** the API is intentionally narrow. Anything that
would let a caller bypass T1–T6 (e.g. a free-form `run_cmd()` method) is
absent by design. The only public surface for live device interaction is
the adapter-allowlisted path.

---

## `netops_autopilot.core.ids`

```python
def new_id() -> str
def typed_id(kind: str, raw: Optional[str] = None) -> str
def extract_kind(typed: str) -> Optional[str]
def is_typed_id(typed: str, kind: Optional[str] = None) -> bool
def short_id(typed: str, length: int = 8) -> str
def strip_kind(typed: str) -> str
```

* `new_id()` — back-compat. Returns a random 8-char hex.
* `typed_id(kind, raw=None)` — returns `"<kind>:<unique>"`. `kind` must
  be non-empty. If `raw` is None a fresh 32-hex unique part is generated.
* `is_typed_id(typed, kind=None)` — True iff `typed` starts with
  `<kind>:` (or any kind if `kind` is None).
* `short_id(typed, length=8)` — returns the typed id with only the
  rightmost `length` chars of the unique part (the `kind:` prefix is
  preserved).
* `strip_kind(typed)` — returns the unique part only. On untyped input
  the input is returned unchanged.

---

## `netops_autopilot.core.failures`

```python
class FailureClass(str, Enum):
    RETRYABLE       # transient — caller may retry (L03)
    BLOCKED         # precondition false — caller must not retry
    ROLLED_BACK     # partial success: was undone
    PARTIAL         # some items failed (T4: count/total)
    MANUAL_REQUIRED # no automation path
    FATAL           # engineering action required

class Failure(Exception):
    cls: FailureClass
    causes: tuple[str, ...]
    count: int  # PARTIAL only
    total: int  # PARTIAL only
    evidence_ids: tuple[str, ...]
    retry_hint: Optional[str]  # RETRYABLE only

def blocked(*causes: str, evidence_ids: tuple[str, ...] = ()) -> Failure
```

Every engine either succeeds or raises/returns a `Failure` with a
typed `cls`. `causes` is a tuple of structured reason codes (NEVER
free-form excuses). Empty `causes` raises `ValueError` (L03 invariant).

---

## `netops_autopilot.core.counters`

```python
T5_COUNTERS: tuple[str, ...]  # the ten release-gate counter names

class CounterCollector:
    def increment(self, name: str, reason: str) -> None
    def value(self, name: str) -> int
    def snapshot(self) -> dict[str, int]
    def reasons(self, name: str) -> Iterator[str]
    def assert_release_gate(self) -> None
```

Release requires ALL counters == 0. The registry is closed:
`increment("UNKNOWN_KEY", ...)` raises `KeyError`. `assert_release_gate()`
raises `AssertionError` listing the dirty counters.

---

## `netops_autopilot.core.timeauth`

```python
class ClockStatus(str, Enum):
    SYNCED
    UNSYNCED
    DRIFT_SUSPECTED

DECISION_FRESHNESS_BOUNDS: dict[str, Optional[float]]
# {"DEPLOY": 60.0, "ROLLBACK": 60.0, "DESIGN": 86400.0,
#  "DOCUMENTATION": None, "MONITORING": 300.0}

class TimeAuthority:
    def __init__(self, clock: Callable[[], datetime], status: ClockStatus = ...) -> None
    def now(self) -> datetime  # always timezone-aware
    def age_seconds(self, collected_at: datetime) -> float
    def evaluate(self, decision_kind: str, collected_at: datetime,
                 hard_freshness_required: bool = True) -> FreshnessVerdict

class FixedTimeAuthority(TimeAuthority):
    def __init__(self, start: Optional[datetime] = None) -> None
    def now(self) -> datetime
    def advance(self, delta: timedelta) -> None
    def iso(self) -> str
```

The clock is injectable; production uses the OS clock + recorded sync
state from the platform's time status. Naive datetimes are rejected
(`ValueError`) — Time Authority is aware-only by construction.

---

## `netops_autopilot.core.ratelimit`

```python
@dataclass(frozen=True)
class RateLimitPolicy:
    capacity: float       # > 0
    refill_per_s: float   # > 0

class RateLimiter:
    def __init__(self, policy: RateLimitPolicy, clock: Optional[Callable[[], float]] = None) -> None
    def try_acquire(self, n: float = 1.0) -> bool
    def acquire(self, n: float = 1.0) -> None  # raises Failure(RETRYABLE) on dry
    @property
    def available_tokens(self) -> float
```

Token-bucket algorithm. `acquire(n)` raises
`Failure(RETRYABLE, ("RATE_LIMITED: ...",), retry_hint="sleep Ns and retry")`
when the bucket is too dry. The clock is injected for determinism.

---

## `netops_autopilot.core.cache`

```python
@dataclass
class CacheStats:
    hits: int
    misses: int
    evictions: int
    size: int
    @property
    def hit_rate(self) -> float

class LRUCache(Generic[K, V]):
    def __init__(self, capacity: int) -> None
    @property
    def capacity(self) -> int
    @property
    def stats(self) -> CacheStats
    def get(self, key: K, default: Optional[V] = None) -> Optional[V]
    def set(self, key: K, value: V) -> None
    def delete(self, key: K) -> bool
    def clear(self) -> None
    def __len__(self) -> int
    def __contains__(self, key: K) -> bool
    def keys(self) -> list[K]
```

Bounded, thread-safe LRU. Capacity must be positive (else `ValueError`).
`get` returns `default` on miss, never raises. Eviction is O(1) via
`OrderedDict.move_to_end`.

---

## `netops_autopilot.llm`

```python
@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    def to_dict(self) -> dict

@dataclass
class LLMRequest:
    system: str
    user: str
    response_schema: Optional[dict] = None
    options: dict = field(default_factory=dict)

@dataclass
class LLMResponse:
    text: str
    structured: Optional[dict] = None
    usage: LLMUsage = field(default_factory=LLMUsage)
    duration_s: float = 0.0
    model: str = ""
    raw: dict = field(default_factory=dict)

class LLMProvider(Protocol):
    name: str
    def is_available(self) -> bool
    def complete(self, request: LLMRequest) -> LLMResponse

class NullProvider:    # always raises Failure(BLOCKED, "LLM_PROVIDER_DISABLED")
class EchoProvider:    # deterministic; honors response_schema when set
class OllamaProvider:  # real HTTP; redacts at egress; JSON-schema-mode emits `format`

def build_provider(name: str, **kw) -> LLMProvider
def redact(text: str) -> str
def redact_dict(d: Any) -> Any
REDACT_PATTERNS: tuple[re.Pattern, ...]
```

`build_provider(name)` accepts:
* `""`, `"null"`, `"none"` → `NullProvider`
* `"echo"` → `EchoProvider`
* `"ollama"` → `OllamaProvider(host=..., model=...)` (lazy-imports urllib)
* anything else → `ValueError("LLM_PROVIDER_UNKNOWN: <name>")`

`redact()` strips: passwords, API keys, tokens, PEM blocks, bearer
headers, basic-auth headers, AWS access keys. `redact_dict()` is
recursive across dicts and lists; keys whose name matches a secret
pattern (e.g. `password`, `api_key`) are also redacted even if the
value is a free-form string.

---

## `netops_autopilot.adapters.cisco_iosxe`

```python
LAYER_COMMANDS: dict[str, str]  # layer -> allowlisted read-only command

class CiscoIosXeSerialAdapter:
    vendor_family: str = "cisco/ios-xe"
    def __init__(self, *, port_factory=None, clock=None, sleep=None) -> None
    def capability(self, operation: str) -> CapabilityState
    def open_session(self, device_ref: str, method: str) -> ExecSession
    def close_session(self, device_ref: str) -> None
    def acquire_lock(self, device_ref: str) -> bool
    def release_lock(self, device_ref: str) -> None
    def human_session_active(self, device_ref: str) -> bool
    def run_layer(self, device_ref: str, layer: str) -> bytes
    def capture_running_config(self, device_ref: str) -> bytes
    def apply_ir(self, device_ref: str, ir_ref: str, dry_run: bool = False) -> Any
```

* `method != "serial_console"` ⇒ `Failure(BLOCKED, "NOT_SUPPORTED: ...")`.
* `layer not in LAYER_COMMANDS` ⇒ `Failure(BLOCKED, "NOT_MODELED: ...")`.
* `apply_ir` requires an explicit `ir_ref` from the allowlist; free-form
  text is rejected (T3 / L04).

---

## `netops_autopilot.autopilot`

```python
class AutopilotEngine:
    def __init__(self, *, store, key_id, io, time_authority, ...) -> None
    def run(self, *, probe_port_session_factory, mgmt_session_factory,
            port: str, execute: bool = False) -> RunReport
```

`run()` drives the full pipeline (BOND → BOOT_PROBE → DISCOVERY_A →
TOPOLOGY_MAP → INTENT_ELICITATION → DESIGN → RENDER → EXECUTION_GATE →
REPORT). The returned `RunReport` carries the phase timeline, the
ledger, the failure summary, and the final verdict (`COMPLETE-STAGED`
or `BLOCKED-<phase>`).

---

## `netops_autopilot.cli`

* `netops_autopilot.cli.io.ScriptedIO` — deterministic I/O for tests
  (answers human prompts from a pre-canned list).
* `netops_autopilot.cli.progress.ProgressReporter` — observable run
  lifecycle (subscribe to snapshots).
* `netops_autopilot.cli.scenarios.make_scenario_io(name)` — returns a
  `ScriptedIO` for the named scenario (`branch`, `leaf-spine`, `hotel`,
  `retail`).

---

## `netops_autopilot.reporting`

* `render_html_report(data) -> str` — full self-contained HTML.
* `render_json_report(report=..., ledger_event_count=..., chain_ok=...) -> str`
  — JSON conforming to schema `netops-autopilot/run-report/v1`.
* `report_from_autopilot(report, run_id, ledger_event_count, chain_ok) -> ReportData`
  — the canonical adapter from the engine report to the rendering data
  shape.
