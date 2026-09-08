"""E03 Parsers/Normalizers — deterministic only (D0-08 §2).

The LLM never sees raw device text; parsers convert RawArtifacts into typed
Observations. Missing fields become MISSING/PARSE_FAILED observations —
never guessed values (L01).
"""
