"""Adapter layer (ADR-0001): vendor isolation via capability-bound interfaces.

Engines import ONLY from this package's interfaces; vendor packages bind at
runtime through the AdapterRegistry keyed by identified
(vendor, platform, os, version) — never by vendor-name conditionals.
"""
