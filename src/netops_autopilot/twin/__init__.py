"""E05 Digital Twin — current-state projection of the Evidence Ledger.

The Twin answers "what is the believed state, and on what evidence"; it
never originates facts (L02): every entity/field exists only via a CLAIM
with relevance PASS, and every mutation emits a TWIN_PROJECTION
STATE_TRANSITION record (D0-04 §1 chain tail). History queries go to the
Ledger, not to the Twin.
"""
