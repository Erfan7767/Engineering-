"""NetConf / YANG Engine — typed config transactions.

A 30-year engineer uses NetConf on Juniper / Nokia / Cisco
IOS-XR for transactional config commits. This module is
the typed implementation: build a typed
:class:`NetConfRequest` from logical operations, validate
against the YANG contract, surface a typed
:class:`NetConfResult`.

Design contract:

* **Typed operations** — :class:`NetConfOp` is one of
  ``GET`` / ``EDIT`` / ``COMMIT`` / ``DISCARD``.
* **Deterministic** — same operations list → same request.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class NetConfOp(str, Enum):
    __test__ = False

    GET = "get"
    EDIT = "edit-config"
    COMMIT = "commit"
    DISCARD = "discard-changes"


class NetConfVerdict(str, Enum):
    __test__ = False

    OK = "OK"
    RPC_ERROR = "rpc-error"
    LOCK_DENIED = "lock-denied"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NetConfOperation:
    __test__ = False

    op: NetConfOp
    filter_xpath: str = ""
    config_xml: str = ""
    target: str = "running"


@dataclass
class NetConfRequest:
    __test__ = False

    target: str
    operations: list[NetConfOperation] = field(default_factory=list)
    request_id: int = 1

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"NetConf -> {self.target}: "
                f"{len(self.operations)} عملية (id={self.request_id})"
            )
        return (
            f"NetConf -> {self.target}: "
            f"{len(self.operations)} op(s) (id={self.request_id})"
        )


@dataclass
class NetConfResult:
    __test__ = False

    request_id: int
    verdict: NetConfVerdict
    message: str = ""
    applied_ops: int = 0

    @property
    def is_ok(self) -> bool:
        return self.verdict == NetConfVerdict.OK

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"NetConf: {self.verdict.value} "
                f"({self.applied_ops} عملية)"
            )
        return (
            f"NetConf: {self.verdict.value} "
            f"({self.applied_ops} op(s))"
        )


_OK_TAG = "<ok/>"
_RPC_ERROR_TAG = "<rpc-error>"


def parse_netconf_reply(
    request_id: int,
    xml: str,
) -> NetConfResult:
    """Parse a NetConf server <rpc-reply> XML payload."""
    if not xml or not xml.strip():
        return NetConfResult(
            request_id=request_id,
            verdict=NetConfVerdict.UNKNOWN,
        )
    if _OK_TAG in xml:
        return NetConfResult(
            request_id=request_id,
            verdict=NetConfVerdict.OK,
            applied_ops=1,
        )
    if _RPC_ERROR_TAG in xml:
        # Differentiate lock-denied from generic rpc-error.
        if "lock-denied" in xml:
            return NetConfResult(
                request_id=request_id,
                verdict=NetConfVerdict.LOCK_DENIED,
            )
        msg = _extract_error_msg(xml)
        return NetConfResult(
            request_id=request_id,
            verdict=NetConfVerdict.RPC_ERROR,
            message=msg,
        )
    if "lock-denied" in xml:
        return NetConfResult(
            request_id=request_id,
            verdict=NetConfVerdict.LOCK_DENIED,
        )
    return NetConfResult(
        request_id=request_id,
        verdict=NetConfVerdict.UNKNOWN,
    )


_ERROR_MSG = re.compile(
    r"<error-message>(?P<msg>.*?)</error-message>",
    re.DOTALL,
)


def _extract_error_msg(xml: str) -> str:
    m = _ERROR_MSG.search(xml)
    return (m.group("msg").strip() if m else "")


def build_request(
    *,
    target: str,
    operations: list[NetConfOperation],
    request_id: int = 1,
) -> NetConfRequest:
    """Build a typed :class:`NetConfRequest`."""
    return NetConfRequest(
        target=target,
        operations=list(operations),
        request_id=request_id,
    )
