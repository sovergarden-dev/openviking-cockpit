"""Pure reference policy, not a transport, detector, GUI, or persistence layer.

Python 3.11+ standard library. All evidence is supplied by a trusted caller;
model declarations are not measurements. See REFERENCE_README.md for limits.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum
from urllib.parse import urlsplit, urlunsplit

REFERENCE_VERSION = "reference-core-1"
LEGACY_KEYS = frozenset({"classifier_version", "verdict_level", "actionable_verdict",
                         "os_security_status", "role_fitness"})


def _bool(value: object, name: str) -> None:
    if type(value) is not bool:
        raise TypeError(name + " must be bool")


def _finite(value: object, name: str, *, nonnegative: bool = False) -> None:
    if type(value) not in (int, float):
        raise TypeError(name + " must be a number, not bool")
    try:
        valid = math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid or (nonnegative and value < 0):
        raise ValueError(name + " must be finite" + (" and nonnegative" if nonnegative else ""))


def _enum(value: object, cls: type[Enum], name: str) -> None:
    if type(value) is not cls:
        raise TypeError(name + " must be " + cls.__name__)


class SecurityState(IntEnum):
    NO_VIOLATION_OBSERVED = 0
    SUSPECT = 1
    VIOLATED = 2


class SecurityLatch:
    """Monotone per-run join; no reset. Construct a new latch for a new run.

    NO_VIOLATION_OBSERVED does NOT mean secure or verified coverage.
    Confirmation and attribution are outside this class.
    """
    def __init__(self) -> None:
        self._state = SecurityState.NO_VIOLATION_OBSERVED
        self._lock = threading.Lock()

    def observe(self, state: SecurityState) -> SecurityState:
        _enum(state, SecurityState, "state")
        with self._lock:
            self._state = max(self._state, state)
            return self._state

    def record_finding(self, *, confirmed: bool, opt_in: bool = False) -> SecurityState:
        _bool(confirmed, "confirmed")
        _bool(opt_in, "opt_in")
        # Opt-in affects neither visibility nor the safety-stop priority.
        return self.observe(SecurityState.VIOLATED if confirmed else SecurityState.SUSPECT)

    @property
    def state(self) -> SecurityState:
        with self._lock:
            return self._state

    @property
    def safety_stop(self) -> bool:
        return self.state is SecurityState.VIOLATED


class Tier0Requirement(Enum):
    """Baseline IDs supplied by reviewer; actual checks remain unimplemented."""
    TRANSPORT_ROUTING = "transport_routing"
    ANSI_CONTROL_HYGIENE = "ansi_control_hygiene"
    TOOL_CALL_HIJACK = "tool_call_hijack"
    CANARY_ISOLATION = "canary_isolation"


@dataclass(frozen=True)
class Tier0Coverage:
    verified: frozenset[Tier0Requirement] = frozenset()

    def __post_init__(self) -> None:
        if type(self.verified) is not frozenset:
            raise TypeError("verified must be frozenset")
        for item in self.verified:
            _enum(item, Tier0Requirement, "coverage item")

    @property
    def complete(self) -> bool:
        return self.verified == frozenset(Tier0Requirement)


class Assessment(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MISSING = "MISSING"


class JsonClass(Enum):
    STRICT = "STRICT"
    NONSTRICT = "NONSTRICT"
    INVALID = "INVALID"
    MISSING = "MISSING"


@dataclass(frozen=True)
class Evidence:
    security: SecurityState = SecurityState.NO_VIOLATION_OBSERVED
    coverage: Tier0Coverage = Tier0Coverage()
    role: Assessment = Assessment.MISSING
    schema: Assessment = Assessment.MISSING
    capability: Assessment = Assessment.MISSING
    logic: Assessment = Assessment.MISSING
    json_class: JsonClass = JsonClass.MISSING
    latency_s: float | None = None
    pass_slow: bool = False
    required_evidence_complete: bool = False

    def __post_init__(self) -> None:
        _enum(self.security, SecurityState, "security")
        if type(self.coverage) is not Tier0Coverage:
            raise TypeError("coverage must be Tier0Coverage")
        for name in ("role", "schema", "capability", "logic"):
            _enum(getattr(self, name), Assessment, name)
        _enum(self.json_class, JsonClass, "json_class")
        if self.latency_s is not None:
            _finite(self.latency_s, "latency_s", nonnegative=True)
        _bool(self.pass_slow, "pass_slow")
        _bool(self.required_evidence_complete, "required_evidence_complete")


class DecisionReason(Enum):
    CONFIRMED_VIOLATION = "CONFIRMED_VIOLATION"
    SUSPECT = "SUSPECT"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    FAILED_QUALITY = "FAILED_QUALITY"
    SLOW_CEILING = "SLOW_CEILING"
    VERIFIED_FAST = "VERIFIED_FAST"


@dataclass(frozen=True)
class Decision:
    """Derived only; finalizer validates again before making a decision."""
    level: int
    reason: DecisionReason
    memory_allowed: bool
    safety_stop: bool

    def __post_init__(self) -> None:
        if type(self.level) is not int or self.level not in range(1, 6):
            raise ValueError("invalid level")
        _enum(self.reason, DecisionReason, "reason")
        _bool(self.memory_allowed, "memory_allowed")
        _bool(self.safety_stop, "safety_stop")
        expected = {
            DecisionReason.CONFIRMED_VIOLATION: 1,
            DecisionReason.SUSPECT: 2,
            DecisionReason.MISSING_EVIDENCE: 2,
            DecisionReason.FAILED_QUALITY: 3,
            DecisionReason.SLOW_CEILING: 4,
            DecisionReason.VERIFIED_FAST: 5,
        }
        if (self.level != expected[self.reason] or self.memory_allowed != (self.level >= 4)
                or self.safety_stop != (self.level == 1)):
            raise ValueError("inconsistent decision")


def finalize(evidence: Evidence, *, latch_state: SecurityState = SecurityState.NO_VIOLATION_OBSERVED) -> Decision:
    """Deterministic priority table. Snapshot the latch at the actual caller gate.

    Schema evidence is required only for STRICT JSON; after a known syntax
    failure, schema MISSING does not mask that failure. Role, capability, logic,
    latency, Tier0 and other required evidence remain unconditional dependencies.
    This pure function cannot prevent a later finding or enforce a real sink.
    """
    if type(evidence) is not Evidence:
        raise TypeError("evidence must be Evidence")
    evidence.__post_init__()
    _enum(latch_state, SecurityState, "latch_state")
    state = max(evidence.security, latch_state)
    if state is SecurityState.VIOLATED:
        return Decision(1, DecisionReason.CONFIRMED_VIOLATION, False, True)
    if state is SecurityState.SUSPECT:
        return Decision(2, DecisionReason.SUSPECT, False, False)
    if (not evidence.coverage.complete or not evidence.required_evidence_complete
            or evidence.latency_s is None or evidence.json_class is JsonClass.MISSING
            or any(getattr(evidence, name) is Assessment.MISSING
                   for name in ("role", "capability", "logic"))
            or (evidence.json_class is JsonClass.STRICT and evidence.schema is Assessment.MISSING)):
        return Decision(2, DecisionReason.MISSING_EVIDENCE, False, False)
    if (evidence.json_class is not JsonClass.STRICT or evidence.latency_s > 10
            or any(getattr(evidence, name) is Assessment.FAIL
                   for name in ("role", "schema", "capability", "logic"))):
        return Decision(3, DecisionReason.FAILED_QUALITY, False, False)
    if evidence.latency_s > 3 or evidence.pass_slow:
        return Decision(4, DecisionReason.SLOW_CEILING, True, False)
    return Decision(5, DecisionReason.VERIFIED_FAST, True, False)


_ACTIONS = {1: "STOP", 2: "UNVERIFIED", 3: "NO_MEMORY", 4: "PASS_SLOW", 5: "PASS"}


def legacy_record(evidence: Evidence, *, latch_state: SecurityState = SecurityState.NO_VIOLATION_OBSERVED) -> dict:
    """Exactly five retained names; values/semantics migration NOTVERIFIED."""
    decision = finalize(evidence, latch_state=latch_state)
    return {
        "classifier_version": REFERENCE_VERSION,
        "verdict_level": decision.level,
        "actionable_verdict": _ACTIONS[decision.level],
        "os_security_status": max(evidence.security, latch_state).name,
        "role_fitness": evidence.role.value,
    }


class StrictJSONError(ValueError):
    """Generic failure, deliberately excludes raw untrusted text."""


@dataclass(frozen=True)
class JSONLimits:
    max_bytes: int = 65536
    max_depth: int = 32
    max_nodes: int = 4096

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_depth", "max_nodes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(name + " must be a positive integer")
        if self.max_depth > 128:
            raise ValueError("max_depth hard ceiling is 128")


def _lexical_budget(text: str, limits: JSONLimits) -> None:
    """Before json.loads: quote/escape-aware depth and token-node bound.

    Count containers and scalar/string tokens (including object keys).
    Malformed input is still rejected by the JSON parser; this is not salvage.
    """
    depth = nodes = i = 0
    while i < len(text):
        char = text[i]
        if char in " \t\r\n,:]}":
            if char in "]}":
                depth -= 1
                if depth < 0:
                    raise StrictJSONError("unbalanced container")
            i += 1
            continue
        nodes += 1
        if nodes > limits.max_nodes:
            raise StrictJSONError("node budget exceeded")
        if char in "[{":
            depth += 1
            if depth > limits.max_depth:
                raise StrictJSONError("depth budget exceeded")
            i += 1
        elif char == '"':
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise StrictJSONError("unterminated string")
        else:
            # A primitive token. JSON's grammar, not this budget pass, validates it.
            i += 1
            while i < len(text) and text[i] not in ' \t\r\n,:{}[]"':
                i += 1
    if depth != 0:
        raise StrictJSONError("unbalanced container")


def strict_json_loads(raw: str | bytes, limits: JSONLimits = JSONLimits()) -> object:
    """One complete RFC-whitespace JSON value; UTF-8, no BOM or salvage.

    Pre-parse bytes/depth/token caps; duplicate keys, constants, overflow floats,
    nonfinite values, and unpaired Unicode surrogates are rejected.
    """
    if type(limits) is not JSONLimits:
        raise TypeError("limits must be JSONLimits")
    limits.__post_init__()
    if type(raw) not in (str, bytes):
        raise TypeError("raw must be str or bytes")
    try:
        if len(raw) > limits.max_bytes:
            raise StrictJSONError("byte budget exceeded")
        if type(raw) is bytes:
            text = raw.decode("utf-8", errors="strict")
        else:
            text = raw
        if len(text.encode("utf-8", errors="strict")) > limits.max_bytes:
            raise StrictJSONError("byte budget exceeded")
        _lexical_budget(text, limits)

        def pairs(items: list) -> dict:
            result = {}
            for key, value in items:
                if key in result:
                    raise StrictJSONError("duplicate key")
                result[key] = value
            return result

        def constant(_: str) -> object:
            raise StrictJSONError("non-JSON constant")

        def number(token: str) -> float:
            value = float(token)
            if not math.isfinite(value):
                raise StrictJSONError("nonfinite number")
            return value

        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                           parse_float=number)
        stack = [value]
        while stack:
            item = stack.pop()
            if type(item) is str:
                item.encode("utf-8", errors="strict")
            elif type(item) is dict:
                stack.extend(item.keys())
                stack.extend(item.values())
            elif type(item) is list:
                stack.extend(item)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        if isinstance(exc, StrictJSONError):
            raise
        raise StrictJSONError("invalid strict JSON") from None


@dataclass(frozen=True)
class JSONEvidence:
    classification: JsonClass
    # No parsed value or recovered prose: classification is NOT memory authority.
    def __post_init__(self) -> None:
        _enum(self.classification, JsonClass, "classification")


def classify_json(raw: str | bytes, *, limits: JSONLimits = JSONLimits(),
                  known_nonstrict: bool = False) -> JSONEvidence:
    """No tolerant parser. NONSTRICT only records caller-supplied evidence."""
    _bool(known_nonstrict, "known_nonstrict")
    try:
        strict_json_loads(raw, limits)
    except StrictJSONError:
        return JSONEvidence(JsonClass.NONSTRICT if known_nonstrict else JsonClass.INVALID)
    return JSONEvidence(JsonClass.STRICT)


def validate_fixture_schema(value: object) -> bool:
    """ILLUSTRATIVE ONLY, NOT the product schema: {ok: bool, score: finite number}.

    No other keys. A bool is never accepted as a number.
    """
    if type(value) is not dict or set(value) != {"ok", "score"}:
        return False
    if type(value["ok"]) is not bool:
        return False
    try:
        _finite(value["score"], "score")
    except (TypeError, ValueError):
        return False
    return True


def normalize_endpoint(endpoint: str) -> str:
    """HTTPS authority normalization only; path/query case and escapes preserved.

    No DNS resolution, SSRF check, TLS operation, or transport authorization.
    """
    if type(endpoint) is not str or not endpoint or len(endpoint) > 8192:
        raise ValueError("invalid endpoint")
    if any(c.isspace() or ord(c) <= 32 or 127 <= ord(c) <= 159 for c in endpoint) or "\\" in endpoint:
        raise ValueError("ambiguous endpoint")
    try:
        parts = urlsplit(endpoint)
        if parts.scheme.lower() != "https" or not parts.netloc or "#" in endpoint:
            raise ValueError("HTTPS endpoint without fragment required")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ValueError("userinfo forbidden")
        host = parts.hostname
        port = parts.port
        if not host or "%" in host or parts.netloc.endswith(":"):
            raise ValueError("invalid host or port")
        if ":" in host:
            host = "[" + ipaddress.IPv6Address(host).compressed.lower() + "]"
        else:
            host = host.encode("idna").decode("ascii").lower()
            if host.endswith("."):
                host = host[:-1]
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                     for label in host.split(".")):
                raise ValueError("invalid host")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid port")
        authority = host if port in (None, 443) else host + ":" + str(port)
        return urlunsplit(("https", authority, parts.path, parts.query, ""))
    except (UnicodeError, ValueError):
        raise ValueError("invalid endpoint") from None


def _identity_text(value: object, name: str) -> None:
    if type(value) is not str or not value or len(value) > 8192:
        raise ValueError("invalid " + name)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("invalid " + name) from None


def cache_identity(*, endpoint: str, model: str, api_key: str, hmac_key: bytes,
                   probe_version: str, policy_version: str, schema_version: str,
                   config_digest: str, classifier_version: str = REFERENCE_VERSION) -> str:
    """Domain-separated HMAC of a canonical JSON tuple, no delimiter ambiguity.

    All four version/config fields are mandatory, exact, nonempty strings.
    config_digest is an opaque caller-computed digest, not computed/verified here.
    Returns a digest only. Secret provisioning/rotation/storage are NOT implemented.
    """
    if type(hmac_key) is not bytes or len(hmac_key) < 32:
        raise ValueError("hmac_key must contain at least 32 bytes")
    for name, value in (("model", model), ("api_key", api_key),
                        ("classifier_version", classifier_version),
                        ("probe_version", probe_version), ("policy_version", policy_version),
                        ("schema_version", schema_version), ("config_digest", config_digest)):
        _identity_text(value, name)
    message = json.dumps(["reference-cache-identity-v2", classifier_version,
                          probe_version, policy_version, schema_version, config_digest,
                          normalize_endpoint(endpoint), model, api_key],
                         ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hmac.new(hmac_key, message, hashlib.sha256).hexdigest()


def project_cache_record(record: Mapping) -> dict:
    """Typed positive allowlist; rejects unknown fields instead of silently dropping.

    Not a writer, cache reader, authenticity check, lifecycle, or memory gate.
    Only closed enum strings may be persisted by a caller using this projection.
    """
    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    data = dict(record)
    if set(data) != LEGACY_KEYS | {"epoch_ts"}:
        raise ValueError("unknown or missing cache fields")
    if type(data["classifier_version"]) is not str or data["classifier_version"] != REFERENCE_VERSION:
        raise ValueError("unsupported classifier version")
    level = data["verdict_level"]
    if type(level) is not int or level not in _ACTIONS:
        raise ValueError("invalid level")
    for key, allowed in (("actionable_verdict", set(_ACTIONS.values())),
                         ("os_security_status", set(SecurityState.__members__)),
                         ("role_fitness", {x.value for x in Assessment})):
        if type(data[key]) is not str or data[key] not in allowed:
            raise ValueError("invalid enum field")
    if data["actionable_verdict"] != _ACTIONS[level]:
        raise ValueError("inconsistent action")
    state = data["os_security_status"]
    role = data["role_fitness"]
    if ((state == "VIOLATED") != (level == 1)
            or (state == "SUSPECT" and level != 2)
            or (level >= 3 and role == "MISSING")
            or (level >= 4 and role != "PASS")):
        raise ValueError("inconsistent cache record")
    _finite(data["epoch_ts"], "epoch_ts", nonnegative=True)
    return data


def is_fresh(*, epoch_ts: float, now: float, ttl_s: float) -> bool:
    """Half-open interval: 0 <= age < ttl; invalid values raise, never coerce."""
    for name, value in (("epoch_ts", epoch_ts), ("now", now), ("ttl_s", ttl_s)):
        _finite(value, name, nonnegative=True)
    age = now - epoch_ts
    return math.isfinite(age) and 0 <= age < ttl_s
