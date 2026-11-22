#!/usr/bin/env python3
"""
API Sentinel - authorization (BOLA) regression testing for authorized environments.

Authorized testing only. This tool compares API behavior across controlled
requests and produces evidence-oriented findings. A finding is a lead, not
proof of a vulnerability.
"""

from __future__ import annotations
import argparse, contextlib, json, math, os, secrets, statistics, sys, time
import http.client, re, traceback
import urllib.error, urllib.request
from dataclasses import dataclass, asdict, field, replace
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit


__version__ = "0.10.0"
OWNER_FIELDS_DEFAULT = ["user_id", "owner_id", "account_id", "customer_id", "created_by", "author_id", "tenant_id"]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: json_shape(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return ["list", json_shape(value[0])] if value else ["list", "empty"]
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


@dataclass
class ResponseFP:
    status: int
    elapsed_ms: float
    size: int
    content_type: str
    entropy: float
    headers: list[str]
    shape: Any
    preview: str
    body: str = ""


@dataclass
class Finding:
    check: str
    severity: str
    confidence: str
    score: float
    evidence: list[str]
    recommendation: str
    endpoint: str
    method: str
    status: str = "needs_manual_confirmation"
    details: dict[str, Any] | None = None


# --- Exit codes and errors ----------------------------------------------------
#
#   0  clean: nothing confirmed, nothing undetermined, nothing incomplete
#   1  confirmed: a finding at or above --fail-on (default: high)
#   2  configuration problem, or a refused operation (for example a write without --allow-destructive)
#   3  incomplete: setup or an owner's baseline failed, so checks could not run
#   4  transport failure: the target could not be reached, or a connection failed
#   5  internal error (a bug in this tool)
#   6  undetermined: nothing confirmed or incomplete, but some results need human review.
#      The tool declined to decide rather than guess.

EXIT_OK, EXIT_POLICY, EXIT_CONFIG, EXIT_INCOMPLETE = 0, 1, 2, 3
EXIT_TRANSPORT, EXIT_INTERNAL, EXIT_UNDETERMINED = 4, 5, 6


class ScanError(Exception):
    exit_code = EXIT_INTERNAL


class ConfigError(ScanError):
    """Invalid input or configuration. Nothing is sent to the target for this reason."""
    exit_code = EXIT_CONFIG


class DestructiveOperationRefused(ConfigError):
    """A write-capable request was asked for without --allow-destructive. Raised before anything is sent."""


class TransportError(ScanError):
    """The target could not be reached, or a connection failed while a request was in flight."""
    exit_code = EXIT_TRANSPORT


# --- Scope: where requests may go, and where a redirect may lead -----------------------------------------------
#
# Every HTTP request goes through request(), which checks the URL before anything is sent: only http and https are
# used, and with --allow-host only the listed host names are used. A redirect is followed only within the origin
# (scheme, host and port) of the request that was sent, because urllib would otherwise copy the Authorization header
# to whatever host a redirect names. Values read from the environment are redacted from everything the tool prints
# or writes.

_ALLOWED_HOSTS: frozenset[str] | None = None  # from --allow-host, for one cli() run; None means no allowlist
_SECRETS: dict[str, str] = {}  # value read from the environment -> the variable it came from
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    return scheme, parts.hostname, port if port is not None else _DEFAULT_PORTS[scheme]


def same_origin(first: str, second: str) -> bool:
    origin = _origin(first)
    return origin is not None and origin == _origin(second)


def _check_scheme_and_host(url: str) -> None:
    """Refuse a URL before anything is sent: only http and https, and only --allow-host names when it is given."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        raise ConfigError("invalid URL: it cannot be parsed") from None
    if parts.scheme.lower() not in _DEFAULT_PORTS:
        raise ConfigError(f"unsupported URL scheme {parts.scheme!r}: only http:// and https:// URLs are used")
    if not host:
        raise ConfigError("invalid URL: it has no host name")
    if _ALLOWED_HOSTS is not None and host not in _ALLOWED_HOSTS:
        raise ConfigError(f"host {host!r} is not in --allow-host. Nothing was sent to it.")


def _host_name(raw: str) -> str:
    """The host name in one --allow-host value. A scheme, port, path, credentials, a space or an unbracketed IPv6
    address are refused, because the match is on the host name alone."""
    text = raw.strip()
    try:
        parts = urlsplit("//" + text)
        has_port = parts.port is not None
    except ValueError:
        parts, has_port = None, True
    if (parts is None or not parts.hostname or has_port or parts.path or parts.query or parts.fragment
            or parts.username or parts.password or any(ch.isspace() for ch in text)
            or (":" in text and not text.startswith("["))):
        raise ConfigError(f"--allow-host {raw!r}: give a host name only, for example 127.0.0.1 or api.internal "
                          "(no scheme, port, path or credentials; an IPv6 address goes in brackets)")
    return parts.hostname.lower()


def _allowed_hosts(values: list[str] | None) -> frozenset[str] | None:
    """The --allow-host values as a set of host names, or None when no allowlist was given."""
    if not values:
        return None
    return frozenset(_host_name(value) for value in values)


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to the origin of the request that was sent. Any other redirect is not followed: the 3xx
    response is returned as the response, and nothing is sent to the location it names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not same_origin(req.full_url, newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameOriginRedirects)


def _masker() -> re.Pattern[str] | None:
    if not _SECRETS:
        return None
    return re.compile("|".join(re.escape(value) for value in sorted(_SECRETS, key=len, reverse=True)))


def _mask(text: str, pattern: re.Pattern[str]) -> str:
    return pattern.sub(lambda match: f"[redacted:{_SECRETS[match.group(0)]}]", text)


def redact_text(text: str) -> str:
    """Every value read from the environment is replaced with [redacted:NAME]."""
    pattern = _masker()
    return text if pattern is None else _mask(text, pattern)


def redact(value: Any) -> Any:
    """A copy of a report-shaped value (dict, list, tuple or str) with every value read from the environment replaced.
    The report is redacted before it is serialized, so a value that JSON or HTML would escape is still replaced."""
    pattern = _masker()
    if pattern is None:
        return value

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            return _mask(node, pattern)
        if isinstance(node, dict):
            return {walk(key): walk(item) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, tuple):
            return tuple(walk(item) for item in node)
        return node

    return walk(value)


class _RedactingStream:
    """Passes everything written through redact_text. cli() puts it in front of stdout and stderr for one run, so no
    console line shows an environment value, whichever message it comes from."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(redact_text(text))

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def request(method: str, url: str, headers: dict[str, str] | None = None,
            data: bytes | None = None, timeout: float = 15) -> ResponseFP:
    headers = headers or {}
    method = method.upper()
    _check_scheme_and_host(url)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            body = r.read()
            status = r.status
            response_headers = [k.lower() for k in r.headers.keys()]
            content_type = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{method} {url}: connection failed while reading the error response: {exc}") from None
        status = e.code
        response_headers = [k.lower() for k in e.headers.keys()]
        content_type = e.headers.get("Content-Type", "")
    except ValueError as exc:  # e.g. "unknown url type": the URL itself is wrong
        raise ConfigError(f"invalid URL {url!r}: {exc}") from None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise TransportError(f"{method} {url} failed: {exc}") from None
    elapsed = (time.perf_counter() - started) * 1000
    text = body.decode("utf-8", errors="replace")
    parsed = None
    if "json" in content_type.lower():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return ResponseFP(
        status=status,
        elapsed_ms=elapsed,
        size=len(body),
        content_type=content_type,
        entropy=entropy(body),
        headers=response_headers,
        shape=json_shape(parsed) if parsed is not None else None,
        preview=text[:240],
        body=text,
    )


def summarize(samples: list[ResponseFP]) -> dict[str, Any]:
    times = [x.elapsed_ms for x in samples]
    sizes = [x.size for x in samples]
    ents = [x.entropy for x in samples]
    return {
        "samples": len(samples),
        "time_ms": {"mean": statistics.mean(times), "stdev": statistics.stdev(times) if len(times) > 1 else 0},
        "size": {"mean": statistics.mean(sizes), "stdev": statistics.stdev(sizes) if len(sizes) > 1 else 0},
        "entropy": {"mean": statistics.mean(ents), "stdev": statistics.stdev(ents) if len(ents) > 1 else 0},
        "statuses": sorted(set(x.status for x in samples)),
        "headers": sorted(set(h for x in samples for h in x.headers)),
        "shapes": [x.shape for x in samples],
    }


def z(value: float, mean: float, stdev: float) -> float:
    return abs(value - mean) / stdev if stdev > 1e-9 else 0.0


def anomaly_score(base: dict[str, Any], fp: ResponseFP) -> tuple[float, list[str]]:
    score = 0.0
    evidence = []
    tz = z(fp.elapsed_ms, base["time_ms"]["mean"], base["time_ms"]["stdev"])
    sz = z(fp.size, base["size"]["mean"], base["size"]["stdev"])
    ez = z(fp.entropy, base["entropy"]["mean"], base["entropy"]["stdev"])
    if tz >= 3:
        score += 25; evidence.append(f"latency is {tz:.1f}σ from baseline")
    if sz >= 3 or (base["size"]["mean"] and abs(fp.size-base["size"]["mean"])/base["size"]["mean"] >= .75):
        score += 25; evidence.append(f"response size changed sharply ({fp.size} bytes)")
    if ez >= 3:
        score += 15; evidence.append(f"body entropy is {ez:.1f}σ from baseline")
    if fp.status not in base["statuses"]:
        score += 20; evidence.append(f"unexpected HTTP status {fp.status}")
    extra = sorted(set(fp.headers) - set(base["headers"]))
    missing = sorted(set(base["headers"]) - set(fp.headers))
    if extra:
        score += 10; evidence.append("new response headers: " + ", ".join(extra[:8]))
    if missing:
        score += 5; evidence.append("missing common headers: " + ", ".join(missing[:8]))
    if fp.shape is not None and base["shapes"] and fp.shape not in base["shapes"]:
        score += 20; evidence.append("JSON response shape differs from baseline")
    return min(score, 100), evidence


def load_openapi(path: str) -> dict[str, Any]:
    # JSON is dependency-free. YAML can be added later without changing the
    # scanning engine.
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("openapi") or doc.get("swagger"):
        return doc
    raise ValueError("Input is not a valid OpenAPI/Swagger JSON document")


def discover_paths(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for path, item in doc.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            op = operation if isinstance(operation, dict) else {}
            out.append({
                "path": path,
                "method": method.upper(),
                "operation_id": op.get("operationId", ""),
                "summary": op.get("summary", ""),
            })
    return out


@dataclass
class Identity:
    name: str
    headers: dict[str, str]
    owns: list[str]
    # Values for {name} placeholders in the URL template, e.g. {"user_id": "42"} for /users/{user_id}/orders/{id}.
    params: dict[str, str] = field(default_factory=dict)
    # Optional declared ownership values, e.g. {"user_id": 42}. A record that contradicts them is undetermined.
    owner_values: dict[str, Any] = field(default_factory=dict)


_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: str, where: str) -> str:
    """Replace each ${NAME} with the environment's value. An unset or empty variable is a configuration error that
    names the variable and never prints a value."""

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        from_env = os.environ.get(name, "")
        if not from_env:
            raise ConfigError(f"{where} refers to ${{{name}}}, which is not set (or is empty) in the environment")
        _SECRETS.setdefault(from_env, name)
        return from_env

    return _ENV_REF.sub(substitute, value)


def load_identities(path: str) -> list[Identity]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"identities file {path!r} is not readable JSON: {e}") from None
    items = doc.get("identities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ConfigError("identities file must contain an 'identities' list")
    out: list[Identity] = []
    for item in items:
        if not isinstance(item, dict) or "name" not in item or not isinstance(item.get("headers", {}), dict):
            raise ConfigError(f"each identity needs a 'name' and a 'headers' object: {item!r}")
        name = str(item["name"])
        if any(existing.name == name for existing in out):
            raise ConfigError(f"duplicate identity name {name!r}")
        params = item.get("params", {})
        owner_values = item.get("owner_values", {})
        if not isinstance(params, dict) or not isinstance(owner_values, dict):
            raise ConfigError(f"identity {name!r}: 'params' and 'owner_values' must be JSON objects")
        out.append(Identity(
            name=name,
            headers={str(k): _expand_env(str(v), f"identity {name!r} header {k!r}")
                     for k, v in item.get("headers", {}).items()},
            owns=[str(x) for x in item.get("owns", [])],
            params={str(k): _expand_env(str(v), f"identity {name!r} param {k!r}") for k, v in params.items()},
            owner_values={k: (_expand_env(v, f"identity {name!r} owner_values {k!r}") if isinstance(v, str) else v)
                          for k, v in owner_values.items()},
        ))
    if len(out) < 2:
        raise ConfigError("identities file needs at least two identities to run cross-account checks")
    return out


# --- POST sub-actions (0.10.0) ---------------------------------------------------------------------------------
#
# A POST sub-action is an operation on the resource itself, such as /orders/{id}/cancel, declared by the operator in an
# actions file. The stateful flow sends each declared action once, as a non-owner, on a resource that the first identity
# created. Its effect is judged by the owner's own record: the values in 'expect' must show there after the request, and
# must not have shown there before it. The status code of the request is never the evidence.

_ACTION_KEYS = ("name", "url", "body", "expect")
_ACTION_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")


@dataclass
class PostAction:
    name: str
    url: str                # a template with {id}; other {names} are filled from identity params, as for --url
    body: dict[str, Any]    # the JSON object sent with the POST
    expect: dict[str, Any]  # the owner's record shows these values once the action has taken effect


def load_post_actions(path: str) -> list[PostAction]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"actions file {path!r} is not readable JSON: {e}") from None
    items = doc.get("actions") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not items:
        raise ConfigError("actions file must contain a non-empty 'actions' list")
    out: list[PostAction] = []
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError(f"each action must be a JSON object: {item!r}")
        name = item.get("name")
        if not isinstance(name, str) or not _ACTION_NAME.fullmatch(name):
            raise ConfigError(f"action name {name!r} must start with a letter and use only letters, digits, '_' or '-'")
        if name.upper() in (*_STATEFUL_VERBS, "POST"):
            raise ConfigError(f"action name {name!r} is an HTTP method: choose another name")
        if any(a.name == name for a in out):
            raise ConfigError(f"duplicate action name {name!r}")
        unknown = sorted(set(item) - set(_ACTION_KEYS))
        if unknown:
            raise ConfigError(f"action {name!r} has unknown key(s) {unknown}: allowed are name, url, body and expect")
        url = item.get("url")
        if not isinstance(url, str) or "{id}" not in url:
            raise ConfigError(f"action {name!r} needs a 'url' that contains {{id}}, for example "
                              "https://localhost:8000/orders/{id}/cancel")
        _check_scheme_and_host(url)
        body = item.get("body", {})
        if not isinstance(body, dict):
            raise ConfigError(f"action {name!r}: 'body' must be a JSON object")
        expect = item.get("expect")
        if not isinstance(expect, dict) or not expect:
            raise ConfigError(f"action {name!r} needs an 'expect' object with the owner's record fields and values that "
                              'show the action took effect, for example {"status": "cancelled"}')
        if any(value is None for value in expect.values()):
            raise ConfigError(f"action {name!r}: 'expect' values must not be null: the record must show a concrete value")
        out.append(PostAction(name, url, body, expect))
    return out


# --- Resource graph ----------------------------------------------------
#
# Heuristic ownership inference from an OpenAPI document: who owns what,
# guessed from path nesting and response schema field names. This is a
# starting point for the checks below, not a verified data model.

_OWNERSHIP_FIELD_HINTS = set(OWNER_FIELDS_DEFAULT)


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("ses"):
        return word[:-2]
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _resource_name_from_path(path: str) -> str | None:
    segments = [s for s in path.split("/") if s]
    for seg in reversed(segments):
        if not (seg.startswith("{") and seg.endswith("}")):
            return _singular(seg).capitalize()
    return None


def _resolve_schema(doc: dict[str, Any], node: Any) -> dict[str, Any]:
    hops = 0
    while isinstance(node, dict) and "$ref" in node and hops < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return node
        cur: Any = doc
        for part in ref[2:].split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        node = cur
        hops += 1
    return node if isinstance(node, dict) else {}


def _response_schema(doc: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    responses = operation.get("responses", {}) if isinstance(operation, dict) else {}
    for code in ("200", "201", "default"):
        resp = responses.get(code)
        if not isinstance(resp, dict):
            continue
        content = resp.get("content", {})
        if not isinstance(content, dict):
            continue
        for media in content.values():
            if isinstance(media, dict) and media.get("schema"):
                return _resolve_schema(doc, media["schema"])
    return {}


def infer_resource_graph(doc: dict[str, Any]) -> dict[str, Any]:
    """Infer resource types and ownership relationships from an OpenAPI document.

    Reads path nesting (e.g. /users/{user_id}/orders) and response schema field
    names (e.g. user_id on an Order) to guess who owns what. Heuristic, not a
    verified data model -- sanity-check the graph against the real API before
    relying on it.
    """
    resources: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    for path, item in doc.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        segments = [s for s in path.split("/") if s]
        param_segments = [s[1:-1] for s in segments if s.startswith("{") and s.endswith("}")]
        name = _resource_name_from_path(path)
        if not name:
            continue
        res = resources.setdefault(name, {"paths": [], "id_params": set(), "owner_fields": set()})
        res["paths"].append(path)
        if param_segments:
            res["id_params"].add(param_segments[-1])

        if param_segments:
            first_param = "{" + param_segments[0] + "}"
            prior_segments = segments[:segments.index(first_param)]
            parent = _resource_name_from_path("/" + "/".join(prior_segments)) if prior_segments else None
            if parent and parent != name:
                edges.append({"from": parent, "to": name, "via": param_segments[0], "relation": "owns"})

        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            schema = _response_schema(doc, operation if isinstance(operation, dict) else {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            if not isinstance(props, dict):
                continue
            id_params_lower = {p.lower() for p in res["id_params"]}
            for prop in props:
                fl = prop.lower()
                if fl in _OWNERSHIP_FIELD_HINTS or (fl.endswith("_id") and fl not in id_params_lower):
                    res["owner_fields"].add(prop)

    for res in resources.values():
        res["paths"] = sorted(set(res["paths"]))
        res["id_params"] = sorted(res["id_params"])
        res["owner_fields"] = sorted(res["owner_fields"])

    return {"resources": resources, "relationships": edges}


def format_graph(graph: dict[str, Any]) -> str:
    lines = ["Resource graph (heuristic, derived from OpenAPI -- verify before relying on it):", ""]
    for name, info in sorted(graph["resources"].items()):
        owner_bit = f"  owner fields: {', '.join(info['owner_fields'])}" if info["owner_fields"] else ""
        id_bit = ", ".join(info["id_params"]) or "-"
        lines.append(f"  {name:12} paths={len(info['paths']):<3} id_params={id_bit}{owner_bit}")
    if graph["relationships"]:
        lines.append("")
        lines.append("Relationships:")
        for e in graph["relationships"]:
            lines.append(f"  {e['from']} --{e['relation']}--> {e['to']}  (via {e['via']})")
    return "\n".join(lines)


# --- Authorization engine -------------------------------------------------------
#
# Rules:
#  * A 2xx status is not evidence, and neither is a matching response shape.
#  * A leak needs identity evidence: the body must identify the requested resource (an id field equal to
#    the requested id) AND corroborate the owner's data (an ownership field equal to the owner's own record,
#    a declared owner value, or a body identical to the owner's own record).
#  * The status code is not a filter: a 403 whose body carries the owner's record is still a leak.
#  * Data that cannot be attributed, or whose owner is contradicted, is reported as undetermined
#    (status needs_input, check authorization-undetermined). It is never a critical finding.
#  * A write counts only when the owner's own read shows its effect, whatever status the write returned.

BOLA_CHECKS = {"authorization-boundary", "stateful-authorization-boundary"}
_RESOURCE_ID_KEYS = ("id", "orderId", "order_id", "resource_id", "uuid")
_active_id_keys: tuple[str, ...] = _RESOURCE_ID_KEYS


@contextlib.contextmanager
def resource_id_field(name: str | None):
    """For one run: the response field that carries the resource id (--id-field), instead of the default names.
    The setting is process-wide while the run lasts, and is restored afterwards."""
    global _active_id_keys
    previous = _active_id_keys
    _active_id_keys = (name,) if name else _RESOURCE_ID_KEYS
    try:
        yield
    finally:
        _active_id_keys = previous
_ENVELOPE_KEYS = ("data", "result", "item", "order", "resource")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_STATEFUL_VERBS = ("GET", "PATCH", "PUT", "DELETE")


def _safe_json(fp: ResponseFP) -> Any:
    if fp.body and "json" in fp.content_type.lower():
        try:
            return json.loads(fp.body)
        except json.JSONDecodeError:
            return None
    return None


def _ok(fp: ResponseFP) -> bool:
    return 200 <= fp.status < 300


def fill_url(template: str, identity: Identity, resource_id: str | None = None, keep_id: bool = False) -> str:
    """Fill {id} with the resource id (unless keep_id) and every other {name} from the identity's params."""
    url = template if resource_id is None else template.replace("{id}", quote(str(resource_id), safe=""))

    def substitute(match: re.Match) -> str:
        key = match.group(1)
        if key == "id" and keep_id:
            return match.group(0)
        if key not in identity.params:
            raise ConfigError(f"URL template {template!r} needs {{{key}}}, but identity {identity.name!r} "
                              f"has no params.{key} in the identities file")
        return quote(identity.params[key], safe="")

    return _PLACEHOLDER.sub(substitute, url)


def _with_id(template: str, resource_id: str | None) -> str:
    return template if resource_id is None else template.replace("{id}", quote(str(resource_id), safe=""))


def _url_variant_templates(template: str, owner: Identity, accessor: Identity) -> list[str]:
    """The owner's own URL (replay), plus the accessor's own parent segment when the template has parameters.

    Substituting the accessor's parent is what exposes servers that check the URL's user id but not the
    resource's owner (/users/{user_id}/orders/{id}).
    """
    out: list[str] = []
    for ident in (owner, accessor):
        candidate = fill_url(template, ident, None, keep_id=True)
        if candidate not in out:
            out.append(candidate)
    return out


def _unwrap(body: Any) -> Any:
    """Look through a single envelope such as {"data": {...}} when the top level carries no id of its own."""
    if isinstance(body, dict) and not any(k in body for k in _active_id_keys):
        for key in _ENVELOPE_KEYS:
            if isinstance(body.get(key), dict):
                return body[key]
    return body


def _identifies(body: Any, resource_id: str) -> bool:
    return isinstance(body, dict) and any(
        key in body and str(body[key]) == str(resource_id) for key in _active_id_keys)


def _informative(value: Any) -> bool:
    """Can this value identify an owner? Null, empty, zero and booleans cannot."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "null", "none", "unknown")
    return False


@dataclass
class Judgement:
    verdict: str                     # "leak" | "undetermined" | "none"
    severity: str = "info"
    confidence: str = "low"
    reasons: list[str] = field(default_factory=list)


def _judge_record(resource_id: str, owner: Identity, owner_body: Any, body: Any,
                  owner_fields: list[str], served: bool) -> Judgement:
    o, b = _unwrap(owner_body), _unwrap(body)
    if not (isinstance(o, dict) and isinstance(b, dict) and o):
        return Judgement("none")
    identifies = _identifies(b, resource_id)
    field_hits = [f for f in owner_fields if f in o and f in b and _informative(o[f]) and o[f] == b[f]]
    declared_hits = [f for f, v in owner.owner_values.items() if f in b and b[f] == v]
    conflicts = [f for f, v in owner.owner_values.items() if f in o and o[f] != v]
    empty = [f for f in owner_fields if f in o and not _informative(o[f])]
    identical = b == o
    corroborated = bool(field_hits or declared_hits or identical)

    reasons: list[str] = []
    if field_hits:
        reasons.append("ownership field " + ", ".join(f"{f}={o[f]!r}" for f in field_hits)
                       + " equals the owner's own record")
    if declared_hits:
        reasons.append("declared owner value matches on " + ", ".join(declared_hits))
    if identical:
        reasons.append("the body is identical to the owner's own record")

    if conflicts and (identifies or corroborated):
        return Judgement("undetermined", reasons=[
            "the owner's own record contradicts the declared owner: "
            + ", ".join(f"{f} is {o[f]!r} in the record but {owner.owner_values[f]!r} was declared"
                        for f in conflicts)])
    if identifies:
        if empty and identical and not owner.owner_values:
            return Judgement("undetermined", reasons=[
                "the owner's record has an empty ownership field (" + ", ".join(empty) + "), so ownership cannot "
                "be established, and an identical copy is not proof"])
        if not corroborated:
            return Judgement("none")
        if served and (field_hits or declared_hits):
            return Judgement("leak", "critical", "high", reasons)
        return Judgement("leak", "high", "medium", reasons)
    if field_hits and identical:
        return Judgement("leak", "high", "medium", [
            "the body has no id for the requested resource, but it is an identical copy of the owner's record"]
            + reasons)
    if corroborated:
        return Judgement("undetermined", reasons=[
            "owner data without an identifier for the requested resource, so the record returned cannot be "
            "attributed"] + reasons)
    return Judgement("none")


def _judge_list(owner_body: Any, body: Any) -> Judgement:
    """A list endpoint parameterised by the owner's id: the owner's own list returned unchanged to someone else."""
    if isinstance(owner_body, list) and owner_body and isinstance(body, list) and body == owner_body:
        return Judgement("leak", "high", "medium",
                         ["the response is the owner's own list, returned unchanged to another identity"])
    return Judgement("none")


def _judge_collection_item(resource_id: str, owner: Identity, owner_items: Any, body: Any,
                           owner_fields: list[str], served: bool) -> Judgement:
    """A collection URL (no {id}): the resource is one item in the list, identified by its id."""
    if not isinstance(owner_items, list) or not isinstance(body, list):
        return Judgement("none")
    owner_item = next((i for i in owner_items if _identifies(i, resource_id)), None)
    item = next((i for i in body if _identifies(i, resource_id)), None)
    if owner_item is None or item is None:
        return Judgement("none")  # the resource id is not in this response, so there is nothing to attribute
    return _judge_record(resource_id, owner, owner_item, item, owner_fields, served)


# --- Text bodies: HTML, XML and plain text ---------------------------------------------------------------------
#
# A text response has no fields to compare, so it is compared as text. The owner's own page must mention the requested
# resource id, or the tool cannot tell which resource the page is about. An accessor's page is a leak when it is an
# identical or near-identical copy of the owner's page and still mentions that id, even under an error status (a 403
# that carries the record). A similar page that is not a copy is undetermined when it was served with 2xx: the tool
# cannot tell whether it discloses the record. Similarity is the Jaccard index of the two word sets. It needs enough
# words to mean something, so a short owner page is compared for identity only. An accessor's response in another
# representation than the owner's cannot be compared: see _judge_unevaluated.

LEAK_SIMILARITY = 0.9      # an accessor's page at or above this word similarity is a copy of the owner's
REVIEW_SIMILARITY = 0.5    # from this similarity a 2xx page is undetermined
MIN_SIMILARITY_WORDS = 8   # the owner's page needs this many distinct words for a similarity verdict


def _body_kind(fp: ResponseFP) -> str:
    """'json', 'text' (text/*, XML, or any +xml type) or 'other' (binary, or no content type at all)."""
    ctype = fp.content_type.lower().split(";")[0].strip()
    if "json" in ctype:
        return "json"
    if ctype.startswith("text/") or ctype in ("application/xml", "application/xhtml+xml") or ctype.endswith("+xml"):
        return "text"
    return "other"


def _mentions(text: str, resource_id: str) -> bool:
    """The id as a whole token, so that 1001 does not match inside 10010."""
    return re.search(r"(?<!\w)" + re.escape(resource_id) + r"(?!\w)", text) is not None


def _words(text: str) -> set[str]:
    return set(re.findall(r"\w+", text.lower()))


def _similarity(a: str, b: str) -> float:
    """Jaccard index of the two word sets: 1.0 when they hold the same words, 0.0 when they share none."""
    wa, wb = _words(a), _words(b)
    return len(wa & wb) / len(wa | wb) if wa | wb else 0.0


def _owner_text_ok(fp: ResponseFP, resource_id: str) -> bool:
    return _ok(fp) and bool(fp.body.strip()) and _mentions(fp.body, resource_id)


def _judge_text(resource_id: str, owner_text: str, fp: ResponseFP) -> Judgement:
    text = fp.body
    if not _mentions(text, resource_id):
        return Judgement("none")
    if " ".join(text.split()) == " ".join(owner_text.split()):
        return Judgement("leak", "high", "medium",
                         [f"the body is identical to the owner's own page and still names resource_id={resource_id}"])
    if len(_words(owner_text)) < MIN_SIMILARITY_WORDS:
        return Judgement("none")
    similarity = _similarity(owner_text, text)
    if similarity >= LEAK_SIMILARITY:
        return Judgement("leak", "high", "medium", [
            f"the body is a near-identical copy of the owner's own page (word similarity {similarity:.0%})"])
    if similarity >= REVIEW_SIMILARITY and _ok(fp):
        return Judgement("undetermined", reasons=[
            f"the body resembles the owner's own page (word similarity {similarity:.0%}) but is not a copy, so the "
            "tool cannot tell whether it discloses the record"])
    return Judgement("none")


def _judge_unevaluated(resource_id: str, owner_kind: str, fp: ResponseFP) -> Judgement:
    """An accessor's response in another representation than the owner's, so it cannot be compared with the record.

    An error status is a refusal, and an empty body is nothing: neither is evidence. A 2xx body the tool cannot read
    (binary or untyped) is undetermined, because it may hold the owner's record in that format. A 2xx text or JSON body
    is undetermined only when it names the requested resource: a page that does not name it is not about it.
    """
    if not _ok(fp) or not fp.size:
        return Judgement("none")
    kind = _body_kind(fp)
    if kind == "other":
        return Judgement("undetermined", reasons=[
            f"the response is {fp.content_type or 'untyped'}, which the tool does not evaluate, so it cannot tell "
            "whether it holds the owner's record"])
    if not _mentions(fp.body, resource_id):
        return Judgement("none")
    if kind == owner_kind:
        return Judgement("undetermined", reasons=[
            f"the response is declared {kind} but does not parse, so the tool cannot read the record in it"])
    return Judgement("undetermined", reasons=[
        f"the response is {kind} and names resource_id={resource_id}, but the owner's own response is {owner_kind}, "
        "so the two cannot be compared"])


def _owner_baseline_ok(fp: ResponseFP, body: Any, resource_id: str, collection: bool) -> bool:
    if not _ok(fp) or body is None:
        return False
    if collection:
        return isinstance(body, list) and any(_identifies(i, resource_id) for i in body)
    if isinstance(body, list):
        return bool(body)
    return isinstance(body, dict)


def _incomplete(owner: Identity, resource_id: str, url: str, method: str, fp: ResponseFP,
                collection: bool) -> Finding:
    kind = _body_kind(fp)
    if not _ok(fp):
        why = f"the owner's own request returned HTTP {fp.status}"
    elif kind == "other":
        why = (f"the owner's response is {fp.content_type or 'untyped'}, which the tool does not evaluate "
               "(it reads JSON and text)")
    elif kind == "text" and collection:
        why = "a collection is evaluated only as JSON, and the owner's listing is text"
    elif kind == "text":
        why = f"the owner's text response does not contain resource_id={resource_id}"
    elif collection:
        why = f"the owner's list does not contain resource_id={resource_id}"
    else:
        why = "the owner's response carries no record that can be evaluated"
    return Finding(
        check="authorization-incomplete", severity="info", confidence="low", score=0.0,
        evidence=[f"owner '{owner.name}' could not establish its own resource_id={resource_id}: {why}. "
                  "No other identity was tested against it."],
        recommendation="Fix the identities file (headers, owns, params) so that the owner can read the "
                       "resource it claims, then re-run.",
        endpoint=url, method=method, status="skipped",
        details={"owner_identity": owner.name, "resource_id": resource_id, "http_status": fp.status,
                 "reason": why},
    )


def _judgement_findings(j: Judgement, owner: Identity, accessor: Identity, resource_id: str, fp: ResponseFP,
                        url: str, method: str, owner_status: int,
                        leak_check: str = "authorization-boundary") -> list[Finding]:
    details = {"class": "BOLA / Broken Object Level Authorization", "owner_identity": owner.name,
               "accessing_identity": accessor.name, "resource_id": resource_id,
               "http_status": fp.status, "response_bytes": fp.size}
    if j.verdict == "leak":
        critical = j.severity == "critical"
        what = "a successful response" if _ok(fp) else f"HTTP {fp.status}, and the body still carries the record"
        return [Finding(
            check=leak_check, severity=j.severity, confidence=j.confidence,
            score=90.0 if critical else 70.0,
            evidence=[f"'{accessor.name}' received the record for resource_id={resource_id} ({what}); "
                      f"owner '{owner.name}' reads it with HTTP {owner_status}",
                      f"expected: '{accessor.name}' must not receive '{owner.name}'s resource_id={resource_id}"]
                     + j.reasons,
            recommendation="Verify server-side that this endpoint checks the authenticated identity against the "
                           "resource owner before returning data, whatever the HTTP status.",
            endpoint=url, method=method, status="confirmed", details=details)]
    if j.verdict == "undetermined":
        return [Finding(
            check="authorization-undetermined", severity="info", confidence="low", score=0.0,
            evidence=[f"'{accessor.name}' received data for resource_id={resource_id} (HTTP {fp.status}); "
                      "the tool cannot decide whether this is an authorization violation"] + j.reasons,
            recommendation="Provide the missing ownership information (owner_values, or an ownership field in "
                           "the owner's record), or confirm the access is intended, then re-run.",
            endpoint=url, method=method, status="needs_input", details=details)]
    return []


def run_authorization_matrix(url_template: str, identities: list[Identity], method: str,
                             owner_fields: list[str], timeout: float,
                             log: list[dict[str, Any]] | None = None
                             ) -> tuple[list[Finding], list[dict[str, Any]]]:
    """For every resource an identity owns, request it as every other identity and judge what comes back.

    The matrix is read-only: it only ever sends GET. Write verbs are covered by run_stateful_flow, which creates
    its own resources and needs an explicit opt-in. Returns (findings, log), where log has one entry per request.
    Requests are appended to the list passed as log, so a caller keeps them even when the pass fails part way.
    """
    if method.upper() != "GET":
        raise ConfigError(f"the authorization matrix is read-only and only sends GET (got {method.upper()}). "
                          "Write verbs are tested by --stateful, which creates its own resources and needs "
                          "--allow-destructive.")
    collection = "{id}" not in url_template
    findings: list[Finding] = []
    log = [] if log is None else log
    for owner in identities:
        for resource_id in owner.owns:
            rid = None if collection else resource_id
            owner_url = fill_url(url_template, owner, rid)
            owner_fp = request("GET", owner_url, owner.headers, timeout=timeout)
            owner_body = _safe_json(owner_fp)
            log.append({"kind": "owner_baseline", "owner": owner.name, "resource_id": resource_id,
                        "url": owner_url, "status": owner_fp.status, "size": owner_fp.size})
            as_text = not collection and _body_kind(owner_fp) == "text"
            owner_ok = (_owner_text_ok(owner_fp, resource_id) if as_text
                        else _owner_baseline_ok(owner_fp, owner_body, resource_id, collection))
            if not owner_ok:
                findings.append(_incomplete(owner, resource_id, owner_url, "GET", owner_fp, collection))
                continue
            for accessor in identities:
                if accessor.name == owner.name:
                    continue
                for template in _url_variant_templates(url_template, owner, accessor):
                    url = _with_id(template, rid)
                    fp = request("GET", url, accessor.headers, timeout=timeout)
                    body = _safe_json(fp)
                    log.append({"kind": "accessor", "owner": owner.name, "accessed_by": accessor.name,
                                "resource_id": resource_id, "url": url, "status": fp.status, "size": fp.size})
                    owner_kind = "text" if as_text else "json"
                    if _body_kind(fp) != owner_kind or (owner_kind == "json" and body is None):
                        judgement = _judge_unevaluated(resource_id, owner_kind, fp)
                    elif as_text:
                        judgement = _judge_text(resource_id, owner_fp.body, fp)
                    elif collection:
                        judgement = _judge_collection_item(resource_id, owner, owner_body, body, owner_fields,
                                                           _ok(fp))
                    elif isinstance(owner_body, list) or isinstance(body, list):
                        judgement = _judge_list(owner_body, body)
                    else:
                        judgement = _judge_record(resource_id, owner, owner_body, body, owner_fields, _ok(fp))
                    findings.extend(_judgement_findings(judgement, owner, accessor, resource_id, fp, url,
                                                        "GET", owner_fp.status))
    return findings, log


# --- Second pass: a confirmed finding must reproduce ----------------------------------------------------------
#
# One response can differ from the next for reasons unrelated to authorization: a cache, a race, a rate limit that
# briefly opened. So every BOLA finding from the first matrix pass is confirmed only if a second, identical matrix
# pass reproduces it: same owner, accessing identity, resource and URL. A finding that does not reproduce becomes
# undetermined and says why. A leak seen only on the second pass is undetermined too, because it was seen once and
# not confirmed. The second pass runs only when the first pass has something to confirm, and it never runs for
# --stateful, which creates and deletes resources.

_RECHECK_OUTCOMES = ("reproduced", "not_reproduced", "not_rechecked", "second_pass_only")
_RECHECK_NOTES = {
    "not_reproduced": ("The second pass did not reproduce this leak: the same request returned a different result, "
                       "so one response is not enough to confirm it."),
    "not_rechecked": ("The second pass could not check this: the owner's own baseline failed on the second pass, "
                      "so the request was not repeated."),
    "second_pass_only": ("The leak appeared on the second pass only, so the first pass did not reproduce it and it is "
                         "not confirmed."),
}


def _pair_key(f: Finding) -> tuple[str, str, str, str]:
    d = f.details or {}
    return (str(d.get("owner_identity")), str(d.get("accessing_identity")), str(d.get("resource_id")), f.endpoint)


def _owner_resource(f: Finding) -> tuple[str, str]:
    d = f.details or {}
    return (str(d.get("owner_identity")), str(d.get("resource_id")))


def _is_pair(f: Finding) -> bool:
    """A judgement about one request (owner, accessing identity, resource, URL), not an owner-level result."""
    return "accessing_identity" in (f.details or {})


def _downgraded(f: Finding, outcome: str, note: str | None = None, prior: Finding | None = None) -> Finding:
    """The observation as undetermined, with its reason. A first-pass judgement it replaces stays as evidence."""
    evidence = [note or _RECHECK_NOTES[outcome], *f.evidence]
    if prior is not None:
        evidence += [f"first pass: {line}" for line in prior.evidence]
    return Finding(
        check="authorization-undetermined", severity="info", confidence="low", score=0.0,
        evidence=evidence,
        recommendation=("Re-run and compare the two responses. If the result changes between identical requests, look "
                        "for caching, race conditions or rate limiting. Only a result that reproduces is confirmed."),
        endpoint=f.endpoint, method=f.method, status="needs_input",
        details={**(f.details or {}), "recheck": outcome})


def apply_recheck(first: list[Finding], second: list[Finding],
                  interrupted: str | None = None) -> tuple[list[Finding], dict[str, Any]]:
    """Keep a first-pass BOLA finding only if the second pass reproduces it; other findings pass through.

    interrupted is the error that stopped the second pass. Nothing was reproduced then, so every candidate is reported
    as not rechecked, with the error as its reason."""
    second_leaks = {} if interrupted else {_pair_key(f): f for f in second if f.check in BOLA_CHECKS}
    second_blocked = set() if interrupted else {_owner_resource(f) for f in second
                                                if f.check == "authorization-incomplete"}
    interrupted_note = None
    if interrupted:
        interrupted_note = f"The second pass could not complete ({interrupted}), so this request was not repeated."
    counts = dict.fromkeys(_RECHECK_OUTCOMES, 0)
    out: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for f in first:
        if f.check not in BOLA_CHECKS and not _is_pair(f):
            out.append(f)
            continue
        key = _pair_key(f)
        seen.add(key)
        leak = second_leaks.get(key)
        if f.check not in BOLA_CHECKS:  # the first pass judged this request undetermined
            if leak is None:
                out.append(f)
            else:
                counts["second_pass_only"] += 1
                out.append(_downgraded(leak, "second_pass_only", prior=f))
            continue
        if leak is not None:
            counts["reproduced"] += 1
            f.details = {**(f.details or {}), "recheck": "reproduced"}
            out.append(f)
            continue
        outcome = "not_rechecked" if interrupted or _owner_resource(f) in second_blocked else "not_reproduced"
        counts[outcome] += 1
        out.append(_downgraded(f, outcome, note=interrupted_note))
    for key, leak in second_leaks.items():
        if key not in seen:
            counts["second_pass_only"] += 1
            out.append(_downgraded(leak, "second_pass_only"))
    candidates = counts["reproduced"] + counts["not_reproduced"] + counts["not_rechecked"]
    return out, {"enabled": True, "ran": True, "candidates": candidates, "interrupted": interrupted, **counts}


def run_matrix_with_recheck(url_template: str, identities: list[Identity], owner_fields: list[str], timeout: float,
                            trail: list[dict[str, Any]], *, scope: str, recheck: bool = True
                            ) -> tuple[list[Finding], dict[str, Any]]:
    """The read-only matrix, then the second pass if there is something to confirm. Every request of both passes goes
    to trail. The second pass is tagged kind 'recheck', so coverage counts its requests and not its checks."""
    first, log = run_authorization_matrix(url_template, identities, "GET", owner_fields, timeout)
    trail.extend(log)
    candidates = sum(1 for f in first if f.check in BOLA_CHECKS)
    if not recheck or candidates == 0:
        return first, {"scope": scope, "enabled": recheck, "ran": False, "candidates": 0, "interrupted": None,
                       **dict.fromkeys(_RECHECK_OUTCOMES, 0)}
    second_log: list[dict[str, Any]] = []
    second: list[Finding] = []
    interrupted = None
    try:
        second, _ = run_authorization_matrix(url_template, identities, "GET", owner_fields, timeout, log=second_log)
    except TransportError as exc:
        interrupted = str(exc)
    finally:
        trail.extend({**entry, "kind": "recheck", "of": entry["kind"]} for entry in second_log)
    findings, summary = apply_recheck(first, second, interrupted)
    return findings, {"scope": scope, **summary}


def _stateful_recheck_run(findings: list[Finding], enabled: bool) -> dict[str, Any]:
    """The stateful flow's second-pass summary, counted from the findings that went through it (details['recheck']).
    Its second pass only re-reads what the first pass saw, so it never reports a result seen only on the second pass."""
    counts = {outcome: sum((f.details or {}).get("recheck") == outcome for f in findings)
              for outcome in ("reproduced", "not_reproduced", "not_rechecked")}
    candidates = sum(counts.values())
    return {"scope": "stateful", "enabled": enabled, "ran": enabled and candidates > 0, "candidates": candidates,
            "interrupted": None, "second_pass_only": 0, **counts}


def recheck_report(enabled: bool, runs: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {key: sum(run[key] for run in runs) for key in ("candidates", *_RECHECK_OUTCOMES)}
    return {"enabled": enabled, "totals": totals, "runs": runs}


def _recheck_enabled(args: argparse.Namespace) -> bool:
    if args.no_recheck:
        print("[!] --no-recheck: each finding is confirmed on one response, without a second pass", file=sys.stderr)
        return False
    return True


def _print_recheck(run: dict[str, Any]) -> None:
    if not run["ran"]:
        return
    if run["interrupted"]:
        print(f"    recheck: the second pass stopped ({run['interrupted']}); {run['not_rechecked']} result(s) "
              "could not be rechecked")
        return
    print(f"    recheck: {run['reproduced']} reproduced on a second pass, {run['not_reproduced']} did not "
          f"reproduce, {run['not_rechecked']} could not be rechecked, "
          f"{run['second_pass_only']} seen only on the second pass")


def _entry(kind: str, verb: str, url: str, fp: ResponseFP, rid: str | None, owner: Identity,
           actor: Identity | None) -> dict[str, Any]:
    return {"kind": kind, "verb": verb, "url": url, "status": fp.status, "size": fp.size,
            "owner": owner.name, "accessed_by": actor.name if actor else None, "resource_id": rid}


def _create_resource(creator: Identity, collection_url: str, body: dict[str, Any],
                     timeout: float) -> tuple[str | None, ResponseFP, str]:
    url = fill_url(collection_url, creator)
    fp = request("POST", url, {**creator.headers, "Content-Type": "application/json"},
                 data=json.dumps(body).encode(), timeout=timeout)
    created = _safe_json(fp)
    if fp.status not in (200, 201) or not isinstance(created, dict) or "id" not in created:
        return None, fp, url
    return str(created["id"]), fp, url


def _setup_failed(url: str, fp: ResponseFP) -> Finding:
    why = ("the response body has no 'id' (Location-only responses are not supported yet)"
           if fp.status in (200, 201) else f"HTTP {fp.status}")
    return Finding(
        check="stateful-flow-setup", severity="info", confidence="high", score=0.0,
        evidence=[f"POST {url} as the first identity did not create a resource: {why}. "
                  "The stateful checks did not run."],
        recommendation="Make the create endpoint return the new resource's id in a JSON body, check the creator's "
                       "headers and --create-body, or test with matrix mode instead.",
        endpoint=url, method="POST", status="setup_failed",
        details={"reason": why, "http_status": fp.status},
    )


def _probe_payload(pre: Any) -> dict[str, Any] | None:
    """A change the owner's record can show: a total, or an item name. None if the record has neither."""
    if isinstance(pre, dict) and "total" in pre:
        return {"total": 0.02 if pre["total"] == 0.01 else 0.01}
    if isinstance(pre, dict) and "item" in pre:
        return {"item": "api-sentinel-probe" if pre["item"] != "api-sentinel-probe" else "api-sentinel-probe-2"}
    return None


def _applied(pre: Any, after: Any, payload: dict[str, Any]) -> bool:
    return (isinstance(pre, dict) and isinstance(after, dict)
            and all(after.get(k) == v for k, v in payload.items())
            and any(pre.get(k) != v for k, v in payload.items()))


def _effect_visible(verb: str, pre: Any, expected: dict[str, Any] | None, read: ResponseFP) -> bool:
    """Whether a read of the owner's record shows the write: the probed values for PATCH and PUT, a gone record for
    DELETE. Judged from the record, never from the status code of the write."""
    if verb == "DELETE":
        return read.status in (404, 410)
    return _applied(pre, _unwrap(_safe_json(read)), expected or {})


def _already(pre: Any, expect: dict[str, Any]) -> bool:
    """The owner's record already shows every expected value before the request, so no effect could be seen."""
    return isinstance(pre, dict) and all(pre.get(k) == v for k, v in expect.items())


def _owner_read(owner: Identity, owner_url: str, rid: str, accessor: Identity, timeout: float,
                trail: list[dict[str, Any]]) -> ResponseFP:
    """The owner's own read of the record after a write. It is the only evidence a write is judged by."""
    fp = request("GET", owner_url, owner.headers, timeout=timeout)
    trail.append(_entry("verify", "GET", owner_url, fp, rid, owner, accessor))
    return fp


def _write_undetermined(verb: str, url: str, owner: Identity, accessor: Identity, rid: str,
                        reason: str, action: str | None = None) -> Finding:
    subject = f"action '{action}' (POST)" if action else verb
    if action:
        recommendation = ("Check the action's 'expect' values: they must be what the record shows after the action, "
                          "and not what it already shows. Then re-run.")
    else:
        recommendation = ("Re-read the resource once the operation completes, or declare a probe field in the record, "
                          "then re-run.")
    return Finding(
        check="authorization-undetermined", severity="info", confidence="low", score=0.0,
        evidence=[f"'{accessor.name}' tried {subject} on resource_id={rid} of '{owner.name}': {reason}"],
        recommendation=recommendation,
        endpoint=url, method=verb, status="needs_input",
        details={"class": "BOLA / Broken Object Level Authorization", "owner_identity": owner.name,
                 "accessing_identity": accessor.name, "resource_id": rid, **({"action": action} if action else {})},
    )


def _cleanup(creator: Identity, rid: str, creator_url: str, timeout: float,
             trail: list[dict[str, Any]]) -> list[Finding]:
    """Remove the resource this check created, if it still exists. A leftover is reported, never ignored."""
    still = request("GET", creator_url, creator.headers, timeout=timeout)
    trail.append(_entry("cleanup_check", "GET", creator_url, still, rid, creator, None))
    if not _ok(still):
        return []
    deleted = request("DELETE", creator_url, creator.headers, timeout=timeout)
    trail.append(_entry("cleanup", "DELETE", creator_url, deleted, rid, creator, None))
    if _ok(deleted):
        return []
    return [Finding(
        check="stateful-cleanup", severity="info", confidence="high", score=0.0,
        evidence=[f"resource_id={rid} created by '{creator.name}' remains on the target: its cleanup DELETE "
                  f"returned HTTP {deleted.status}"],
        recommendation="Remove the leftover resource by hand, and run the stateful flow only against a disposable "
                       "environment.",
        endpoint=creator_url, method="DELETE", status="residue",
        details={"owner_identity": creator.name, "resource_id": rid, "http_status": deleted.status},
    )]


_REREAD_NOTES = {
    "read": "The second read did not reproduce the leak, so one response is not enough to confirm it.",
    "write": "The owner's record was read again and did not show the write's effect, so one read is not enough to "
             "confirm it.",
}


def _confirm_on_reread(finding: Finding, reproduced: bool, *, kind: str, error: str | None = None) -> Finding:
    """The second pass for one attempt. A finding is kept only if the second read shows its effect again. If that
    read could not be made (error), the finding is not rechecked, and says why. kind is 'read' or 'write'."""
    if error is not None:
        return _downgraded(finding, "not_rechecked",
                           note=f"The second pass could not complete ({error}), so this result was not rechecked.")
    if reproduced:
        finding.details = {**(finding.details or {}), "recheck": "reproduced"}  # as apply_recheck does
        return finding
    return _downgraded(finding, "not_reproduced", note=_REREAD_NOTES[kind])


@dataclass
class _Attempt:
    """One attempt's context: the resource, its owner, the accessor, the owner's record URL and the run's settings."""
    rid: str
    creator: Identity
    attacker: Identity
    creator_url: str
    timeout: float
    trail: list[dict[str, Any]]
    recheck: bool


def _judge_write(att: _Attempt, verb: str, url: str, fp: ResponseFP, after_fp: ResponseFP,
                 visible: Callable[[ResponseFP], bool], *, what: str, action: str | None = None) -> list[Finding]:
    """The verdict for one write. It comes from the owner's own read afterwards (after_fp), judged by visible(), and
    never from the status of the write alone. A visible effect is confirmed, and the second pass must see it again on a
    second read of the owner's record. The write itself is never sent twice. A success status without an effect is
    no_effect; 202, 400 and 422 are undetermined."""
    subject = f"action '{action}' (POST)" if action else verb
    details = {"class": "BOLA / Broken Object Level Authorization", "owner_identity": att.creator.name,
               "accessing_identity": att.attacker.name, "resource_id": att.rid, "http_status": fp.status,
               "response_bytes": fp.size,
               "workflow": "create-then-action" if action else "create-then-cross-access",
               **({"action": action} if action else {})}
    if visible(after_fp):
        effect = "the resource is gone" if verb == "DELETE" else "the change is visible in the owner's record"
        target = "this action" if action else "this verb"
        sent = "request" if action else "write"
        finding = Finding(
            check="stateful-authorization-boundary", severity="critical", confidence="high", score=90.0,
            evidence=[f"'{att.attacker.name}' sent {what} for resource_id={att.rid} (HTTP {fp.status})",
                      f"the owner's own read afterwards shows the effect: {effect}",
                      "judged from the owner's record, not from the status code",
                      f"expected: a non-owner's {subject} must be rejected before it takes effect"],
            recommendation=f"Verify server-side ownership checks on {target}: a non-owner {sent} must be rejected "
                           "before it takes effect.",
            endpoint=url, method=verb, status="confirmed", details=details)
        if not att.recheck:
            return [finding]
        # The write is not sent again: a second write would be a second destructive action. The owner's record is read
        # once more instead, and the effect must still be there for the finding to stand.
        try:
            again = request("GET", att.creator_url, att.creator.headers, timeout=att.timeout)
        except TransportError as exc:
            return [_confirm_on_reread(finding, False, kind="write", error=str(exc))]
        att.trail.append({**_entry("recheck", "GET", att.creator_url, again, att.rid, att.creator, att.attacker),
                          "of": "verify"})
        return [_confirm_on_reread(finding, visible(again), kind="write")]
    if fp.status == 202:
        return [_write_undetermined(verb, url, att.creator, att.attacker, att.rid,
                                    "HTTP 202 was accepted but the owner's record has not changed yet; the effect "
                                    "may be asynchronous", action=action)]
    if _ok(fp):
        no_effect = "No action: a success status without an effect is not reported as a finding."
        if action:
            no_effect += (" If this action should change the record, check that its 'expect' names the field and value "
                          "the record shows afterwards.")
        return [Finding(
            check="stateful-no-effect", severity="info", confidence="high", score=0.0,
            evidence=[f"{what} by '{att.attacker.name}' returned HTTP {fp.status}, but the owner's record did not "
                      "change: no unauthorized modification was observed"],
            recommendation=no_effect, endpoint=url, method=verb, status="no_effect", details=details)]
    if fp.status in (400, 422):
        return [_write_undetermined(verb, url, att.creator, att.attacker, att.rid,
                                    f"HTTP {fp.status}: the target rejected the request and changed nothing, so the "
                                    "response does not show whether authorization was checked", action=action)]
    return []


def _action_attempt(action: PostAction, url: str, pre: Any, att: _Attempt) -> list[Finding]:
    """One POST sub-action, sent once as the accessor. It has taken effect when the owner's record shows action.expect
    after the request and did not show it before. A record that already shows it cannot show the effect: then no request
    is sent and the result is undetermined."""
    if _already(pre, action.expect):
        return [_write_undetermined("POST", url, att.creator, att.attacker, att.rid,
                                    f"the owner's record already shows the result of '{action.name}' before any "
                                    "request, so its effect cannot be seen. No request was sent", action=action.name)]
    body = action.body
    fp = request("POST", url, {**att.attacker.headers, "Content-Type": "application/json"},
                 data=json.dumps(body).encode(), timeout=att.timeout)
    att.trail.append({**_entry("attempt", "POST", url, fp, att.rid, att.creator, att.attacker), "action": action.name})
    after_fp = _owner_read(att.creator, att.creator_url, att.rid, att.attacker, att.timeout, att.trail)
    return _judge_write(att, "POST", url, fp, after_fp,
                        lambda read: _applied(pre, _unwrap(_safe_json(read)), action.expect),
                        what=f"action '{action.name}' (POST, body {json.dumps(body)})", action=action.name)


def _stateful_attempt(verb: str, url: str, rid: str, creator: Identity, attacker: Identity, creator_url: str,
                      owner_status: int, pre_raw: Any, pre: Any, fields: list[str], timeout: float,
                      trail: list[dict[str, Any]], recheck: bool = True) -> list[Finding]:
    if verb == "GET":
        fp = request("GET", url, attacker.headers, timeout=timeout)
        trail.append(_entry("attempt", "GET", url, fp, rid, creator, attacker))
        judgement = _judge_record(rid, creator, pre_raw, _safe_json(fp), fields, _ok(fp))
        first = _judgement_findings(judgement, creator, attacker, rid, fp, url, "GET", owner_status,
                                    leak_check="stateful-authorization-boundary")
        if not recheck or not any(f.check in BOLA_CHECKS for f in first):
            return first
        # The second pass repeats the read: a read is safe to repeat, so a leak is confirmed only if it reproduces.
        try:
            again = request("GET", url, attacker.headers, timeout=timeout)
        except TransportError as exc:
            return [_confirm_on_reread(f, False, kind="read", error=str(exc)) if f.check in BOLA_CHECKS else f
                    for f in first]
        trail.append({**_entry("recheck", "GET", url, again, rid, creator, attacker), "of": "attempt"})
        second = _judge_record(rid, creator, pre_raw, _safe_json(again), fields, _ok(again))
        reproduced = any(f.check in BOLA_CHECKS for f in _judgement_findings(
            second, creator, attacker, rid, again, url, "GET", owner_status,
            leak_check="stateful-authorization-boundary"))
        return [_confirm_on_reread(f, reproduced, kind="read") if f.check in BOLA_CHECKS else f for f in first]
    att = _Attempt(rid, creator, attacker, creator_url, timeout, trail, recheck)
    if verb in ("PATCH", "PUT"):
        payload = _probe_payload(pre)
        if payload is None:
            return [_write_undetermined(verb, url, creator, attacker, rid,
                                        "the record has neither a 'total' nor an 'item' field to probe, so no write "
                                        "was sent")]
        # PATCH sends only the probed field. PUT replaces the whole record, so it sends the owner's record with
        # that field changed; a PUT with only the probed field is a different request, often a rejected one.
        body = payload if verb == "PATCH" else {**pre, **payload}
        fp = request(verb, url, {**attacker.headers, "Content-Type": "application/json"},
                     data=json.dumps(body).encode(), timeout=timeout)
        trail.append(_entry("attempt", verb, url, fp, rid, creator, attacker))
        after_fp = _owner_read(creator, creator_url, rid, attacker, timeout, trail)
        return _judge_write(att, verb, url, fp, after_fp, lambda read: _effect_visible(verb, pre, payload, read),
                            what=f"{verb} {json.dumps(body)}")
    fp = request("DELETE", url, attacker.headers, timeout=timeout)
    trail.append(_entry("attempt", "DELETE", url, fp, rid, creator, attacker))
    after_fp = _owner_read(creator, creator_url, rid, attacker, timeout, trail)
    return _judge_write(att, "DELETE", url, fp, after_fp, lambda read: _effect_visible("DELETE", pre, None, read),
                        what="DELETE")


def _attempts(item_url_template: str, actions: list[PostAction], owner: Identity, accessor: Identity
              ) -> list[tuple[str | PostAction, str]]:
    """Every attempt against one accessor, in order: each verb, then each POST action. Each one is tried on every URL
    variant of its template (see _url_variant_templates)."""
    out: list[tuple[str | PostAction, str]] = []
    for verb in _STATEFUL_VERBS:
        out += [(verb, template) for template in _url_variant_templates(item_url_template, owner, accessor)]
    for action in actions:
        out += [(action, template) for template in _url_variant_templates(action.url, owner, accessor)]
    return out


def run_stateful_flow(collection_url: str, item_url_template: str, identities: list[Identity],
                      create_body: dict[str, Any], timeout: float, allow_destructive: bool = False,
                      owner_fields: list[str] | None = None,
                      log: list[dict[str, Any]] | None = None, recheck: bool = True,
                      actions: list[PostAction] | None = None) -> list[Finding]:
    """Create a resource as the first identity. For every other identity and every verb, create a fresh copy
    and try the verb on it. Reads are judged like matrix reads. Writes are judged by the owner's own read
    afterwards, so neither a 2xx nor a 403 on a write is evidence on its own. Each created resource is removed
    afterwards if it still exists. Every request is appended to `log` when a list is given. With `recheck`, a leak is
    confirmed only if a second read (for reads) or a second read of the owner's record (for writes) shows it again.
    With `actions`, each declared POST sub-action is also tried, after the verbs, and is judged like a write.
    """
    if not allow_destructive:
        raise DestructiveOperationRefused(
            "the stateful flow creates, modifies and deletes resources on the target. "
            "Re-run with --allow-destructive only against a disposable environment.")
    if len(identities) < 2:
        raise ConfigError("the stateful flow needs at least two identities")
    fields = owner_fields or OWNER_FIELDS_DEFAULT
    trail = log if log is not None else []
    creator, *others = identities
    findings: list[Finding] = []
    for attacker in others:
        for attempt, template in _attempts(item_url_template, actions or [], creator, attacker):
            rid, create_fp, create_url = _create_resource(creator, collection_url, create_body, timeout)
            trail.append(_entry("create", "POST", create_url, create_fp, None, creator, attacker))
            if rid is None:
                findings.append(_setup_failed(create_url, create_fp))
                return findings
            url = _with_id(template, rid)
            creator_url = fill_url(item_url_template, creator, rid)
            pre_fp = request("GET", creator_url, creator.headers, timeout=timeout)
            trail.append(_entry("baseline", "GET", creator_url, pre_fp, rid, creator, attacker))
            pre_raw = _safe_json(pre_fp)
            pre = _unwrap(pre_raw)
            if _ok(pre_fp) and _identifies(pre, rid):
                if isinstance(attempt, PostAction):
                    att = _Attempt(rid, creator, attacker, creator_url, timeout, trail, recheck)
                    findings.extend(_action_attempt(attempt, url, pre, att))
                else:
                    findings.extend(_stateful_attempt(attempt, url, rid, creator, attacker, creator_url,
                                                      pre_fp.status, pre_raw, pre, fields, timeout, trail, recheck))
            else:
                findings.append(_incomplete(creator, rid, creator_url, "GET", pre_fp, False))
            findings.extend(_cleanup(creator, rid, creator_url, timeout, trail))
    return findings


def explain_finding(f: Finding) -> str:
    """Evidence-engine formatter: turn a Finding into the human-readable
    'why was this flagged' block shown in the console and the HTML report."""
    d = f.details or {}
    lines = [f"WHY THIS WAS FLAGGED  [{f.check}]", ""]
    if d.get("owner_identity"):
        lines.append(f"  Owner identity:      {d['owner_identity']}")
    if d.get("accessing_identity"):
        lines.append(f"  Accessing identity:  {d['accessing_identity']}")
    if d.get("resource_id") is not None:
        lines.append(f"  Resource:            {d['resource_id']}")
    if d.get("action"):
        lines.append(f"  Action:              {d['action']}")
    lines.append(f"  Request:             {f.method} {f.endpoint}")
    if d.get("http_status") is not None:
        lines.append(f"  Response:            HTTP {d['http_status']}, {d.get('response_bytes', '?')} bytes")
    lines.append("")
    lines.append("  Evidence:")
    lines.extend(f"    - {e}" for e in f.evidence)
    lines.append("")
    lines.append(f"  Confidence: {f.confidence.upper()}   Severity: {f.severity.upper()}   Score: {f.score:.0f}/100")
    lines.append("")
    lines.append("  Why it matters: an identity other than the resource owner received data for that resource.")
    lines.append(f"  Recommended verification: {f.recommendation}")
    return "\n".join(lines)


def categorize(f: Finding) -> str:
    """The one category a result belongs to. Only 'confirmed' is ever reported as a violation."""
    if f.check in BOLA_CHECKS:
        return "confirmed"
    if f.status == "needs_input":
        return "undetermined"
    if f.status in ("setup_failed", "skipped"):
        return "incomplete"
    if f.status == "residue":
        return "residue"
    return "info"


_REPORT_CSS = """
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; background: #0b1020; color: #e2e8f0;
         margin: 0; padding: 2rem; }
  h1 { color: #f8fafc; margin-bottom: .25rem; }
  .meta-top { color: #94a3b8; margin: .25rem 0; }
  .finding { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1.25rem 1.5rem;
             margin-bottom: 1rem; }
  .badge { color: white; font-size: .7rem; padding: .15rem .5rem; border-radius: 999px; margin-right: .5rem;
           letter-spacing: .03em; }
  .meta { color: #94a3b8; font-size: .85rem; margin: .25rem 0; }
  ul { margin: .5rem 0; padding-left: 1.25rem; }
  li { margin: .2rem 0; }
  .rec { color: #cbd5e1; margin-top: .75rem; }
  .disclaimer { margin-top: 2rem; color: #64748b; font-size: .8rem; border-top: 1px solid #1f2937;
                padding-top: 1rem; }
"""


def render_html(report: dict[str, Any]) -> str:
    def esc(s: Any) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    sev_color = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207",
                 "low": "#4d7c0f", "info": "#475569"}
    cat_color = {"undetermined": "#475569", "incomplete": "#a16207", "residue": "#7c3aed"}
    rows = []
    for f in report["findings"]:
        if f["category"] == "info":
            continue  # bookkeeping (for example a write that had no effect) stays in the JSON report
        if f["category"] == "confirmed":
            color = sev_color.get(f["severity"], "#475569")
            label = f"CONFIRMED &middot; {esc(f['severity'].upper())}"
        else:
            color = cat_color.get(f["category"], "#475569")
            label = esc(f["category"].upper())
        details = f.get("details") or {}
        detail_bits = " &middot; ".join(f"{esc(k)}: {esc(v)}" for k, v in details.items() if k != "class")
        evidence_html = "".join(f"<li>{esc(e)}</li>" for e in f["evidence"])
        rows.append(f"""
        <section class="finding">
          <h3><span class="badge" style="background:{color}">{label}</span>{esc(f['check'])}</h3>
          <p class="meta">{esc(f['method'])} {esc(f['endpoint'])} &middot; confidence: {esc(f['confidence'])}</p>
          {f'<p class="meta">{detail_bits}</p>' if detail_bits else ''}
          <ul>{evidence_html}</ul>
          <p class="rec"><strong>Recommended verification:</strong> {esc(f['recommendation'])}</p>
        </section>""")
    summary, cov = report["summary"], report["coverage"]
    empty = "<p>No confirmed findings, undetermined results or incomplete checks.</p>"
    findings_html = "\n".join(rows) if rows else empty
    totals = report.get("recheck", {}).get("totals", {})
    second_pass = ""
    if totals.get("candidates"):
        second_pass = (f'<p class="meta-top">Second pass: {totals["reproduced"]} reproduced, '
                       f'{totals["not_reproduced"]} did not reproduce, '
                       f'{totals["not_rechecked"]} could not be rechecked, '
                       f'{totals["second_pass_only"]} seen only on the second pass</p>')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>API Sentinel Report - {esc(report['target'])}</title>
<style>{_REPORT_CSS}</style></head>
<body>
  <h1>API Sentinel Report</h1>
  <p class="meta-top">Target: {esc(report['target'])} &middot; Status: {esc(report['status'])}
     &middot; Generated: {esc(report['generated_at'])}</p>
  <p class="meta-top">Confirmed: {summary['confirmed']} &middot; Undetermined: {summary['undetermined']}
     &middot; Incomplete: {summary['incomplete']} &middot; Residue: {summary['residue']}</p>
  <p class="meta-top">Checks run: {cov['checks_run']} &middot; Passed: {cov['passed']}
     &middot; Requests sent: {cov['requests_sent']} &middot; Owned resources tested: {cov['owned_resources_tested']}</p>
  {second_pass}
  {findings_html}
  <p class="disclaimer">{esc(report['disclaimer'])}</p>
</body></html>"""


def render_sarif(report: dict[str, Any], artifact_uri: str) -> dict[str, Any]:
    """SARIF 2.1.0 with confirmed findings only. Undetermined and incomplete results are not code-scanning alerts."""
    results = []
    for f in report["findings"]:
        if f["category"] != "confirmed":
            continue
        results.append({
            "ruleId": f["check"],
            "level": "error" if f["severity"] in ("critical", "high") else "warning",
            "message": {"text": f"{f['check']} ({f['confidence']} confidence): " + "; ".join(f["evidence"])},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact_uri}},
                "logicalLocations": [{"name": f["endpoint"]}],
            }],
            "properties": {"category": f["category"], "method": f["method"],
                           "recommendation": f["recommendation"],
                           **{k: v for k, v in (f.get("details") or {}).items()}},
        })
    rule_ids = sorted({r["ruleId"] for r in results})
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "api-sentinel", "version": report["version"],
                                "rules": [{"id": rid} for rid in rule_ids]}},
            "results": results,
        }],
    }


def _make_report_core(target: str, baseline: dict[str, Any] | None, findings: list[Finding],
                coverage: dict[str, Any], status: str) -> dict[str, Any]:
    items = []
    for f in findings:
        d = asdict(f)
        d["category"] = categorize(f)
        items.append(d)
    counts = Counter(d["category"] for d in items)
    return {
        "tool": "api-sentinel",
        "version": __version__,
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "operator_attested_authorization": True,  # set by --yes-i-am-authorized: an attestation, not a control
        "status": status,
        "summary": {k: counts.get(k, 0) for k in ("confirmed", "undetermined", "incomplete", "residue", "info")},
        "coverage": coverage,
        "baseline": baseline,
        "findings": items,
        "disclaimer": ("Confirmed means the behavioral evidence rules were met. It is a lead for human validation, "
                       "not proof of a vulnerability. Undetermined results were not decided and need review. "
                       "A clean run does not prove an API is secure."),
    }


# --- Ownership discovery, OpenAPI plan and report output (0.3.0) -----------------------------------------
#
# --discover reads each identity's own collection listing and tests the ids it shows. Those ids go through the
# same matrix and evidence rules as declared ids. Ownership is attributed conservatively:
#   * a declared id stays with the identity that declared it;
#   * an item whose ownership field equals an identity's declared owner_values belongs to that identity
#     ("owner-field"), even when a leaky listing shows it to everybody;
#   * an id that exactly one identity can see belongs to that identity ("listing");
#   * anything else is ambiguous and is not tested.
# Discovery reads the first page of each listing only. A finding on a discovered id is capped at medium
# confidence and says how its ownership was inferred.

_LIST_ENVELOPE_KEYS = ("data", "items", "results", "records")
_HOW_INFERRED = {"listing": "the owner's own listing", "owner-field": "the ownership field of the owner's listed item"}


@dataclass
class Discovery:
    owns: dict[str, list[str]]           # identity name -> ids attributed to it (declared ids are not repeated)
    sources: dict[tuple[str, str], str]  # (identity name, id) -> "owner-field" | "listing"
    per_identity: list[dict[str, Any]]   # what each listing gave
    ambiguous: list[str]                 # ids that could not be attributed to one identity
    listed_for_other: int                # (attributed id, other identity) pairs where a listing shows the id

    def summary(self) -> dict[str, Any]:
        return {
            "identities": self.per_identity,
            "attributed": {name: len(ids) for name, ids in self.owns.items()},
            "ambiguous_ids": self.ambiguous,
            "listed_for_other_identity": self.listed_for_other,
            "scope": "first page of each listing only",
        }


def _list_items(body: Any) -> list[Any] | None:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in _LIST_ENVELOPE_KEYS:
            if isinstance(body.get(key), list):
                return body[key]
        lists = [value for value in body.values() if isinstance(value, list)]
        if len(lists) == 1:
            return lists[0]
    return None


def _item_id(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    for key in _active_id_keys:
        value = item.get(key)
        if value is not None and not isinstance(value, (dict, list, bool)):
            return str(value)
    return None


def discover_owned_ids(identities: list[Identity], list_url: str, owner_fields: list[str], timeout: float,
                       trail: list[dict[str, Any]]) -> Discovery:
    """One GET per identity against the listing, then attribution by the rules above. No other request is sent."""
    if "{id}" in list_url:
        raise ConfigError("the listing URL for discovery is a collection, for example https://host/orders: "
                          "it must not contain {id}")
    listed: dict[str, dict[str, Any]] = {}  # identity -> {id: the item as that identity saw it}
    per_identity: list[dict[str, Any]] = []
    for ident in identities:
        url = fill_url(list_url, ident)
        fp = request("GET", url, ident.headers, timeout=timeout)
        trail.append({"kind": "discover", "owner": ident.name, "url": url, "status": fp.status, "size": fp.size})
        items = _list_items(_safe_json(fp)) if _ok(fp) else None
        if items is None:
            why = f"HTTP {fp.status}" if not _ok(fp) else "the response is not a JSON list"
            per_identity.append({"identity": ident.name, "status": "not_listed", "reason": why, "ids": 0})
            listed[ident.name] = {}
            continue
        seen: dict[str, Any] = {}
        without_id = 0
        for item in items:
            rid = _item_id(item)
            if rid is None:
                without_id += 1
            else:
                seen.setdefault(rid, item)
        listed[ident.name] = seen
        per_identity.append({"identity": ident.name, "status": "listed", "reason": None,
                             "ids": len(seen), "items_without_id": without_id})

    membership: dict[str, list[str]] = {}
    for name, seen in listed.items():
        for rid in seen:
            membership.setdefault(rid, []).append(name)
    declared_owner = {rid: ident.name for ident in identities for rid in ident.owns}
    owner_values = [(ident.name, field_name, value) for ident in identities
                    for field_name, value in ident.owner_values.items() if _informative(value)]

    owns: dict[str, list[str]] = {ident.name: [] for ident in identities}
    sources: dict[tuple[str, str], str] = {}
    ambiguous: list[str] = []
    listed_for_other = 0
    for rid in sorted(membership):
        if rid in declared_owner:
            owner, how = declared_owner[rid], "declared"
        else:
            matches: set[str] = set()
            for seen in listed.values():
                if rid not in seen:
                    continue
                item = seen[rid]
                for name, field_name, value in owner_values:
                    if field_name in item and item[field_name] == value:
                        matches.add(name)
            if len(matches) == 1:
                owner, how = matches.pop(), "owner-field"
            elif not matches and len(membership[rid]) == 1:
                owner, how = membership[rid][0], "listing"
            else:
                ambiguous.append(rid)
                continue
        listed_for_other += sum(1 for name in membership[rid] if name != owner)
        if how != "declared":
            owns[owner].append(rid)
            sources[(owner, rid)] = how
    return Discovery(owns, sources, per_identity, ambiguous, listed_for_other)


def _with_discovered(identities: list[Identity], disc: Discovery) -> list[Identity]:
    out = []
    for ident in identities:
        new = [rid for rid in disc.owns.get(ident.name, []) if rid not in ident.owns]
        out.append(replace(ident, owns=[*ident.owns, *new]))
    return out


def annotate_discovered(findings: list[Finding], sources: dict[tuple[str, str], str]) -> None:
    """Findings on ids whose ownership was inferred say how it was inferred, and are capped at medium confidence."""
    for f in findings:
        d = f.details or {}
        key = (d.get("owner_identity"), str(d.get("resource_id")))
        how = sources.get(key)
        if how is None or not (f.check in BOLA_CHECKS or f.check == "authorization-undetermined"):
            continue
        d["ownership_source"] = how
        f.details = d
        if f.confidence == "high":
            f.confidence = "medium"
        f.evidence.append(f"ownership of resource_id={key[1]} was inferred from {_HOW_INFERRED[how]}, "
                          "not declared in the identities file")


# --- OpenAPI test plan ----------------------------------------------------------------------------------

def _has_get(node: Any) -> bool:
    return isinstance(node, dict) and any(str(key).lower() == "get" for key in node)


def build_plan(doc: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    """One entry per route whose last segment is an identity parameter, e.g. /orders/{orderId} or
    /users/{uid}/orders/{id}. The item template uses {id}. Any other parameter (uid) is filled from each identity's
    params, and the entry lists it in params_needed. Ownership is discovered from the GET collection of the parent
    path (/orders, or /users/{uid}/orders). Every other route is listed with the reason it is not tested, so the
    scope is visible before anything is sent."""
    base = base_url.rstrip("/")
    if not re.match(r"^https?://[^/\s]+", base):
        raise ConfigError(f"--base-url must be an http(s) URL such as http://127.0.0.1:8000, got {base_url!r}")
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    plan: list[dict[str, Any]] = []
    seen_items: set[str] = set()
    for path, node in paths.items():
        segments = [seg for seg in path.split("/") if seg]
        params = [seg for seg in segments if seg.startswith("{") and seg.endswith("}")]
        inline = [seg for seg in segments if "{" in seg and seg not in params]
        if not params and not inline:
            continue  # fixed routes such as /orders are collections, not items
        entry: dict[str, Any] = {"path": path, "item_url": None, "collection_url": None,
                                 "params_needed": [], "status": "skipped", "reason": None}
        plan.append(entry)
        if inline:
            entry["reason"] = "a placeholder inside a path segment, such as {id}.json, is not supported"
            continue
        if not segments[-1].startswith("{"):
            entry["reason"] = ("a collection under a parameter: not an item route, so it is not tested itself; "
                               "discovery uses it as the listing for its item route")
            continue
        if not _has_get(node):
            entry["reason"] = "no GET on this route; the matrix is read-only"
            continue
        entry["params_needed"] = [seg[1:-1] for seg in segments[:-1] if seg.startswith("{") and seg.endswith("}")]
        if "id" in entry["params_needed"]:
            entry["reason"] = "a parent parameter named id collides with the item placeholder {id}"
            continue
        item_url = f"{base}/" + "/".join(segments[:-1] + ["{id}"])
        if item_url in seen_items:
            entry["reason"] = "same route as an earlier entry"
            continue
        seen_items.add(item_url)
        entry["item_url"] = item_url
        parent = "/" + "/".join(segments[:-1])
        if len(segments) == 1 or not _has_get(paths.get(parent)):
            entry["reason"] = "no GET collection endpoint in the document, so ownership cannot be discovered"
            continue
        entry.update(status="planned", collection_url=f"{base}{parent}")
    return plan


def _run_plan(args: argparse.Namespace, doc: dict[str, Any]) -> int:
    _check_scheme_and_host(args.base_url)  # before anything else: a refused host sends nothing, not even a plan
    plan = build_plan(doc, args.base_url)
    base = args.base_url.rstrip("/")
    runnable = [p for p in plan if p["status"] == "planned"]
    print(f"[+] Plan against {base}: {len(runnable)} resource(s) to test, {len(plan) - len(runnable)} not tested")
    for p in plan:
        mark = "RUN " if p["status"] == "planned" else "skip"
        line = f"    [{mark}] {p['item_url'] or p['path']}"
        if p["collection_url"]:
            line += f"   listing: {p['collection_url']}"
        if p["params_needed"]:
            line += f"   needs params.{', params.'.join(p['params_needed'])} for every identity"
        if p["reason"]:
            line += f"   ({p['reason']})"
        print(line)
    if args.plan_only:
        plan_doc = json.dumps({"tool": "api-sentinel", "version": __version__, "base_url": base, "plan": plan},
                              indent=2, ensure_ascii=False)
        if args.report_dir:
            path = _unique_stem(args.report_dir, "api-sentinel") + "-plan.json"
            _write(path, plan_doc, exclusive=True)
        else:
            path = args.output or "api-sentinel-plan.json"
            _write(path, plan_doc, exclusive=False)
        print(f"[+] Plan written: {path}. No requests were sent.")
        return EXIT_OK
    if not args.identities:
        raise ConfigError("plan mode needs --identities: the identities send the requests")
    if not runnable:
        raise ConfigError("nothing to test: no single-id GET route in this document has a GET collection to "
                          "discover ownership from")
    identities = load_identities(args.identities)
    base_ids = [replace(ident, owns=[]) for ident in identities]  # plan mode takes ownership from discovery only
    owner_fields = [x.strip() for x in args.ownership_fields.split(",") if x.strip()]
    findings: list[Finding] = []
    trail: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []  # one recheck summary per route
    recheck = _recheck_enabled(args)
    for p in plan:
        if p["status"] != "planned":
            results.append(p)
            continue
        lacking = [f"'{ident.name}' has no params.{key}" for ident in base_ids for key in p["params_needed"]
                   if key not in ident.params]
        if lacking:
            reason = "these identities have no value for a parent parameter this route needs: " + "; ".join(lacking)
            findings.append(Finding(
                "plan-item-skipped", "info", "high", 0.0, [f"{p['item_url']}: {reason}"],
                "Add a params entry for each parent parameter to every identity, then re-run.",
                p["item_url"], "GET", status="skipped", details={"reason": reason}))
            results.append({**p, "status": "skipped", "reason": reason})
            continue
        disc = discover_owned_ids(base_ids, p["collection_url"], owner_fields, args.timeout, trail)
        attributed = sum(len(ids) for ids in disc.owns.values())
        if attributed == 0:
            reason = "discovery attributed no id to any identity, so this route was not tested"
            findings.append(Finding(
                "plan-item-skipped", "info", "high", 0.0, [f"{p['item_url']}: {reason}"],
                "Make each identity's listing show its own resources, or declare owner_values so that ownership "
                "can be attributed, then re-run.", p["item_url"], "GET", status="skipped", details={"reason": reason}))
            results.append({**p, "status": "skipped", "reason": reason, "discovery": disc.summary()})
            continue
        print(f"[+] {p['item_url']}: {attributed} resource(s) attributed by discovery")
        found, run = run_matrix_with_recheck(p["item_url"], _with_discovered(base_ids, disc), owner_fields,
                                             args.timeout, trail, scope=p["item_url"], recheck=recheck)
        annotate_discovered(found, disc.sources)
        findings.extend(found)
        runs.append(run)
        _print_recheck(run)
        results.append({**p, "status": "ran", "reason": None, "discovery": disc.summary(), "recheck": run,
                        "confirmed": sum(1 for f in found if f.check in BOLA_CHECKS)})
    extra = {"mode": "openapi-plan", "plan": results, "recheck": recheck_report(recheck, runs)}
    return _conclude(args, identities, findings, trail, base, None, extra)


# --- Report output and the common ending of a run ---------------------------------------------------------

def make_report(target: str, baseline: dict[str, Any] | None, findings: list[Finding],
                coverage: dict[str, Any], status: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    report = _make_report_core(target, baseline, findings, coverage, status)
    report.update(extra or {})
    return report


def _unique_stem(directory: str, label: str) -> str:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for _ in range(20):
        stem = f"{label}-{stamp}-{secrets.token_hex(3)}"
        if not any((folder / (stem + ext)).exists() for ext in (".json", ".html", ".sarif")):
            return str(folder / stem)
    raise ConfigError(f"could not find a free report name in {directory!r}")


def _write(path: str, text: str, exclusive: bool) -> None:
    text = redact_text(text)  # defence in depth: a report is redacted before it is serialized
    if not exclusive:
        Path(path).write_text(text, encoding="utf-8")
        return
    try:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError:
        raise ConfigError(f"refusing to overwrite {path!r}") from None


def _emit_reports(args: argparse.Namespace, report: dict[str, Any]) -> None:
    report = redact(report)
    if args.report_dir:
        stem = _unique_stem(args.report_dir, "api-sentinel")
        json_path, html_path, sarif_path = stem + ".json", stem + ".html", stem + ".sarif"
        exclusive = True
    else:
        json_path = args.output or "api-sentinel-report.json"
        html_path, sarif_path = args.html_output, args.sarif_output
        exclusive = False
    _write(json_path, json.dumps(report, indent=2, ensure_ascii=False), exclusive)
    print(f"[+] Report: {json_path}")
    if html_path:
        _write(html_path, render_html(report), exclusive)
        print(f"[+] HTML report: {html_path}")
    if sarif_path:
        _write(sarif_path, json.dumps(render_sarif(report, args.identities or json_path), indent=2), exclusive)
        print(f"[+] SARIF report: {sarif_path}")


def _conclude(args: argparse.Namespace, identities: list[Identity], findings: list[Finding],
              trail: list[dict[str, Any]], target: str, base: dict[str, Any] | None,
              extra: dict[str, Any] | None) -> int:
    coverage = _coverage(identities, findings, trail)
    incomplete = [f for f in findings if f.status in ("setup_failed", "skipped")]
    residue = [f for f in findings if f.status == "residue"]
    undetermined = [f for f in findings if f.status == "needs_input"]
    confirmed = [f for f in findings if f.check in BOLA_CHECKS]
    status = "incomplete" if incomplete else "complete"
    report = make_report(target, base, findings, coverage, status, extra=extra)
    _emit_reports(args, report)

    s = report["summary"]
    print(f"\n[+] Result: {status}")
    print(f"    confirmed={s['confirmed']}  undetermined={s['undetermined']}  incomplete={s['incomplete']}  "
          f"residue={s['residue']}")
    print(f"    checks run={coverage['checks_run']}  passed={coverage['passed']}  "
          f"requests sent={coverage['requests_sent']}  owned resources tested={coverage['owned_resources_tested']}")
    if confirmed:
        print()
        print("\n\n".join(explain_finding(f) for f in confirmed))
    for f in incomplete:
        print(f"[!] incomplete: {f.evidence[0]}", file=sys.stderr)
    for f in residue:
        print(f"[!] residue: {f.evidence[0]}", file=sys.stderr)

    threshold = {"none": 99, "high": 3, "critical": 4}[args.fail_on]
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if any(rank.get(f.severity, 0) >= threshold for f in confirmed):
        return EXIT_POLICY
    if incomplete:
        print(f"[x] {len(incomplete)} check(s) did not run to completion; the result is not a clean pass",
              file=sys.stderr)
        return EXIT_INCOMPLETE
    if undetermined:
        print(f"[!] {len(undetermined)} result(s) are undetermined and need human review", file=sys.stderr)
        return EXIT_UNDETERMINED
    return EXIT_OK


def cli(argv: list[str] | None = None) -> int:
    global _ALLOWED_HOSTS
    p = argparse.ArgumentParser(
        prog="api-sentinel",
        description="Authorization (BOLA) regression testing for authorized environments. Compares what two or more "
                    "controlled identities can read, and reports behavioral evidence.",
        epilog="exit codes: 0 clean; 1 confirmed finding at/above --fail-on; 2 configuration problem or refused "
               "operation; 3 incomplete (setup or baseline failed, checks not run); 4 transport failure; "
               "5 internal error; 6 undetermined (results need human review)",
    )
    p.add_argument("--version", action="version", version=f"api-sentinel {__version__}")
    p.add_argument("--yes-i-am-authorized", action="store_true",
                   help="Required. Attests that you are authorized to test the target. A guard against accidental "
                        "runs, not a security control.")
    p.add_argument("--url", help="URL template containing {id}, e.g. https://localhost:8000/orders/{id}. Other "
                                 "{names} are filled from identity 'params', e.g. /users/{user_id}/orders/{id}.")
    p.add_argument("--allow-host", action="append", default=None, metavar="HOST",
                   help="Host name the tool may contact, for example 127.0.0.1 or api.internal (no scheme, port or "
                        "path). Repeatable. When given, every URL is checked before the first request, and a request "
                        "to any other host is refused. Recommended in CI.")
    p.add_argument("--method", default="GET",
                   help="Must be GET. Baseline, fuzz and authorization checks are read-only. Write verbs are tested "
                        "only by --stateful.")
    p.add_argument("--allow-destructive", action="store_true",
                   help="Opt-in for --stateful, which creates, modifies and deletes resources on the target. "
                        "Use only on disposable environments.")
    p.add_argument("--baseline-ids", help="Comma-separated known-good values (3+)")
    p.add_argument("--fuzz", action="store_true",
                   help="Send edge-case values and report deviations from the baseline as undetermined anomalies")
    p.add_argument("--token-a")
    p.add_argument("--token-b")
    p.add_argument("--auth-header", default="Authorization")
    p.add_argument("--test-id", help="Two-identity shorthand: token A owns this id, token B must not read it "
                                     "(needs --token-a and --token-b)")
    p.add_argument("--openapi", help="OpenAPI/Swagger JSON file; discovery or graph mode only")
    p.add_argument("--graph", action="store_true",
                   help="With --openapi, infer and print the resource/ownership graph instead of listing operations")
    p.add_argument("--identities", help="JSON file describing 2+ identities (headers, owns, optional params and "
                                        "owner_values). A value written as ${NAME} is read from the environment, so "
                                        "tokens need not be stored in the file.")
    p.add_argument("--ownership-fields", default=",".join(OWNER_FIELDS_DEFAULT),
                   help="Comma-separated response field names treated as ownership signals")
    p.add_argument("--stateful", action="store_true",
                   help="Also run the create-then-cross-access flow (needs --identities, --collection-url and "
                        "--allow-destructive)")
    p.add_argument("--collection-url", help="Collection URL for POST in the stateful flow, e.g. "
                                            "https://localhost:8000/orders")
    p.add_argument("--create-body", default='{"item": "API Sentinel test item", "total": 9.99}',
                   help="JSON object used to create a resource in the stateful flow")
    p.add_argument("--actions", metavar="FILE",
                   help="JSON file of POST sub-actions to try in the stateful flow after the verbs, for example "
                        "cancelling an order. Each action is sent once per non-owner and judged by the owner's record: "
                        "its 'expect' values must show there afterwards. Needs --stateful. See POST sub-actions in the "
                        "README.")
    p.add_argument("--output", default=None,
                   help="JSON report path (default api-sentinel-report.json; api-sentinel-plan.json with --plan-only). "
                        "Not allowed with --report-dir.")
    p.add_argument("--html-output", help="Optional path to also write an HTML report")
    p.add_argument("--sarif-output", help="Optional path to also write a SARIF 2.1.0 report (confirmed findings only)")
    p.add_argument("--fail-on", choices=["none", "high", "critical"], default="high",
                   help="Exit 1 when a confirmed finding is at or above this severity (default: high). 'none' reports "
                        "without failing: confirmed findings then do not change the exit code")
    p.add_argument("--discover", action="store_true",
                   help="Read each identity's own listing (--collection-url, GET) and test the ids it shows. Ids that "
                        "cannot be attributed to one identity are not tested. Findings on discovered ids are capped at "
                        "medium confidence.")
    p.add_argument("--report-dir",
                   help="Write the JSON, HTML and SARIF reports into this directory under a unique, timestamped name. "
                        "Existing reports are never overwritten. Not allowed with --output, --html-output or "
                        "--sarif-output.")
    p.add_argument("--base-url",
                   help="With --openapi: build a test plan against this server (for example http://127.0.0.1:8000) and "
                        "run it. Every single-id GET route with a GET collection is tested; ownership comes from "
                        "discovery only, declared owns are ignored in this mode.")
    p.add_argument("--plan-only", action="store_true",
                   help="With --openapi and --base-url: print the plan and write it as JSON. Sends no requests.")
    p.add_argument("--id-field",
                   help="Name of the response field that carries the resource id, for example book_title. Replaces the "
                        "default names (id, orderId, order_id, resource_id, uuid) for matching and for discovery.")
    p.add_argument("--no-recheck", action="store_true",
                   help="Skip the second pass that must reproduce each confirmed finding. Without it, one response "
                        "is enough to report a confirmed finding.")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--debug", action="store_true", help="Show tracebacks for errors")
    args = p.parse_args(argv)
    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _RedactingStream(stdout), _RedactingStream(stderr)
    _SECRETS.clear()
    try:
        _ALLOWED_HOSTS = _allowed_hosts(args.allow_host)
        with resource_id_field(args.id_field):
            return _run(args)
    except ScanError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return exc.exit_code
    except KeyboardInterrupt:
        print("[x] interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # a bug in this tool, not a finding: report it in a controlled way
        print(f"[x] internal error: {type(exc).__name__}: {exc}. Re-run with --debug for the traceback.",
              file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return EXIT_INTERNAL
    finally:
        _ALLOWED_HOSTS = None
        _SECRETS.clear()
        sys.stdout, sys.stderr = stdout, stderr


def _check_key(entry: dict[str, Any]) -> tuple[str, str, str, str]:
    return (str(entry["owner"]), str(entry["accessed_by"]), str(entry["resource_id"]), str(entry["url"]))


def _coverage(identities: list[Identity], findings: list[Finding], trail: list[dict[str, Any]]) -> dict[str, Any]:
    """What was actually exercised. 'passed' = checks that produced no confirmed and no undetermined result.

    The second pass repeats requests. A check that both passes ran counts once, and a check that only the second pass
    ran (its owner's baseline failed on the first pass) counts as run. Every request counts as sent."""
    accessor = [e for e in trail if e.get("kind") == "accessor"]
    attempts = [e for e in trail if e.get("kind") == "attempt"]
    first_checks = {_check_key(e) for e in accessor}
    repeated = {_check_key(e) for e in trail if e.get("kind") == "recheck" and e.get("of") == "accessor"}
    owned_ok = {(e["owner"], e["resource_id"]) for e in trail
                if e.get("of", e.get("kind")) == "owner_baseline" and 200 <= e["status"] < 300}
    checks_run = len(accessor) + len(repeated - first_checks) + len(attempts)
    confirmed = sum(1 for f in findings if f.check in BOLA_CHECKS)
    undetermined_checks = sum(1 for f in findings if f.check == "authorization-undetermined")
    return {
        "identities": len(identities),
        "owned_resources_tested": len(owned_ok),
        "requests_sent": len(trail),
        "checks_run": checks_run,
        "confirmed": confirmed,
        "passed": checks_run - confirmed - undetermined_checks,
        "undetermined": sum(1 for f in findings if f.status == "needs_input"),
        "incomplete": sum(1 for f in findings if f.status in ("setup_failed", "skipped")),
        "residue": sum(1 for f in findings if f.status == "residue"),
    }


def _run(args: argparse.Namespace) -> int:
    if not args.yes_i_am_authorized:
        raise ConfigError("refusing to run: pass --yes-i-am-authorized for an authorized target")

    if args.report_dir and (args.output or args.html_output or args.sarif_output):
        raise ConfigError("--report-dir writes all three reports itself: do not combine it with --output, "
                          "--html-output or --sarif-output")

    if args.openapi:
        try:
            doc = load_openapi(args.openapi)
        except (OSError, ValueError) as e:
            raise ConfigError(f"OpenAPI error: {e}") from None
        if args.base_url:
            if args.url or args.graph or args.test_id or args.stateful or args.discover:
                raise ConfigError("--base-url runs the plan by itself: do not combine it with --url, --graph, "
                                  "--test-id, --stateful or --discover")
            return _run_plan(args, doc)
        if args.plan_only:
            raise ConfigError("--plan-only needs --base-url")
        if args.graph:
            print(format_graph(infer_resource_graph(doc)))
        else:
            paths = discover_paths(doc)
            print(f"Discovered {len(paths)} operations:")
            for x in paths:
                print(f"  {x['method']:6} {x['path']}  {x['operation_id']}")
        return EXIT_OK
    if args.base_url or args.plan_only:
        raise ConfigError("--base-url and --plan-only need --openapi")

    if not args.url:
        raise ConfigError("--url is required unless --openapi is used")
    if args.method.upper() != "GET":
        raise ConfigError(f"--method {args.method.upper()} is not supported: baseline, fuzz and authorization checks "
                          "are read-only. Write verbs are tested only by --stateful, which needs --allow-destructive.")
    for configured in (args.url, args.collection_url):
        if configured:
            _check_scheme_and_host(configured)  # before any request: the scheme, and --allow-host when it is given
    if args.stateful and not args.allow_destructive:
        raise DestructiveOperationRefused("--stateful creates, modifies and deletes resources on the target. "
                                          "Re-run with --allow-destructive only against a disposable environment.")
    if args.actions and not args.stateful:
        raise ConfigError("--actions sends POST requests inside the stateful flow: add --stateful, with "
                          "--allow-destructive, --collection-url and --identities")
    if args.allow_destructive and not args.stateful:
        print("[!] --allow-destructive has no effect without --stateful", file=sys.stderr)
    if args.stateful:
        sent = "create, PATCH, PUT and DELETE requests" + (" and the POST actions of --actions" if args.actions else "")
        print(f"[!] --stateful: {sent} will be sent to the target", file=sys.stderr)

    values = [x.strip() for x in args.baseline_ids.split(",") if x.strip()] if args.baseline_ids else []
    if args.baseline_ids and len(values) < 3:
        raise ConfigError("--baseline-ids needs at least 3 values")
    if args.fuzz and not values:
        raise ConfigError("--fuzz needs --baseline-ids: fuzz results are compared against the baseline")
    if args.test_id and not (args.token_a and args.token_b):
        raise ConfigError("--test-id needs both --token-a and --token-b")
    if args.discover:
        if not args.identities:
            raise ConfigError("--discover needs --identities")
        if not args.collection_url:
            raise ConfigError("--discover needs --collection-url: the listing that each identity reads its own "
                              "resources from")
        if "{id}" in args.collection_url:
            raise ConfigError("--collection-url for --discover is a collection, for example https://host/orders: "
                              "it must not contain {id}")
    if args.stateful:
        if not args.identities:
            raise ConfigError("--stateful needs --identities")
        if not args.collection_url:
            raise ConfigError("--stateful needs --collection-url")
        if "{id}" not in args.url:
            raise ConfigError("--stateful needs --url with {id} for the item endpoint")
    if (values or args.test_id) and _PLACEHOLDER.search(args.url.replace("{id}", "")):
        raise ConfigError("baseline, fuzz and two-identity checks support --url with {id} only; parent placeholders "
                          "are supported by the identities matrix and stateful checks")
    identities = load_identities(args.identities) if args.identities else []
    actions = load_post_actions(args.actions) if args.actions else []
    if identities and not args.stateful and not args.discover and not any(i.owns for i in identities):
        raise ConfigError("the identities file declares no 'owns' resources, so there is nothing to test; list the "
                          "resource ids each identity owns, or use --stateful")
    if not (args.test_id or args.stateful or args.discover or any(i.owns for i in identities)):
        raise ConfigError("nothing to test: no authorization check is configured. Give two identities with 'owns' "
                          "(matrix), --test-id with both tokens, or --stateful with --allow-destructive. "
                          "--baseline-ids and --fuzz measure behaviour only and never show authorization.")
    try:
        create_body = json.loads(args.create_body)
    except json.JSONDecodeError as e:
        raise ConfigError(f"--create-body is not valid JSON: {e}") from None
    if not isinstance(create_body, dict):
        raise ConfigError("--create-body must be a JSON object")

    def build(v: str) -> str:
        return args.url.replace("{id}", quote(v, safe=""))

    headers = {args.auth_header: args.token_a} if args.token_a else {}
    owner_fields = [x.strip() for x in args.ownership_fields.split(",") if x.strip()]
    findings: list[Finding] = []
    trail: list[dict[str, Any]] = []  # every request sent, for the coverage section
    runs: list[dict[str, Any]] = []  # one recheck summary per matrix pass
    recheck = _recheck_enabled(args)
    base = None
    if values:
        print(f"[+] Building baseline from {len(values)} authorized requests...")
        samples = []
        for v in values:
            fp = request("GET", build(v), headers, timeout=args.timeout)
            samples.append(fp)
            trail.append({"kind": "sample", "url": build(v), "status": fp.status, "size": fp.size})
        base = summarize(samples)
        print(f"[+] Baseline: {base['samples']} samples; statuses={base['statuses']}")
        if args.fuzz:
            for value in ["", "0", "-1", "null", "999999999", "x" * 128]:
                fp = request("GET", build(value), headers, timeout=args.timeout)
                trail.append({"kind": "fuzz", "url": build(value), "status": fp.status, "size": fp.size})
                score, evidence = anomaly_score(base, fp)
                if score >= 50:
                    findings.append(Finding(
                        "behavioral-anomaly", "info", "low", score,
                        evidence + ["unverified: a deviation from the baseline is not evidence of an authorization "
                                    "violation"],
                        "Inspect this response manually. It is an undetermined anomaly, not a confirmed finding.",
                        build(value), "GET", status="needs_input",
                    ))
                print(f"  fuzz={value[:16]!r:18} HTTP {fp.status} score={score:.1f}")
    disc = None
    if args.discover:
        print(f"[+] Discovering owned ids from the listing {args.collection_url} (one GET per identity)...")
        disc = discover_owned_ids(identities, args.collection_url, owner_fields, args.timeout, trail)
        identities = _with_discovered(identities, disc)
        for row in disc.per_identity:
            print(f"    {row['identity']}: {row['reason'] or str(row['ids']) + ' id(s) listed'}")
        print(f"    attributed: {sum(len(ids) for ids in disc.owns.values())} id(s); "
              f"ambiguous and not tested: {len(disc.ambiguous)}")
    if args.test_id:
        pair = [Identity("token-a", {args.auth_header: args.token_a}, [args.test_id]),
                Identity("token-b", {args.auth_header: args.token_b}, [])]
        found, run = run_matrix_with_recheck(args.url, pair, owner_fields, args.timeout, trail,
                                             scope="test-id", recheck=recheck)
        findings.extend(found)
        runs.append(run)
        _print_recheck(run)
    if identities and any(i.owns for i in identities):
        print(f"[+] Running authorization matrix across {len(identities)} identities (read-only)...")
        found, run = run_matrix_with_recheck(args.url, identities, owner_fields, args.timeout, trail,
                                             scope="matrix", recheck=recheck)
        if disc is not None:
            annotate_discovered(found, disc.sources)
        findings.extend(found)
        runs.append(run)
        _print_recheck(run)
        print(f"    {sum(f.check == 'authorization-boundary' for f in found)} confirmed, "
              f"{sum(f.check == 'authorization-undetermined' for f in found)} undetermined, "
              f"{sum(f.check == 'authorization-incomplete' for f in found)} incomplete")
    if args.stateful:
        note = f" and {len(actions)} POST action(s)" if actions else ""
        print(f"[+] Running stateful create-then-cross-access flow (writes to the target){note}...")
        slog: list[dict[str, Any]] = []
        stateful = run_stateful_flow(args.collection_url, args.url, identities, create_body, args.timeout,
                                     allow_destructive=True, owner_fields=owner_fields, log=slog, recheck=recheck,
                                     actions=actions)
        findings.extend(stateful)
        trail.extend(slog)
        runs.append(_stateful_recheck_run(stateful, recheck))
        _print_recheck(runs[-1])
        print(f"    {len(slog)} request(s), {len(stateful)} result(s)")

    extra: dict[str, Any] = {"recheck": recheck_report(recheck, runs)}
    if disc is not None:
        extra["discovery"] = disc.summary()
    return _conclude(args, identities, findings, trail, args.url, base, extra)


if __name__ == "__main__":
    raise SystemExit(cli())
