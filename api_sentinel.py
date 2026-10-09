#!/usr/bin/env python3
"""
API Sentinel - authorization (BOLA) regression testing for authorized environments.

Authorized testing only. This tool compares API behavior across controlled
requests and produces evidence-oriented findings. A finding is a lead, not
proof of a vulnerability.
"""

from __future__ import annotations
import argparse, json, math, statistics, sys, time
import http.client, re, traceback
import urllib.error, urllib.request
from dataclasses import dataclass, asdict, field
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


__version__ = "0.2.0"
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

EXIT_OK, EXIT_POLICY, EXIT_CONFIG, EXIT_INCOMPLETE, EXIT_TRANSPORT, EXIT_INTERNAL, EXIT_UNDETERMINED = 0, 1, 2, 3, 4, 5, 6


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


def request(method: str, url: str, headers: dict[str, str] | None = None,
            data: bytes | None = None, timeout: float = 15) -> ResponseFP:
    headers = headers or {}
    method = method.upper()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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
            headers={str(k): str(v) for k, v in item.get("headers", {}).items()},
            owns=[str(x) for x in item.get("owns", [])],
            params={str(k): str(v) for k, v in params.items()},
            owner_values=dict(owner_values),
        ))
    if len(out) < 2:
        raise ConfigError("identities file needs at least two identities to run cross-account checks")
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
_ENVELOPE_KEYS = ("data", "result", "item", "order", "resource")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_STATEFUL_VERBS = ("GET", "PATCH", "DELETE")


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
    if isinstance(body, dict) and not any(k in body for k in _RESOURCE_ID_KEYS):
        for key in _ENVELOPE_KEYS:
            if isinstance(body.get(key), dict):
                return body[key]
    return body


def _identifies(body: Any, resource_id: str) -> bool:
    return isinstance(body, dict) and any(
        key in body and str(body[key]) == str(resource_id) for key in _RESOURCE_ID_KEYS)


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
            + ", ".join(f"{f} is {o[f]!r} in the record but {owner.owner_values[f]!r} was declared" for f in conflicts)])
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
    if not _ok(fp):
        why = f"the owner's own request returned HTTP {fp.status}"
    elif "json" not in fp.content_type.lower():
        why = f"the owner's response is {fp.content_type or 'untyped'}, not JSON, so the check cannot be evaluated"
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
                             owner_fields: list[str], timeout: float
                             ) -> tuple[list[Finding], list[dict[str, Any]]]:
    """For every resource an identity owns, request it as every other identity and judge what comes back.

    The matrix is read-only: it only ever sends GET. Write verbs are covered by run_stateful_flow, which creates
    its own resources and needs an explicit opt-in. Returns (findings, log) where log has one entry per request.
    """
    if method.upper() != "GET":
        raise ConfigError(f"the authorization matrix is read-only and only sends GET (got {method.upper()}). "
                          "Write verbs are tested by --stateful, which creates its own resources and needs "
                          "--allow-destructive.")
    collection = "{id}" not in url_template
    findings: list[Finding] = []
    log: list[dict[str, Any]] = []
    for owner in identities:
        for resource_id in owner.owns:
            rid = None if collection else resource_id
            owner_url = fill_url(url_template, owner, rid)
            owner_fp = request("GET", owner_url, owner.headers, timeout=timeout)
            owner_body = _safe_json(owner_fp)
            log.append({"kind": "owner_baseline", "owner": owner.name, "resource_id": resource_id,
                        "url": owner_url, "status": owner_fp.status, "size": owner_fp.size})
            if not _owner_baseline_ok(owner_fp, owner_body, resource_id, collection):
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
                    if collection:
                        judgement = _judge_collection_item(resource_id, owner, owner_body, body, owner_fields,
                                                           _ok(fp))
                    elif isinstance(owner_body, list) or isinstance(body, list):
                        judgement = _judge_list(owner_body, body)
                    else:
                        judgement = _judge_record(resource_id, owner, owner_body, body, owner_fields, _ok(fp))
                    findings.extend(_judgement_findings(judgement, owner, accessor, resource_id, fp, url,
                                                        "GET", owner_fp.status))
    return findings, log


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


def _write_undetermined(verb: str, url: str, owner: Identity, accessor: Identity, rid: str,
                        reason: str) -> Finding:
    return Finding(
        check="authorization-undetermined", severity="info", confidence="low", score=0.0,
        evidence=[f"'{accessor.name}' tried {verb} on resource_id={rid} of '{owner.name}': {reason}"],
        recommendation="Re-read the resource once the operation completes, or declare a probe field in the "
                       "record, then re-run.",
        endpoint=url, method=verb, status="needs_input",
        details={"class": "BOLA / Broken Object Level Authorization", "owner_identity": owner.name,
                 "accessing_identity": accessor.name, "resource_id": rid},
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


def _stateful_attempt(verb: str, url: str, rid: str, creator: Identity, attacker: Identity, creator_url: str,
                      owner_status: int, pre_raw: Any, pre: Any, fields: list[str], timeout: float,
                      trail: list[dict[str, Any]]) -> list[Finding]:
    if verb == "GET":
        fp = request("GET", url, attacker.headers, timeout=timeout)
        trail.append(_entry("attempt", "GET", url, fp, rid, creator, attacker))
        judgement = _judge_record(rid, creator, pre_raw, _safe_json(fp), fields, _ok(fp))
        return _judgement_findings(judgement, creator, attacker, rid, fp, url, "GET", owner_status,
                                   leak_check="stateful-authorization-boundary")
    if verb == "PATCH":
        payload = _probe_payload(pre)
        if payload is None:
            return [_write_undetermined(verb, url, creator, attacker, rid,
                                        "the record has neither a 'total' nor an 'item' field to probe, so no write "
                                        "was sent")]
        fp = request("PATCH", url, {**attacker.headers, "Content-Type": "application/json"},
                     data=json.dumps(payload).encode(), timeout=timeout)
        trail.append(_entry("attempt", "PATCH", url, fp, rid, creator, attacker))
        after_fp = request("GET", creator_url, creator.headers, timeout=timeout)
        trail.append(_entry("verify", "GET", creator_url, after_fp, rid, creator, attacker))
        changed = _applied(pre, _unwrap(_safe_json(after_fp)), payload)
        what = f"PATCH {json.dumps(payload)}"
    else:  # DELETE
        fp = request("DELETE", url, attacker.headers, timeout=timeout)
        trail.append(_entry("attempt", "DELETE", url, fp, rid, creator, attacker))
        after_fp = request("GET", creator_url, creator.headers, timeout=timeout)
        trail.append(_entry("verify", "GET", creator_url, after_fp, rid, creator, attacker))
        changed = after_fp.status in (404, 410)
        what = "DELETE"
    details = {"class": "BOLA / Broken Object Level Authorization", "owner_identity": creator.name,
               "accessing_identity": attacker.name, "resource_id": rid, "http_status": fp.status,
               "response_bytes": fp.size, "workflow": "create-then-cross-access"}
    if changed:
        effect = "the change is visible in the owner's record" if verb == "PATCH" else "the resource is gone"
        return [Finding(
            check="stateful-authorization-boundary", severity="critical", confidence="high", score=90.0,
            evidence=[f"'{attacker.name}' sent {what} for resource_id={rid} (HTTP {fp.status})",
                      f"the owner's own read afterwards shows the effect: {effect}",
                      "judged from the owner's record, not from the status code",
                      f"expected: a non-owner's {verb} must be rejected before it takes effect"],
            recommendation="Verify server-side ownership checks on this verb: a non-owner write must be rejected "
                           "before it takes effect.",
            endpoint=url, method=verb, status="confirmed", details=details)]
    if fp.status == 202:
        return [_write_undetermined(verb, url, creator, attacker, rid,
                                    "HTTP 202 was accepted but the owner's record has not changed yet; the effect "
                                    "may be asynchronous")]
    if _ok(fp):
        return [Finding(
            check="stateful-no-effect", severity="info", confidence="high", score=0.0,
            evidence=[f"{what} by '{attacker.name}' returned HTTP {fp.status}, but the owner's record did not "
                      "change: no unauthorized modification was observed"],
            recommendation="No action: a success status without an effect is not reported as a finding.",
            endpoint=url, method=verb, status="no_effect", details=details)]
    return []


def run_stateful_flow(collection_url: str, item_url_template: str, identities: list[Identity],
                      create_body: dict[str, Any], timeout: float, allow_destructive: bool = False,
                      owner_fields: list[str] | None = None,
                      log: list[dict[str, Any]] | None = None) -> list[Finding]:
    """Create a resource as the first identity. For every other identity and every verb, create a fresh copy
    and try the verb on it. Reads are judged like matrix reads. Writes are judged by the owner's own read
    afterwards, so neither a 2xx nor a 403 on a write is evidence on its own. Each created resource is removed
    afterwards if it still exists. Every request is appended to `log` when a list is given.
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
        for verb in _STATEFUL_VERBS:
            for template in _url_variant_templates(item_url_template, creator, attacker):
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
                    findings.extend(_stateful_attempt(verb, url, rid, creator, attacker, creator_url,
                                                      pre_fp.status, pre_raw, pre, fields, timeout, trail))
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
    findings_html = "\n".join(rows) if rows else "<p>No confirmed findings, undetermined results or incomplete checks.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>API Sentinel Report - {esc(report['target'])}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; background:#0b1020; color:#e2e8f0; margin:0; padding:2rem; }}
  h1 {{ color:#f8fafc; margin-bottom:.25rem; }}
  .meta-top {{ color:#94a3b8; margin:.25rem 0; }}
  .finding {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:1.25rem 1.5rem; margin-bottom:1rem; }}
  .badge {{ color:white; font-size:.7rem; padding:.15rem .5rem; border-radius:999px; margin-right:.5rem; letter-spacing:.03em; }}
  .meta {{ color:#94a3b8; font-size:.85rem; margin:.25rem 0; }}
  ul {{ margin:.5rem 0; padding-left:1.25rem; }}
  li {{ margin:.2rem 0; }}
  .rec {{ color:#cbd5e1; margin-top:.75rem; }}
  .disclaimer {{ margin-top:2rem; color:#64748b; font-size:.8rem; border-top:1px solid #1f2937; padding-top:1rem; }}
</style></head>
<body>
  <h1>API Sentinel Report</h1>
  <p class="meta-top">Target: {esc(report['target'])} &middot; Status: {esc(report['status'])} &middot; Generated: {esc(report['generated_at'])}</p>
  <p class="meta-top">Confirmed: {summary['confirmed']} &middot; Undetermined: {summary['undetermined']} &middot; Incomplete: {summary['incomplete']} &middot; Residue: {summary['residue']}</p>
  <p class="meta-top">Checks run: {cov['checks_run']} &middot; Passed: {cov['passed']} &middot; Requests sent: {cov['requests_sent']} &middot; Owned resources tested: {cov['owned_resources_tested']}</p>
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


def make_report(target: str, baseline: dict[str, Any] | None, findings: list[Finding],
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


def cli(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="api-sentinel",
        description="Authorization (BOLA) regression testing for authorized environments. Compares what two or more "
                    "controlled identities can read, and reports behavioral evidence.",
        epilog="exit codes: 0 clean; 1 confirmed finding at/above --fail-on; 2 configuration problem or refused "
               "operation; 3 incomplete (setup or baseline failed, checks not run); 4 transport failure; "
               "5 internal error; 6 undetermined (results need human review)",
    )
    p.add_argument("--yes-i-am-authorized", action="store_true",
                   help="Required. Attests that you are authorized to test the target. A guard against accidental "
                        "runs, not a security control.")
    p.add_argument("--url", help="URL template containing {id}, e.g. https://localhost:8000/orders/{id}. Other "
                                 "{names} are filled from identity 'params', e.g. /users/{user_id}/orders/{id}.")
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
                                        "owner_values)")
    p.add_argument("--ownership-fields", default=",".join(OWNER_FIELDS_DEFAULT),
                   help="Comma-separated response field names treated as ownership signals")
    p.add_argument("--stateful", action="store_true",
                   help="Also run the create-then-cross-access flow (needs --identities, --collection-url and "
                        "--allow-destructive)")
    p.add_argument("--collection-url", help="Collection URL for POST in the stateful flow, e.g. "
                                            "https://localhost:8000/orders")
    p.add_argument("--create-body", default='{"item": "API Sentinel test item", "total": 9.99}',
                   help="JSON object used to create a resource in the stateful flow")
    p.add_argument("--output", default="api-sentinel-report.json")
    p.add_argument("--html-output", help="Optional path to also write an HTML report")
    p.add_argument("--sarif-output", help="Optional path to also write a SARIF 2.1.0 report (confirmed findings only)")
    p.add_argument("--fail-on", choices=["none", "high", "critical"], default="high",
                   help="Exit 1 when a confirmed finding is at or above this severity (default: high). 'none' reports "
                        "without failing: confirmed findings then do not change the exit code")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--debug", action="store_true", help="Show tracebacks for errors")
    args = p.parse_args(argv)
    try:
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


def _coverage(identities: list[Identity], findings: list[Finding], trail: list[dict[str, Any]]) -> dict[str, Any]:
    """What was actually exercised. 'passed' = checks that produced no confirmed and no undetermined result."""
    accessor = [e for e in trail if e.get("kind") == "accessor"]
    attempts = [e for e in trail if e.get("kind") == "attempt"]
    owned_ok = [e for e in trail if e.get("kind") == "owner_baseline" and 200 <= e["status"] < 300]
    checks_run = len(accessor) + len(attempts)
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

    if args.openapi:
        try:
            doc = load_openapi(args.openapi)
        except (OSError, ValueError) as e:
            raise ConfigError(f"OpenAPI error: {e}") from None
        if args.graph:
            print(format_graph(infer_resource_graph(doc)))
        else:
            paths = discover_paths(doc)
            print(f"Discovered {len(paths)} operations:")
            for x in paths:
                print(f"  {x['method']:6} {x['path']}  {x['operation_id']}")
        return EXIT_OK

    if not args.url:
        raise ConfigError("--url is required unless --openapi is used")
    if args.method.upper() != "GET":
        raise ConfigError(f"--method {args.method.upper()} is not supported: baseline, fuzz and authorization checks "
                          "are read-only. Write verbs are tested only by --stateful, which needs --allow-destructive.")
    if args.stateful and not args.allow_destructive:
        raise DestructiveOperationRefused("--stateful creates, modifies and deletes resources on the target. "
                                          "Re-run with --allow-destructive only against a disposable environment.")
    if args.allow_destructive and not args.stateful:
        print("[!] --allow-destructive has no effect without --stateful", file=sys.stderr)
    if args.stateful:
        print("[!] --stateful: create, PATCH and DELETE requests will be sent to the target", file=sys.stderr)

    values = [x.strip() for x in args.baseline_ids.split(",") if x.strip()] if args.baseline_ids else []
    if args.baseline_ids and len(values) < 3:
        raise ConfigError("--baseline-ids needs at least 3 values")
    if args.fuzz and not values:
        raise ConfigError("--fuzz needs --baseline-ids: fuzz results are compared against the baseline")
    if args.test_id and not (args.token_a and args.token_b):
        raise ConfigError("--test-id needs both --token-a and --token-b")
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
    if identities and not args.stateful and not any(i.owns for i in identities):
        raise ConfigError("the identities file declares no 'owns' resources, so there is nothing to test; list the "
                          "resource ids each identity owns, or use --stateful")
    if not (args.test_id or args.stateful or any(i.owns for i in identities)):
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
    if args.test_id:
        pair = [Identity("token-a", {args.auth_header: args.token_a}, [args.test_id]),
                Identity("token-b", {args.auth_header: args.token_b}, [])]
        found, mlog = run_authorization_matrix(args.url, pair, "GET", owner_fields, args.timeout)
        findings.extend(found)
        trail.extend(mlog)
    if identities and any(i.owns for i in identities):
        print(f"[+] Running authorization matrix across {len(identities)} identities (read-only)...")
        found, mlog = run_authorization_matrix(args.url, identities, "GET", owner_fields, args.timeout)
        findings.extend(found)
        trail.extend(mlog)
        print(f"    {sum(f.check == 'authorization-boundary' for f in found)} confirmed, "
              f"{sum(f.check == 'authorization-undetermined' for f in found)} undetermined, "
              f"{sum(f.check == 'authorization-incomplete' for f in found)} incomplete")
    if args.stateful:
        print("[+] Running stateful create-then-cross-access flow (writes to the target)...")
        slog: list[dict[str, Any]] = []
        stateful = run_stateful_flow(args.collection_url, args.url, identities, create_body, args.timeout,
                                     allow_destructive=True, owner_fields=owner_fields, log=slog)
        findings.extend(stateful)
        trail.extend(slog)
        print(f"    {len(slog)} request(s), {len(stateful)} result(s)")

    coverage = _coverage(identities, findings, trail)
    incomplete = [f for f in findings if f.status in ("setup_failed", "skipped")]
    residue = [f for f in findings if f.status == "residue"]
    undetermined = [f for f in findings if f.status == "needs_input"]
    confirmed = [f for f in findings if f.check in BOLA_CHECKS]
    status = "incomplete" if incomplete else "complete"
    report = make_report(args.url, base, findings, coverage, status)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Report: {args.output}")
    if args.html_output:
        Path(args.html_output).write_text(render_html(report), encoding="utf-8")
        print(f"[+] HTML report: {args.html_output}")
    if args.sarif_output:
        artifact = args.identities or args.output
        Path(args.sarif_output).write_text(json.dumps(render_sarif(report, artifact), indent=2), encoding="utf-8")
        print(f"[+] SARIF report: {args.sarif_output}")

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


if __name__ == "__main__":
    raise SystemExit(cli())
