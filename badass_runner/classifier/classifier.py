"""Heuristic AI request classifier for Local Runner recorder sessions.

Architecture
------------
* Pure Python — no LLM, no cloud call, no external dependencies.
* Accepts ``Capture`` dataclass instances (in-memory) **or** raw dicts
  loaded from JSONL storage — normalised on entry.
* ``classify_capture`` scores a single request/response pair.
* ``classify_session`` scores all captures and returns the highest-confidence
  candidate plus the full result list.

Scoring (raw points, capped at MAX_SCORE=100, then divided to 0.0–1.0)
-----------------------------------------------------------------------
  POST method              +25   form-urlencoded CT         +8
  JSON content-type        +15   non-HTML response CT       +5
  Prompt field detected    +30   AI keyword in path         +10
  Response field detected  +20
  Generated-text bonus     +15   (additive with response field)

Hard exclusions (confidence = 0, ``likely_ai`` = False immediately)
--------------------------------------------------------------------
  * Static asset extension in path (.css .js .png …)
  * Exact health-check path (/health /ping /metrics …)
  * Response content-type is HTML, CSS, JS, image, font, or octet-stream

False-positive handling
-----------------------
  A plain POST JSON endpoint with no AI field names scores only 40/100 = 0.40,
  which falls below AI_CONFIDENCE_THRESHOLD (0.50).  A real AI endpoint that has
  both a prompt field and a response field scores ≥ 0.70.
  The generated-text bonus (+15) only fires when the response field value is a
  multi-word string of ≥ 20 chars — it does not trigger on IDs or short values.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROMPT_FIELDS: frozenset = frozenset({
    "message",
    "messages",
    "prompt",
    "query",
    "input",
    "question",
    "text",
    "user_input",
    "content",
    "user_message",
    "human",
})

RESPONSE_FIELDS: frozenset = frozenset({
    "response",
    "reply",
    "answer",
    "output",
    "result",
    "completion",
    "generated_text",
    "choices",
    "text",
    "content",
    "assistant",
    "bot_message",
})

_STATIC_EXTENSIONS: frozenset = frozenset({
    ".css", ".js", ".jsx", ".ts", ".tsx",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".html", ".htm", ".pdf",
})

_HEALTH_PATHS_EXACT: frozenset = frozenset({
    "/health", "/healthz", "/ping", "/ready", "/alive",
    "/favicon.ico", "/metrics", "/robots.txt", "/status",
})

_NON_AI_RESPONSE_CT_PREFIXES: tuple = (
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "image/",
    "font/",
    "application/octet-stream",
)

_AI_PATH_RE = re.compile(
    r"(chat|complet|generat|predict|infer|ask|answer|prompt|message|"
    r"query|llm|ai|nlp|gpt|bert|embed|assistant|completions)",
    re.IGNORECASE,
)

# Scoring weights
_W_POST = 25
_W_JSON_CT = 15
_W_FORM_CT = 8
_W_PROMPT_FIELD = 30
_W_RESPONSE_FIELD = 20
_W_GENERATED_TEXT = 15
_W_NON_HTML_RESP = 5
_W_AI_PATH = 10
MAX_SCORE = 100

AI_CONFIDENCE_THRESHOLD = 0.50


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    likely_ai: bool
    confidence: float
    detected_prompt_field: Optional[str]
    detected_response_field: Optional[str]
    method: str
    path: str
    content_type: str
    response_preview: str


@dataclass
class SessionClassification:
    best: Optional[ClassificationResult]
    all_results: List[ClassificationResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise(capture: Any) -> tuple:
    """Return (req_dict, resp_dict) regardless of whether capture is a
    ``Capture`` dataclass or a plain dict loaded from JSONL."""
    if hasattr(capture, "request"):
        req = capture.request or {}
        resp = capture.response or {}
    else:
        req = capture.get("request") or {}
        resp = capture.get("response") or {}
    return req, resp


def _ext(path: str) -> str:
    """Return lowercase file extension from path, stripping query/fragment."""
    bare = path.split("?")[0].split("#")[0]
    dot = bare.rfind(".")
    slash = bare.rfind("/")
    return bare[dot:].lower() if dot > slash else ""


def _is_static(path: str) -> bool:
    return _ext(path) in _STATIC_EXTENSIONS


def _is_health_check(path: str) -> bool:
    return path.lower().rstrip("/") in _HEALTH_PATHS_EXACT


def _response_ct_excluded(ct: str) -> bool:
    ct_low = (ct or "").lower()
    return any(ct_low.startswith(p) for p in _NON_AI_RESPONSE_CT_PREFIXES)


def _parse_json_fields(snippet: str) -> Dict[str, Any]:
    """Try to parse snippet as JSON; return the top-level dict or {}."""
    if not snippet:
        return {}
    try:
        obj = json.loads(snippet)
        if isinstance(obj, dict):
            return obj
    except (ValueError, json.JSONDecodeError):
        pass
    return {}


def _parse_form_fields(snippet: str) -> Dict[str, Any]:
    """Parse application/x-www-form-urlencoded body snippet."""
    if not snippet:
        return {}
    try:
        parsed = parse_qs(snippet, keep_blank_values=False)
        return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}
    except Exception:
        return {}


def _find_field(body: Dict[str, Any], candidates: frozenset) -> Optional[str]:
    """Return the first matching candidate key (case-insensitive), or None."""
    lower_map = {k.lower(): k for k in body}
    for candidate in sorted(candidates):
        if candidate in lower_map:
            return lower_map[candidate]
    return None


def _looks_like_generated_text(value: Any) -> bool:
    """Return True if *value* looks like a genuine natural-language output."""
    if isinstance(value, list):
        if not value:
            return False
        first = value[0]
        if isinstance(first, dict):
            value = (
                first.get("text")
                or first.get("content")
                or (first.get("message") or {}).get("content")
                or str(first)
            )
        else:
            value = str(first)
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if len(stripped) < 20:
        return False
    if len(stripped.split()) < 3:
        return False
    if stripped.startswith(("http://", "https://", "data:", "urn:")):
        return False
    return True


# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------

def _build_result(
    score: int,
    method: str,
    path: str,
    content_type: str,
    response_preview: str,
    prompt_field: Optional[str],
    response_field: Optional[str],
) -> ClassificationResult:
    confidence = round(min(score / MAX_SCORE, 1.0), 4)
    return ClassificationResult(
        likely_ai=confidence >= AI_CONFIDENCE_THRESHOLD,
        confidence=confidence,
        detected_prompt_field=prompt_field,
        detected_response_field=response_field,
        method=method,
        path=path,
        content_type=content_type,
        response_preview=response_preview,
    )


def classify_capture(capture: Any) -> ClassificationResult:
    """Score a single capture and return a :class:`ClassificationResult`.

    *capture* may be a ``Capture`` dataclass instance (in-memory session) or a
    plain dict loaded from JSONL storage — both are normalised transparently.
    """
    req, resp = _normalise(capture)

    method = (req.get("method") or "GET").upper()
    path = req.get("path") or "/"
    req_ct = req.get("content_type") or ""
    body_snippet = req.get("body_snippet") or ""
    resp_ct = resp.get("content_type") or ""
    resp_preview = (resp.get("body_snippet") or "")[:200]

    # ---- hard exclusions ------------------------------------------------
    if _is_static(path) or _is_health_check(path) or _response_ct_excluded(resp_ct):
        return _build_result(0, method, path, req_ct, resp_preview, None, None)

    score = 0

    # ---- method ---------------------------------------------------------
    if method == "POST":
        score += _W_POST

    # ---- request content-type -------------------------------------------
    req_ct_low = req_ct.lower()
    is_json = "application/json" in req_ct_low
    is_form = "application/x-www-form-urlencoded" in req_ct_low

    if is_json:
        score += _W_JSON_CT
    elif is_form:
        score += _W_FORM_CT

    # ---- body field detection -------------------------------------------
    if is_json:
        req_fields = _parse_json_fields(body_snippet)
    elif is_form:
        req_fields = _parse_form_fields(body_snippet)
    else:
        req_fields = {}

    prompt_field = _find_field(req_fields, PROMPT_FIELDS)
    if prompt_field:
        score += _W_PROMPT_FIELD

    # ---- response field detection ---------------------------------------
    resp_fields = _parse_json_fields(resp_preview)
    response_field = _find_field(resp_fields, RESPONSE_FIELDS)
    if response_field:
        score += _W_RESPONSE_FIELD
        if _looks_like_generated_text(resp_fields.get(response_field)):
            score += _W_GENERATED_TEXT

    # ---- response content-type signal -----------------------------------
    if resp_ct and not resp_ct.lower().startswith("text/html"):
        score += _W_NON_HTML_RESP

    # ---- AI keyword in path ---------------------------------------------
    if _AI_PATH_RE.search(path):
        score += _W_AI_PATH

    return _build_result(score, method, path, req_ct, resp_preview, prompt_field, response_field)


# ---------------------------------------------------------------------------
# Session-level classifier
# ---------------------------------------------------------------------------

def classify_session(captures) -> SessionClassification:
    """Classify all captures in *captures* and return a :class:`SessionClassification`.

    The ``best`` field is the highest-confidence ``likely_ai`` result, or the
    overall highest-confidence result when no capture clears the threshold.
    """
    if not captures:
        return SessionClassification(best=None, all_results=[])

    results = [classify_capture(c) for c in captures]
    ai_results = [r for r in results if r.likely_ai]
    pool = ai_results if ai_results else results
    best = max(pool, key=lambda r: r.confidence)
    return SessionClassification(best=best, all_results=results)
