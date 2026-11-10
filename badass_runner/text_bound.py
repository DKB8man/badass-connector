"""Complete-input redaction followed by a marker-safe, suffix-inclusive bound.

Mirrored byte-for-byte between the two execution codebases. Keep domain
redactors at their own boundary; this module must not guess their policies.
Admission readers must reject overflow, never pass a partial segment here.
"""
import re


_MARKER = re.compile(r"\[(?:REDACTED[^\]]*|PLANTED:[^\]]*|LINK:[^\]]*|#[0-9a-f]{6})\]", re.I)


def redact_before_bound(value, limit=None, *, redactor, suffix="…", start=0):
    """Redact the full admitted value once, then cut before any marker.

    ``None`` means no implicit cap. Zero means empty. The suffix is part of
    the budget and is only present when text was omitted at the right edge.
    ``start`` supports backend evidence windows; a start inside a marker
    skips the whole marker while retaining the original window's end.
    """
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("excerpt limit must be a non-negative integer")
    if type(start) is not int or start < 0:
        raise ValueError("excerpt start must be a non-negative integer")
    if not isinstance(suffix, str):
        raise ValueError("excerpt suffix must be text")
    text = "" if value is None else str(value)
    safe = redactor(text)
    if not isinstance(safe, str):
        raise TypeError("excerpt redactor must return text")
    end = len(safe) if limit is None else min(start + limit, len(safe))
    truncated = end < len(safe)
    tail = suffix if truncated else ""
    if limit is not None:
        tail = tail[:limit]
    end = max(start, end - len(tail))
    spans = []
    for marker in _MARKER.finditer(safe):
        left = marker.start()
        if marker.group().startswith("[#"):
            # Find a high/low correlatable prefix without a backtracking
            # ``\\S*...\\S*`` search on long dot-filled target responses.
            word_end = left
            while word_end and safe[word_end - 1].isspace():
                word_end -= 1
            word_start = word_end
            while word_start and not safe[word_start - 1].isspace():
                word_start -= 1
            if "..." in safe[word_start:word_end]:
                left = word_start
        spans.append((left, marker.end()))
    # A correlatable token may contain marker-like text itself. Visit the
    # outer span first so a nested bracket cannot leave its prefix behind.
    for left, right in sorted(spans, key=lambda span: (span[0], -span[1])):
        if left < start < right:
            start = right
        if left < end < right:
            end = left
            break
    return safe[start:max(start, end)] + tail
