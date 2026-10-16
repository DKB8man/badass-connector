"""Capture-owned pairing metadata, separate from credential sanitization."""


def strip_pairing_metadata(value):
    """Discard target provenance before reply extraction or call processing."""
    if isinstance(value, dict):
        return {
            key: strip_pairing_metadata(item) for key, item in value.items()
            if key not in {"occurrence_basis", "native_pairing_basis", "classifier_facts"}
        }
    if isinstance(value, list):
        return [strip_pairing_metadata(item) for item in value]
    return value


def capture_native_calls(native, detail):
    """Return calls and turn-level basis; pairing is intact or absent."""
    native, detail = strip_pairing_metadata(native), strip_pairing_metadata(detail)
    if not isinstance(native, list):
        return None, None
    if native and all(isinstance(name, str) for name in native):
        if (
            not isinstance(detail, list) or len(native) != len(detail)
            or any(
                not name.strip() or not isinstance(entry, dict)
                or entry.get("name") != name
                for name, entry in zip(native, detail)
            )
        ):
            return None, None
        return [
            {"name": name, "arguments": entry.get("arguments", {})}
            for name, entry in zip(native, detail)
        ], "positional"
    return [
        {key: value for key, value in entry.items() if key != "classifier_facts"}
        for entry in native if isinstance(entry, dict)
    ] or None, None


def pairing_metadata(turn):
    """One closed public enum; never copy arbitrary target or uploaded text."""
    value = turn.get("native_pairing_basis")
    return {"native_pairing_basis": "positional"} if (
        isinstance(value, str) and value == "positional"
    ) else {}


def prepare_turns_for_upload(turns, *args, **kwargs):
    """Sanitize content unchanged, then attach separately validated metadata."""
    from .sanitize import sanitize_turns
    safe = sanitize_turns(turns, *args, **kwargs)
    return [{**turn, **pairing_metadata(original)}
            for turn, original in zip(safe, turns)]
