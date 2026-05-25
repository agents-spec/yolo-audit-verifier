"""
verifier/canon.py — payload canonicalization for the Yolo audit verifier (P0.3).

Reproduces the Yolo server's canonicalization byte-for-byte so that a
client-side recompute of payload_hash matches what was anchored on Base. Two versions,
selected per entry by `canon_version`:

  v2  = RFC 8785 (JSON Canonicalization Scheme). Uses a GENUINE JCS library (rfc8785) — NOT
        json.dumps(sort_keys=True), which sorts keys by Unicode code POINT (JCS requires
        UTF-16 code UNIT order) and formats numbers differently (e.g. floats as "1.0", no
        ECMAScript shortest-form). rfc8785.dumps gives ECMAScript-conformant primitive
        serialization + UTF-16 code-unit key sort + minimal encoding == the server's v2.

  v1  = legacy. The server's v1 is JS `JSON.stringify(payload, Object.keys(payload).sort())`.
        The array argument is a recursive key ALLOWLIST, so only keys present in the sorted
        TOP-LEVEL key list survive — at EVERY nesting level (the documented v1 bug: nested
        objects whose keys aren't top-level names collapse to {}). We reproduce it as
        rfc8785.dumps(deep_filter(payload, allowlist=top_level_keys)): after filtering, JCS's
        UTF-16 sort equals the legacy allowlist order and JCS primitive formatting equals
        JSON.stringify, so ONE library serves both versions — canon_version only decides
        whether to pre-filter. NULL/absent canon_version is treated as v1 (matches verifyChain).
"""
import hashlib
import rfc8785


def _deep_filter(value, allowlist):
    """Mirror JS JSON.stringify's array-replacer: at EVERY object level, keep only keys that
    are in `allowlist` (the sorted top-level key set). Arrays recurse into elements; primitives
    pass through unchanged. rfc8785 re-sorts the survivors, which equals the legacy order."""
    if isinstance(value, dict):
        return {k: _deep_filter(v, allowlist) for k, v in value.items() if k in allowlist}
    if isinstance(value, list):
        return [_deep_filter(v, allowlist) for v in value]
    return value


def canonical_bytes(payload: dict, canon_version) -> bytes:
    """UTF-8 canonical bytes for `payload`, byte-for-byte identical to the server."""
    if canon_version == "v2":
        return rfc8785.dumps(payload)
    # NULL / "v1" → legacy allowlist (top-level keys), then JCS.
    allowlist = set(payload.keys())
    return rfc8785.dumps(_deep_filter(payload, allowlist))


def payload_hash(payload: dict, canon_version) -> str:
    """SHA-256 hex of the canonical bytes — must equal the stored payload_hash."""
    return hashlib.sha256(canonical_bytes(payload, canon_version)).hexdigest()
