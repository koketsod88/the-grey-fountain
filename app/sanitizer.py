import re

SENSITIVE_PATTERNS = [
    (
        re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;\"']+)"),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
        r"\1[REDACTED]",
    ),
]


def sanitize_text(value: str) -> str:
    sanitized = value
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_payload(obj: object) -> object:
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    if isinstance(obj, dict):
        return {k: sanitize_payload(v) for k, v in obj.items()}
    return obj
