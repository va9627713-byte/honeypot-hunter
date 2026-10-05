"""Non-executing sample triage and opt-in handoff to an isolated analyzer."""

import hashlib
import math
import re
import urllib.request
from collections import Counter
from urllib.parse import urlsplit

MAX_SAMPLE_SIZE = 2 * 1024 * 1024
_ASCII_STRINGS = re.compile(rb"[ -~]{6,}")
_URL = re.compile(r"https?://[^\s'\"<>]{1,200}", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_STATIC_MARKERS = (
    b"powershell",
    b"base64",
    b"chmod +x",
    b"/dev/tcp/",
    b"curl ",
    b"wget ",
    b"eval(",
    b"cmd.exe",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


def analyze_sample(data: bytes) -> dict:
    """Summarize attacker-supplied bytes without writing or executing them."""
    if len(data) > MAX_SAMPLE_SIZE:
        raise ValueError(f"Sample exceeds the {MAX_SAMPLE_SIZE}-byte limit")

    if data.startswith(b"\x7fELF"):
        file_type = "ELF"
    elif data.startswith(b"MZ"):
        file_type = "PE/DOS"
    elif data.startswith(b"#!"):
        file_type = "script"
    elif data.startswith(b"PK\x03\x04"):
        file_type = "ZIP"
    elif data.startswith(b"\x1f\x8b"):
        file_type = "gzip"
    else:
        file_type = "unknown"

    frequencies = Counter(data)
    entropy = -sum(
        (count / len(data)) * math.log2(count / len(data))
        for count in frequencies.values()
    ) if data else 0.0

    # Extract ALL strings, then cap the output list
    all_strings = [
        match[:200].decode("ascii", errors="replace")
        for match in _ASCII_STRINGS.findall(data)
    ]
    strings = all_strings[:20]

    # Search all strings for URLs and IPs, not just first 20
    printable = "\n".join(all_strings)
    urls = sorted(set(_URL.findall(printable)))[:20]
    ips = sorted(set(_IPV4.findall(printable)))[:20]

    # Compute lower once for marker matching
    data_lower = data.lower()
    markers = [
        marker.decode("ascii")
        for marker in _STATIC_MARKERS
        if marker.lower() in data_lower
    ]
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "file_type": file_type,
        "entropy": round(entropy, 3),
        "strings": strings,
        "urls": urls,
        "ipv4_candidates": ips,
        "static_markers": markers,
        "execution_performed": False,
    }


def validate_sandbox_url(url: str) -> None:
    """Validate a deliberately configured analyzer endpoint."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("sandbox_submit_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("sandbox_submit_url must not contain credentials or a fragment")


def submit_to_sandbox(url: str, data: bytes, token: str = None) -> int:
    """POST sample bytes to the explicitly configured isolated analyzer endpoint."""
    validate_sandbox_url(url)
    parsed = urlsplit(url)
    if token and parsed.scheme == "http":
        raise ValueError("Refusing to send bearer token over plain HTTP")
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Sample-SHA256": hashlib.sha256(data).hexdigest(),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirectHandler())
    with opener.open(request, timeout=10) as response:
        return response.status
