#!/usr/bin/env python3
"""Read-only Soroban Testnet release preflight. Never signs or deploys contracts.

Run from the repository root after creating pinned reproducible artifacts.
An optional RPC probe verifies network identity and a fresh ledger, but does
NOT establish on-chain contract existence or operator authorization.
"""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from validate_manifest import validate as validate_manifest
from verify_artifacts import verify as verify_artifacts

PASSPHRASE = "Test SDF Network ; September 2015"
MAX_RPC_JSON = 64 * 1024


def valid_operator_address(address):
    if not isinstance(address, str) or not re.fullmatch(r"G[A-Z2-7]{55}", address):
        return False
    try:
        binary = base64.b32decode(address)
    except (ValueError, binascii.Error):
        return False
    return (len(binary) == 35 and binary[0] == 48
            and binascii.crc_hqx(binary[:33], 0).to_bytes(2, "little") == binary[33:])


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("RPC redirects are not allowed")


def require_rpc_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("RPC endpoint must be HTTPS with no URL query, embedded username or fragment")
    return url


def probe_rpc(url, *, now=None, opener=None):
    require_rpc_url(url)
    opener = opener or build_opener(NoRedirect())
    results = {}
    for method in ("getNetwork", "getLatestLedger"):
        payload = json.dumps({
            "jsonrpc": "2.0", "id": "stealthbridge-preflight",
            "method": method, "params": {}
        }).encode()
        request = Request(url, data=payload, method="POST", headers={
            "Accept": "application/json", "Content-Type": "application/json"
        })
        with opener.open(request, timeout=8) as response:
            size = response.headers.get("Content-Length")
            if size is not None and int(size) > MAX_RPC_JSON:
                raise ValueError("Oversized RPC response")
            raw = response.read(MAX_RPC_JSON + 1)
            if len(raw) > MAX_RPC_JSON:
                raise ValueError("Oversized RPC response")
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("jsonrpc") != "2.0"
                or data.get("id") != "stealthbridge-preflight"
                or data.get("error") is not None
                or not isinstance(data.get("result"), dict)):
            raise ValueError("Untrusted Stellar RPC response")
        results[method] = data["result"]
    if results["getNetwork"].get("passphrase") != PASSPHRASE:
        raise ValueError("RPC is not Stellar Testnet")
    ledger = results["getLatestLedger"]
    sequence = ledger.get("sequence")
    protocol = ledger.get("protocolVersion")
    close_time = ledger.get("closeTime")
    ledger_hash = ledger.get("id")
    if (type(sequence) is not int or sequence <= 0
            or type(protocol) is not int or protocol < 27
            or not isinstance(close_time, str) or not close_time.isdigit()
            or not isinstance(ledger_hash, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", ledger_hash) is None):
        raise ValueError("Invalid or incompatible Stellar ledger observation")
    when = int(time.time() if now is None else now)
    age = when - int(close_time)
    if age < -30 or age > 180:
        raise ValueError("Stellar ledger is stale or future-dated")
    return {"network": "testnet", "ledger_sequence": sequence,
            "protocol_version": protocol, "ledger_age_seconds": age}


def preflight(artifacts, manifest, operator=None, rpc_url=None, now=None, opener=None):
    # A v1 not-deployed manifest is deliberately kept until audited on-chain
    # evidence and three-contract manifest schema are separately approved.
    document = json.loads(Path(manifest).read_text())
    validate_manifest(document)
    if document["status"] != "not-deployed":
        raise ValueError("This preflight is only valid before an authorized deployment")
    count = verify_artifacts(artifacts)
    if count != 3:
        raise ValueError("Expected all three independently reproduced contracts")
    if operator is not None and not valid_operator_address(operator):
        raise ValueError("Operator must supply a valid classic Stellar G-account")
    result = {"artifacts_verified": count, "manifest": "not-deployed",
              "wallet_signing": "not-requested", "payment_execution": "disabled"}
    if rpc_url is not None:
        result["testnet_rpc"] = probe_rpc(rpc_url, now=now, opener=opener)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--manifest", type=Path, default=Path("deployments/testnet/manifest.json"))
    parser.add_argument("--operator", help="Public G-address only. Never supply a secret key.")
    parser.add_argument("--rpc-url", help="Optional public HTTPS Stellar Testnet RPC endpoint; not printed")
    parser.add_argument("--rpc-url-env", help="Environment variable name holding private RPC URL; keeps token out of command arguments")
    args = parser.parse_args()
    try:
        if args.rpc_url and args.rpc_url_env:
            raise ValueError("Choose only one RPC configuration method")
        if args.rpc_url_env and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", args.rpc_url_env):
            raise ValueError("Invalid RPC environment-variable name")
        rpc_url = os.environ.get(args.rpc_url_env) if args.rpc_url_env else args.rpc_url
        if args.rpc_url_env and not rpc_url:
            raise ValueError("Requested RPC environment variable is missing")
        status = preflight(args.artifacts, args.manifest, args.operator, rpc_url)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        # Do not echo RPC URLs containing provider API keys or user secrets.
        print("Preflight failed. Verify artifacts, manifest, account syntax, RPC "
              "network identity and ledger freshness.", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(status, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
