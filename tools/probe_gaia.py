r"""
Record what a real Gaia gateway answers - read-only, and it only reads.

`app/gaia_topology.py` parses routing without a lab-verified sample of the
payload, because Gaia's envelopes differ between builds and this project's
eleventh principle forbids writing against a shape assumed from documentation.
This tool closes that gap: it calls each allowlisted read against each
configured gateway and writes the raw answers to a file, so the readers can be
narrowed to what a build actually returns instead of widened to every guess.

It cannot issue a command that is not on the read allowlist in `app/gaia.py`;
the client refuses before any request is built.

Usage
-----
    # .env: GAIA_ENABLED=true, GAIA_USER, GAIA_PASSWORD, GAIA_HOSTS
    python -m tools.probe_gaia
    python -m tools.probe_gaia --host 172.23.31.177 --json gaia-probe.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from app.config import settings
from app.gaia import ALLOWED, GaiaAPIError, GaiaClient
from app.gaia_topology import read_routes
from app.version import APP_VERSION

GREEN, RED, YELLOW, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

# Reads worth probing, in the order a person would want to see them.
PROBE = ["show-version", "show-routes", "show-static-routes", "show-interfaces",
         "show-cluster-state"]


def _shape(value: Any, depth: int = 0) -> str:
    """A one-line description of an envelope, without dumping the whole body."""
    if isinstance(value, dict):
        keys = list(value)[:12]
        inner = ""
        for key in keys:
            item = value[key]
            if isinstance(item, list) and item and isinstance(item[0], dict):
                inner = f"  first item of '{key}': {sorted(item[0])[:14]}"
                break
        return f"dict keys={keys}" + (f"\n       {inner}" if inner else "")
    if isinstance(value, list):
        head = value[0] if value else None
        if isinstance(head, dict):
            return f"list[{len(value)}] first item keys={sorted(head)[:14]}"
        return f"list[{len(value)}]"
    return type(value).__name__


async def probe_host(host: str) -> dict[str, Any]:
    print(f"\n{DIM}=== {host} ==={OFF}")
    client = GaiaClient(host)
    result: dict[str, Any] = {"host": host, "commands": {}}
    try:
        try:
            await client.login()
            print(f"  [{GREEN}PASS{OFF}] login")
        except GaiaAPIError as exc:
            print(f"  [{RED}FAIL{OFF}] login  {DIM}{exc}{OFF}")
            result["error"] = str(exc)
            return result

        for command in PROBE:
            if command not in ALLOWED:
                print(f"  [{YELLOW}SKIP{OFF}] {command} is not on the read allowlist")
                continue
            try:
                payload = await client.call(command, {})
            except GaiaAPIError as exc:
                print(f"  [{YELLOW}INFO{OFF}] {command}  {DIM}{exc}{OFF}")
                result["commands"][command] = {"error": str(exc)}
                continue
            print(f"  [{GREEN}PASS{OFF}] {command}  {DIM}{_shape(payload)}{OFF}")
            result["commands"][command] = {"raw": payload}

            if command in ("show-routes", "show-static-routes"):
                parsed = read_routes(payload, source=command)
                result["commands"][command]["parsed"] = {
                    "parsed": parsed["parsed"], "total": parsed["total"],
                    "sample": parsed["routes"][:5],
                    "unparsed_sample": parsed["unparsed"][:5],
                }
                tone = GREEN if parsed["parsed"] == parsed["total"] else YELLOW
                print(f"         {tone}reader understood {parsed['parsed']}/{parsed['total']} "
                      f"route entries{OFF}")
                for route in parsed["routes"][:5]:
                    print(f"           {route['prefix']:<20} via "
                          f"{', '.join(route['next_hops']) or 'connected':<18} "
                          f"{route['type']}")
                for bad in parsed["unparsed"][:3]:
                    print(f"           {YELLOW}unparsed:{OFF} {json.dumps(bad['raw'])[:120]}")
    finally:
        await client.close()
    return result


async def run(hosts: list[str], out_path: str) -> int:
    print(f"Firewall Insight {APP_VERSION} - Gaia API probe (read-only)")
    print(f"{DIM}allowlist: {', '.join(sorted(ALLOWED))}{OFF}")
    if not settings.gaia_enabled:
        print(f"{YELLOW}note: GAIA_ENABLED is false. The probe still runs, but the "
              f"network map will not overlay routing until you set it true.{OFF}")

    results = [await probe_host(host) for host in hosts]
    Path(out_path).write_text(
        json.dumps({"app_version": APP_VERSION, "hosts": results}, indent=2,
                   ensure_ascii=False), encoding="utf-8")
    print(f"\n{DIM}raw answers written to {out_path}{OFF}")
    print(f"{DIM}If any route entry says 'unparsed', send that file back: the "
          f"readers in app/gaia_topology.py should be narrowed to this build's "
          f"shape rather than left guessing.{OFF}")
    return 0 if any(not r.get("error") for r in results) else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe the Gaia API, read-only")
    ap.add_argument("--host", action="append", default=[],
                    help="gateway address; repeatable. Defaults to GAIA_HOSTS")
    ap.add_argument("--json", default="gaia-probe.json")
    args = ap.parse_args()
    hosts = args.host or [h.strip() for h in str(settings.gaia_hosts or "").split(",")
                          if h.strip()]
    if not hosts:
        print("No hosts. Set GAIA_HOSTS in .env or pass --host.")
        sys.exit(2)
    sys.exit(asyncio.run(run(hosts, args.json)))


if __name__ == "__main__":
    main()
