"""
Gaia API client - read-only by construction, not by convention.

The Management API this application already speaks has a convenient property:
its read commands all start with `show-`, so "read-only" can be checked by
grepping for anything else. The Gaia API does not have that property. Its
reference lists `show-routes` and `show-cluster-state` next to `set-static-route`,
`add-license`, `run-script` and `run-reboot`, on the same connection, with the
same session. Extending the application onto that API without extending the
guarantee would have quietly turned a tool that *cannot* change a firewall into
one that merely *does not*.

So the allowlist here is enforced at call time, in code, and it is the only
route to the API:

  * `call()` refuses any command not in ALLOWED, before any network I/O
  * every entry in ALLOWED is a read
  * `login`, `keepalive` and `logout` are session management, listed apart so
    the read allowlist stays exactly the reads

A structural test asserts that no mutating Gaia command string appears anywhere
in `app/`, the same way one already does for the Management API. Adding a
capability tightened the guarantee rather than loosening it, which is the only
acceptable direction for a tool people are asked to point at production.

Response shapes are NOT hardcoded here. Gaia returns different envelopes on
different versions, so `tools/probe_gaia.py` exists to record what a given lab
actually answers, and the parsers in gaia_topology.py read defensively and
report what they could not understand instead of inventing it.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .config import settings

# Reads. Every one of these was taken from the Gaia API reference; nothing is
# here on the assumption that it probably exists.
ALLOWED = {
    "show-routes",
    "show-static-routes",
    "show-interfaces",
    "show-interface",
    "show-bond-interfaces",
    "show-cluster-state",
    "show-version",
    "show-asset",
    "show-lldp-status",
    "show-physical-interfaces-xcvr",
}
SESSION = {"login", "logout", "keepalive"}


class GaiaAPIError(RuntimeError):
    pass


class GaiaNotAllowed(GaiaAPIError):
    """Raised before any I/O when a command is not on the read allowlist."""


class GaiaClient:
    """One Gaia host. Short-lived: log in, read, log out."""

    def __init__(self, host: str, user: str | None = None,
                 password: str | None = None) -> None:
        self.host = str(host).strip().rstrip("/")
        if not self.host.startswith(("http://", "https://")):
            self.host = f"https://{self.host}"
        self.user = user if user is not None else settings.gaia_user
        self.password = password if password is not None else settings.gaia_password
        self.sid: str | None = None
        self.client = httpx.AsyncClient(
            verify=settings.gaia_verify_ssl,
            timeout=settings.gaia_timeout,
            headers={"Content-Type": "application/json"},
        )
        self._lock = asyncio.Lock()

    # -- transport ------------------------------------------------------

    @staticmethod
    def _parse(response: httpx.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except Exception as exc:                                  # noqa: BLE001
            body = response.text[:400].strip()
            raise GaiaAPIError(
                f"Gaia returned HTTP {response.status_code} with a non-JSON body: {body}"
            ) from exc
        if response.is_error:
            message = data.get("message") or data.get("code") or str(data)
            raise GaiaAPIError(f"HTTP {response.status_code}: {message}")
        return data

    async def _post(self, command: str, payload: dict[str, Any] | None,
                    *, use_sid: bool = True) -> dict[str, Any]:
        headers = {"X-chkp-sid": self.sid} if use_sid and self.sid else {}
        url = f"{self.host}/gaia_api/{command}"
        try:
            async with self._lock:
                response = await self.client.post(url, json=payload or {}, headers=headers)
        except httpx.ConnectError as exc:
            raise GaiaAPIError(f"Unable to connect to the Gaia API at {self.host}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise GaiaAPIError(f"Timeout contacting the Gaia API at {self.host}") from exc
        return self._parse(response)

    # -- session --------------------------------------------------------

    async def login(self) -> dict[str, Any]:
        if not self.user:
            raise GaiaAPIError(
                "No Gaia credentials configured. Set GAIA_USER and GAIA_PASSWORD "
                "in .env, or leave GAIA_ENABLED false to keep this feature off.")
        data = await self._post("login", {"user": self.user, "password": self.password},
                                use_sid=False)
        self.sid = data.get("sid")
        if not self.sid:
            raise GaiaAPIError("Gaia login succeeded but returned no session id.")
        return data

    async def close(self) -> None:
        if self.sid:
            try:
                await self._post("logout", {})
            except Exception:                                     # noqa: BLE001
                pass
        self.sid = None
        await self.client.aclose()

    # -- the only way in ------------------------------------------------

    async def call(self, command: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Run one allowlisted read.

        The check happens before login and before any request is built, so a
        command that is not on the list never reaches the network - not even as
        an authentication attempt.
        """
        if command not in ALLOWED:
            raise GaiaNotAllowed(
                f"'{command}' is not on the Gaia read allowlist. This application "
                f"issues only: {', '.join(sorted(ALLOWED))}. Session commands "
                f"({', '.join(sorted(SESSION))}) are handled separately.")
        if not self.sid:
            await self.login()
        return await self._post(command, payload)

    # -- the reads this application actually uses -----------------------

    async def routes(self) -> dict[str, Any]:
        # No parameters. R82 answers `HTTP 400: Validation Error` to a `limit`
        # on these two, which is how the map reported "no routing" from the very
        # gateways tools/probe_gaia.py had just read successfully - the probe
        # sends {} and the client did not. The payload carries from/to/total, so
        # if a routing table ever exceeds one page this needs the real parameter
        # names from that build rather than a guess repeated.
        return await self.call("show-routes", {})

    async def static_routes(self) -> dict[str, Any]:
        return await self.call("show-static-routes", {})

    async def interfaces(self) -> dict[str, Any]:
        return await self.call("show-interfaces", {})

    async def cluster_state(self) -> dict[str, Any]:
        return await self.call("show-cluster-state", {})

    async def version(self) -> dict[str, Any]:
        return await self.call("show-version", {})


async def read_all_routes(hosts: list[str] | None = None) -> dict[str, Any]:
    """
    Read routing from every configured gateway.

    One gateway failing must not cost the others: an unreachable host comes
    back as {"error": ...} for that key, and the map names it in its
    limitations rather than drawing the remaining gateways as if the estate
    were smaller than it is.
    """
    from .gaia_topology import read_routes

    targets = hosts if hosts is not None else [
        h.strip() for h in str(settings.gaia_hosts or "").split(",") if h.strip()
    ]
    out: dict[str, Any] = {}
    for host in targets:
        client = GaiaClient(host)
        try:
            out[host] = read_routes(await client.routes())
        except GaiaAPIError as exc:
            out[host] = {"error": str(exc)}
        except Exception as exc:                                  # noqa: BLE001
            out[host] = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            await client.close()
    return out


async def read_all_state(hosts: list[str] | None = None) -> dict[str, Any]:
    """
    Read interfaces, cluster state and version from every configured gateway.

    Same contract as read_all_routes: one gateway failing costs only that
    gateway, and the failure is reported as data rather than swallowed - a
    gateway that produced no findings because nobody could reach it must not
    read as a gateway with nothing wrong.
    """
    targets = hosts if hosts is not None else [
        h.strip() for h in str(settings.gaia_hosts or "").split(",") if h.strip()
    ]
    out: dict[str, Any] = {}
    for host in targets:
        client = GaiaClient(host)
        try:
            try:
                await client.login()
            except Exception as exc:                              # noqa: BLE001
                out[host] = {"error": str(exc)}
                continue

            # Each read stands on its own. `show-cluster-state` fails on a
            # standalone gateway - Internal-GW01 in the lab is exactly that -
            # and losing its interfaces and version over a command that was
            # never going to apply would be the same mistake the routing reader
            # already refuses to make: one failure costing everything around it.
            entry: dict[str, Any] = {}
            errors: dict[str, str] = {}
            for name, read in (("interfaces", client.interfaces),
                               ("cluster", client.cluster_state),
                               ("version", client.version)):
                try:
                    entry[name] = await read()
                except GaiaAPIError as exc:
                    errors[name] = str(exc)
                except Exception as exc:                          # noqa: BLE001
                    errors[name] = f"{type(exc).__name__}: {exc}"
            if errors:
                entry["errors"] = errors
            out[host] = entry
            if not any(k in entry for k in ("interfaces", "cluster", "version")):
                out[host] = {"error": "; ".join(f"{k}: {v}" for k, v in errors.items())
                             or "the gateway answered nothing"}
        finally:
            await client.close()
    return out
