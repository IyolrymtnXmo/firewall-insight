from __future__ import annotations
from typing import Any
import asyncio, time
import httpx
from .config import settings


def _rulebase_item_key(item):
    if not isinstance(item, dict):
        return None
    uid = item.get("uid")
    if uid:
        return ("uid", str(uid))
    typ = item.get("type")
    if typ == "access-section":
        return ("access-section", str(item.get("name") or ""))
    if typ == "access-rule":
        return ("access-rule", str(item.get("rule-number") or ""), str(item.get("name") or ""))
    if typ == "nat-section":
        return ("nat-section", str(item.get("name") or ""))
    if typ == "nat-rule":
        return ("nat-rule", str(item.get("rule-number") or ""), str(item.get("name") or ""))
    return None


def _merge_rulebase_page(target, incoming):
    """
    Merge paginated rulebase pages without duplicating a section wrapper.

    show-access-rulebase/show-nat-rulebase can repeat the same section wrapper
    across pages while returning a different slice of rules inside it.
    """
    index = {}
    for i, item in enumerate(target):
        key = _rulebase_item_key(item)
        if key is not None:
            index[key] = i

    for item in incoming or []:
        if not isinstance(item, dict):
            continue
        key = _rulebase_item_key(item)

        if key is None or key not in index:
            target.append(item)
            if key is not None:
                index[key] = len(target) - 1
            continue

        existing = target[index[key]]
        old_nested = existing.get("rulebase")
        new_nested = item.get("rulebase")
        if isinstance(old_nested, list) and isinstance(new_nested, list):
            _merge_rulebase_page(old_nested, new_nested)

        for k, v in item.items():
            if k == "rulebase":
                continue
            if k not in existing or existing[k] in (None, "", [], {}):
                existing[k] = v

    return target

def _is_unsupported_parameter_error(exc: Exception) -> bool:
    """
    Detect 'HTTP 400: Unrecognized parameter [show-hits]' style responses.

    Management API builds differ: show-nat-rulebase rejected show-hits on
    v1.9 but accepts it on newer builds / Jumbo levels. Probe instead of
    hardcoding either behaviour.
    """
    msg = str(exc).lower()
    return "unrecognized parameter" in msg or "show-hits" in msg


class CheckPointAPIError(RuntimeError):
    pass

class CheckPointRateLimitError(CheckPointAPIError):
    pass

class CheckPointClient:
    def __init__(self) -> None:
        self.base_url = settings.checkpoint_mgmt.rstrip("/")
        self.sid: str | None = None
        self.login_info: dict[str, Any] = {}
        self.client = httpx.AsyncClient(verify=settings.checkpoint_verify_ssl, timeout=settings.checkpoint_timeout, headers={"Content-Type":"application/json"})
        self._request_lock = asyncio.Lock()
        self._last_request_at = 0.0
        # None = not probed yet, True/False = this Management API's answer.
        self.nat_show_hits_supported: bool | None = None
        # Set when object hydration stopped early on rate limiting, so callers
        # can report reduced confidence instead of silently guessing.
        self.hydration_truncated = False

    async def close(self) -> None:
        if self.sid:
            try: await self._raw_post("logout", {}, use_sid=True, allow_rate_retry=False)
            except Exception: pass
        self.sid = None
        await self.client.aclose()

    async def _pace(self) -> None:
        interval=max(0.0,float(settings.checkpoint_min_request_interval))
        elapsed=time.monotonic()-self._last_request_at
        if elapsed < interval: await asyncio.sleep(interval-elapsed)

    @staticmethod
    def _parse_response(response:httpx.Response)->dict[str,Any]:
        try: data=response.json()
        except Exception as exc:
            body=response.text[:500].strip()
            raise CheckPointAPIError(f"Check Point returned HTTP {response.status_code} with non-JSON body: {body}") from exc
        if response.is_error:
            message=data.get("message") or data.get("code") or str(data)
            low=str(message).lower()
            if response.status_code==403 and ("too many requests" in low or "given amount of time" in low):
                raise CheckPointRateLimitError(f"HTTP 403: {message}")
            raise CheckPointAPIError(f"HTTP {response.status_code}: {message}")
        return data

    async def _raw_post(self, command:str, payload:dict[str,Any]|None=None, *, use_sid:bool=True, allow_rate_retry:bool=True)->dict[str,Any]:
        retries=max(0,int(settings.checkpoint_rate_limit_retries)); base=max(.5,float(settings.checkpoint_rate_limit_base_delay))
        async with self._request_lock:
            for attempt in range(retries+1):
                await self._pace()
                headers={"X-chkp-sid":self.sid} if use_sid and self.sid else {}
                try:
                    r=await self.client.post(f"{self.base_url}/web_api/{command}", json=payload or {}, headers=headers)
                    self._last_request_at=time.monotonic()
                    return self._parse_response(r)
                except CheckPointRateLimitError:
                    if not allow_rate_retry or attempt>=retries: raise
                    await asyncio.sleep(base*(2**attempt))
                except httpx.ConnectError as exc:
                    raise CheckPointAPIError(f"Unable to connect to Check Point Management API at {self.base_url}: {exc}") from exc
                except httpx.TimeoutException as exc:
                    raise CheckPointAPIError(f"Timeout while contacting Check Point Management API at {self.base_url}") from exc
        raise CheckPointAPIError("Unexpected Management API request failure")

    async def login(self, force:bool=False)->dict[str,Any]:
        if self.sid and not force: return self.login_info
        payload={"user":settings.checkpoint_user,"password":settings.checkpoint_password}
        if settings.checkpoint_domain: payload["domain"]=settings.checkpoint_domain
        data=await self._raw_post("login",payload,use_sid=False)
        self.sid=data.get("sid")
        if not self.sid: raise CheckPointAPIError("Login succeeded but no session ID was returned.")
        self.login_info=data
        return data

    async def call(self, command:str, payload:dict[str,Any]|None=None)->dict[str,Any]:
        if not self.sid: await self.login()
        try: return await self._raw_post(command,payload,use_sid=True)
        except CheckPointAPIError as exc:
            msg=str(exc).lower()
            if "session" in msg and any(x in msg for x in ("invalid","expired","not found")):
                self.sid=None; await self.login(force=True); return await self._raw_post(command,payload,use_sid=True)
            raise

    async def show_packages(self):
        return (await self.call("show-packages",{"limit":500,"offset":0,"details-level":"standard"})).get("packages",[])

    async def show_package(self, package: str):
        try:
            return await self.call(
                "show-package",
                {"name": package, "details-level": "full"},
            )
        except CheckPointAPIError:
            return await self.call(
                "show-package",
                {"name": package, "details-level": "standard"},
            )

    async def show_package_access_layers(self, package: str):
        """
        Return ordered Access Control layer(s) that belong to a Policy Package.

        API builds can expose these as access-layers on show-package. If not,
        fall back to the standard '<package> Network' naming convention.
        """
        data = await self.show_package(package)
        candidates = []

        containers = [data]
        if isinstance(data.get("package"), dict):
            containers.append(data["package"])

        for container in containers:
            for key in ("access-layers", "access_layers", "accessLayers"):
                value = container.get(key)
                if isinstance(value, list):
                    candidates = value
                    break
            if candidates:
                break

        result = []
        seen = set()
        for item in candidates:
            if isinstance(item, str):
                name, uid = item, ""
            elif isinstance(item, dict):
                name = str(item.get("name") or "")
                uid = str(item.get("uid") or "")
            else:
                continue
            if not name:
                continue
            token = uid or name
            if token in seen:
                continue
            seen.add(token)
            result.append({"name": name, "uid": uid})

        if not result:
            conventional = f"{package} Network"
            for layer in await self.show_access_layers():
                if isinstance(layer, dict) and str(layer.get("name") or "") == conventional:
                    result.append(
                        {"name": conventional, "uid": str(layer.get("uid") or "")}
                    )
                    break

        return result

    async def show_access_layers(self):
        return (await self.call("show-access-layers",{"limit":500,"offset":0,"details-level":"standard"})).get("access-layers",[])

    async def show_rulebase(self, layer: str):
        limit = 100
        offset = 0
        total = None
        items = []
        dictionary = {}
        seen_offsets = set()

        while total is None or offset < total:
            if offset in seen_offsets:
                break
            seen_offsets.add(offset)

            page = await self.call(
                "show-access-rulebase",
                {
                    "name": layer,
                    "limit": limit,
                    "offset": offset,
                    "details-level": "standard",
                    "use-object-dictionary": True,
                    "show-hits": True,
                },
            )

            batch = page.get("rulebase", [])
            _merge_rulebase_page(items, batch)

            for obj in page.get("objects-dictionary", []):
                if isinstance(obj, dict) and obj.get("uid"):
                    dictionary[obj["uid"]] = obj

            total = int(page.get("total", 0) or 0)

            # IMPORTANT:
            # use collection response 'to' as next offset.
            # len(batch) can be just the number of section wrappers and causes
            # overlapping pages / duplicated rules.
            response_to = page.get("to")
            if response_to is not None:
                next_offset = int(response_to)
            else:
                next_offset = offset + limit

            if not batch or next_offset <= offset:
                break
            offset = next_offset

        return {
            "layer": layer,
            "total": total,
            "rulebase": items,
            "objects-dictionary": list(dictionary.values()),
        }

    async def show_rulebase_tree(self, root_layer: str, max_depth: int = 10):
        """
        Recursively retrieve a top-level Access Layer and every referenced
        Inline Layer. Each layer remains an independent rulebase node.
        """
        from .inline_layers import walk_access_rules, inline_ref, layer_catalog

        catalog = await self.show_access_layers()
        uid_to_name, name_to_uid = layer_catalog(catalog)

        layers = []
        errors = []
        visited = set()

        async def load(layer_name: str, *, layer_uid: str = "", depth: int = 0,
                       parent_layer: str | None = None, parent_rule=None,
                       parent_path: str = "", display_prefix: str = ""):
            if depth > max_depth:
                errors.append({
                    "layer": layer_name,
                    "parent_layer": parent_layer,
                    "parent_rule": parent_rule,
                    "error": f"Maximum inline layer depth {max_depth} reached",
                })
                return

            canonical = layer_uid or name_to_uid.get(layer_name) or layer_name
            if canonical in visited:
                return
            visited.add(canonical)

            try:
                payload = await self.show_rulebase(layer_name)
            except CheckPointAPIError as exc:
                errors.append({
                    "layer": layer_name,
                    "uid": layer_uid,
                    "parent_layer": parent_layer,
                    "parent_rule": parent_rule,
                    "error": str(exc),
                })
                return

            path = f"{parent_path} → {layer_name}" if parent_path else layer_name
            node = {
                "name": layer_name,
                "uid": layer_uid or name_to_uid.get(layer_name, ""),
                "depth": depth,
                "path": path,
                "parent_layer": parent_layer,
                "parent_rule": parent_rule,
                "display_prefix": display_prefix,
                "rule_count": sum(1 for _ in walk_access_rules(payload.get("rulebase", []))),
                "payload": payload,
            }
            layers.append(node)

            for rule in walk_access_rules(payload.get("rulebase", [])):
                ref = inline_ref(rule, uid_to_name)
                if not ref:
                    continue
                child_uid, child_name = ref
                if not child_name and child_uid:
                    child_name = uid_to_name.get(child_uid, "")
                if not child_name:
                    errors.append({
                        "layer": str(child_uid or "unknown"),
                        "parent_layer": layer_name,
                        "parent_rule": rule.get("rule-number"),
                        "error": "Inline Layer reference could not be resolved to a layer name",
                    })
                    continue

                parent_rn = rule.get("rule-number")
                child_prefix = (
                    f"{display_prefix}.{parent_rn}"
                    if display_prefix
                    else str(parent_rn)
                )
                await load(
                    child_name,
                    layer_uid=child_uid or name_to_uid.get(child_name, ""),
                    depth=depth + 1,
                    parent_layer=layer_name,
                    parent_rule=parent_rn,
                    parent_path=path,
                    display_prefix=child_prefix,
                )

        await load(root_layer, layer_uid=name_to_uid.get(root_layer, ""))
        return {
            "root_layer": root_layer,
            "layers": layers,
            "errors": errors,
            "total_layers": len(layers),
        }

    async def hydrate_objects(
        self,
        uids: set[str],
        existing: dict[str, dict[str, Any]],
        *,
        refresh_incomplete: bool = True,
    ):
        """
        Fetch full detail for referenced objects.

        A UID already present in `existing` is NOT automatically complete:
        objects-dictionary entries from details-level=standard carry only
        uid/name/type, so groups arrive with no members and gateways with no
        address. Those must be re-fetched or the resolver reports every one of
        them as statically unevaluable, which turns correct traffic answers
        into UNVERIFIED and silently weakens shadow analysis.
        """
        from .resolver import needs_detail

        targets = []
        for uid in uids:
            if not uid:
                continue
            current = existing.get(uid)
            if current is None:
                targets.append(uid)
            elif refresh_incomplete and needs_detail(current):
                targets.append(uid)

        for uid in targets:
            try:
                data = await self.call("show-object", {"uid": uid, "details-level": "full"})
                obj = data.get("object") if isinstance(data, dict) else None
                if isinstance(obj, dict):
                    existing[uid] = obj
            except CheckPointRateLimitError:
                # Stop hammering, but do not pretend the data is complete.
                self.hydration_truncated = True
                break
            except CheckPointAPIError:
                continue
        return existing

    async def show_gateways_and_servers(self):
        out=[]; offset=0; limit=100
        while True:
            page=await self.call("show-gateways-and-servers",{"limit":limit,"offset":offset,"details-level":"full"})
            batch=page.get("objects",[]); out.extend(batch); total=int(page.get("total",len(out)))
            if not batch or len(out)>=total: break
            offset+=len(batch)
        return out

    async def _nat_rulebase_page(self, package: str, limit: int, offset: int):
        """
        Request one NAT rulebase page, probing show-hits support once.

        Older Management builds answer HTTP 400 'Unrecognized parameter
        [show-hits]'. When that happens we remember it and never ask again
        for this session, instead of permanently disabling NAT hit counts
        for every environment.
        """
        params = {
            "package": package,
            "limit": limit,
            "offset": offset,
            "details-level": "standard",
            "use-object-dictionary": True,
        }

        if self.nat_show_hits_supported is not False:
            try:
                page = await self.call("show-nat-rulebase", {**params, "show-hits": True})
                self.nat_show_hits_supported = True
                return page
            except CheckPointRateLimitError:
                raise
            except CheckPointAPIError as exc:
                if not _is_unsupported_parameter_error(exc):
                    raise
                self.nat_show_hits_supported = False

        return await self.call("show-nat-rulebase", params)

    async def show_nat_rulebase(self, package: str):
        items = []
        dictionary = {}
        offset = 0
        limit = 100
        total = None
        seen_offsets = set()

        while total is None or offset < total:
            if offset in seen_offsets:
                break
            seen_offsets.add(offset)

            page = await self._nat_rulebase_page(package, limit, offset)

            batch = page.get("rulebase", [])
            _merge_rulebase_page(items, batch)

            for obj in page.get("objects-dictionary", []):
                if isinstance(obj, dict) and obj.get("uid"):
                    dictionary[obj["uid"]] = obj

            total = int(page.get("total", 0) or 0)

            response_to = page.get("to")
            if response_to is not None:
                next_offset = int(response_to)
            else:
                next_offset = offset + limit

            if not batch or next_offset <= offset:
                break
            offset = next_offset

        return {
            "package": package,
            "total": total,
            "rulebase": items,
            "objects-dictionary": list(dictionary.values()),
            "hits_requested": bool(self.nat_show_hits_supported),
        }
