from __future__ import annotations
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any
import re

# Fields that let ObjectResolver turn an object into a comparable range.
_ADDRESS_KEYS = (
    "ip-address", "ipv4-address", "ipv6-address",
    "subnet4", "subnet", "subnet6",
    "ipv4-address-first", "first-ip", "ipv6-address-first",
)
_SERVICE_KEYS = ("port",)
_CONTAINER_KEYS = ("members", "include", "except")

# Object kinds that are never an address or a service, so re-fetching them
# with details-level=full would only waste rate-limited API calls.
_NON_RESOLVABLE_TYPES = {
    "cpmianyobject", "any",
    "rulebaseaction", "cpmiaction", "cpmiacceptaction",
    "track", "cpmilogtrack", "rulebasetrack",
    "global", "cpmiglobal",
    "access-layer", "cpmiaccesslayer",
}


def needs_detail(obj: Any) -> bool:
    """
    True when a dictionary entry is too thin for the resolver to use.

    `show-access-rulebase` with details-level=standard returns uid/name/type
    but omits group membership and the addresses of gateways and clusters.
    Presence in objects-dictionary therefore does NOT mean the object is
    usable - it must actually carry an address, a port, or members.
    """
    if not isinstance(obj, dict) or not obj.get("uid"):
        return True

    if obj.get("name") == "Any":
        return False

    typ = str(obj.get("type") or "").lower()
    if typ in _NON_RESOLVABLE_TYPES or typ.endswith("action"):
        return False

    for key in _ADDRESS_KEYS + _SERVICE_KEYS + _CONTAINER_KEYS:
        if obj.get(key) not in (None, "", [], {}):
            return False

    return True


@dataclass(frozen=True)
class AddrAtom:
    start: int
    end: int
    version: int

@dataclass(frozen=True)
class PortAtom:
    start: int
    end: int
    proto: str

class ObjectResolver:
    def __init__(self, objects: dict[str, dict[str, Any]]):
        self.objects = objects

    def obj(self, uid: str) -> dict[str, Any]:
        return self.objects.get(uid, {"uid": uid, "name": uid, "type": "unknown"})

    def name(self, value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("name") or value.get("uid") or "")
        if isinstance(value, str):
            return str(self.obj(value).get("name") or value)
        return str(value or "")

    def uids(self, value: Any) -> list[str]:
        if not isinstance(value, list): return []
        out=[]
        for x in value:
            if isinstance(x,str): out.append(x)
            elif isinstance(x,dict) and x.get("uid"): out.append(x["uid"])
        return out

    def is_any_uid(self, uid: str) -> bool:
        o=self.obj(uid)
        return o.get("name") == "Any" or o.get("type") in {"CpmiAnyObject","any"}

    def is_any(self, values: Any) -> bool:
        return any(self.is_any_uid(u) for u in self.uids(values))

    def collect_child_uids(self, uid: str, seen: set[str] | None=None) -> set[str]:
        seen=set() if seen is None else seen
        if uid in seen: return set()
        seen.add(uid); o=self.obj(uid); out=set()
        for key in ("members","include","except"):
            v=o.get(key)
            if isinstance(v,list):
                for x in v:
                    cu=x if isinstance(x,str) else x.get("uid") if isinstance(x,dict) else None
                    if cu: out.add(cu); out |= self.collect_child_uids(cu,seen)
            elif isinstance(v,dict) and v.get("uid"):
                cu=v["uid"]; out.add(cu); out |= self.collect_child_uids(cu,seen)
        return out

    def _member_uids(self, obj: dict[str, Any]) -> list[str]:
        out = []
        members = obj.get("members")
        if isinstance(members, list):
            for x in members:
                cu = x if isinstance(x, str) else x.get("uid") if isinstance(x, dict) else None
                if cu:
                    out.append(cu)
        return out

    def address_atoms_partial(
        self, uid: str, seen: set[str] | None = None
    ) -> tuple[list[AddrAtom], bool]:
        """
        Resolve as much of `uid` as possible.

        Returns (atoms, complete). `complete` is False when at least one part
        could not be modelled - a dynamic object, or a group member of an
        unsupported type.

        Two callers need different things from the same data:

          * Matching ("is this IP inside the object?") only needs ONE atom to
            hit. Positive evidence does not require complete knowledge, so it
            uses the partial atoms.
          * Containment ("does set A cover set B?") needs every atom, so
            address_atoms() below discards partial results.
        """
        seen = set() if seen is None else seen
        if uid in seen:
            return [], True
        seen.add(uid)

        o = self.obj(uid)
        t = str(o.get("type", "")).lower()

        if self.is_any_uid(uid):
            return [AddrAtom(0, 2**32 - 1, 4), AddrAtom(0, 2**128 - 1, 6)], True

        ip = o.get("ip-address") or o.get("ipv4-address") or o.get("ipv6-address")
        if ip:
            try:
                a = ip_address(str(ip))
                return [AddrAtom(int(a), int(a), a.version)], True
            except ValueError:
                pass

        subnet = o.get("subnet4") or o.get("subnet") or o.get("subnet6")
        ml = o.get("mask-length4") if o.get("mask-length4") is not None else o.get("mask-length")
        if ml is None:
            ml = o.get("mask-length6")
        if subnet is not None and ml is not None:
            try:
                n = ip_network(f"{subnet}/{ml}", strict=False)
                return [AddrAtom(int(n.network_address), int(n.broadcast_address), n.version)], True
            except ValueError:
                pass

        first = o.get("ipv4-address-first") or o.get("first-ip") or o.get("ipv6-address-first")
        last = o.get("ipv4-address-last") or o.get("last-ip") or o.get("ipv6-address-last")
        if first and last:
            try:
                a, b = ip_address(str(first)), ip_address(str(last))
                if a.version == b.version:
                    return [AddrAtom(int(a), int(b), a.version)], True
            except ValueError:
                pass

        if isinstance(o.get("members"), list) or "group" in t:
            atoms = []
            complete = True
            for cu in self._member_uids(o):
                part, part_complete = self.address_atoms_partial(cu, seen.copy())
                atoms.extend(part)
                complete = complete and part_complete
            if not atoms and not self._member_uids(o):
                # An empty group tells us nothing either way.
                return [], False
            return atoms, complete

        return [], False

    def address_atoms(self, uid: str, seen: set[str] | None=None) -> list[AddrAtom] | None:
        """Strict resolution: None unless the object is fully modelled."""
        atoms, complete = self.address_atoms_partial(uid, seen)
        if not complete:
            return None
        return atoms if atoms else None

    def _port_ranges(self, text: str) -> list[tuple[int,int]] | None:
        s=str(text).strip().lower().replace(" ","")
        if s in {"","any"}: return [(0,65535)]
        out=[]
        for token in s.split(","):
            if token.isdigit(): out.append((int(token),int(token))); continue
            m=re.fullmatch(r"(\d+)-(\d+)",token)
            if m: out.append((int(m.group(1)),int(m.group(2)))); continue
            m=re.fullmatch(r">(\d+)",token)
            if m: out.append((int(m.group(1))+1,65535)); continue
            m=re.fullmatch(r"<(\d+)",token)
            if m: out.append((0,int(m.group(1))-1)); continue
            return None
        return out

    def _leaf_service_atoms(self, obj: dict[str, Any], typ: str) -> tuple[list[PortAtom], bool] | None:
        """
        Model one non-group service object. None means "not a leaf service".

        Protocols without a port number still get an atom with a distinct
        proto tag. That matters: an ICMP-only service can then be reported as
        a confident no-match against a TCP query instead of poisoning the
        whole rule with `unknown`.
        """
        if "tcp" in typ or "udp" in typ or "sctp" in typ:
            proto = "sctp" if "sctp" in typ else ("tcp" if "tcp" in typ else "udp")
            ranges = self._port_ranges(obj.get("port", ""))
            if ranges is None:
                return [], False
            return [PortAtom(a, b, proto) for a, b in ranges], True

        if "icmp" in typ:
            proto = "icmp6" if ("icmp6" in typ or "icmpv6" in typ) else "icmp"
            icmp_type = obj.get("icmp-type")
            try:
                value = int(icmp_type)
                return [PortAtom(value, value, proto)], True
            except (TypeError, ValueError):
                return [PortAtom(0, 255, proto)], True

        if "service-other" in typ:
            ip_proto = obj.get("ip-protocol")
            try:
                return [PortAtom(0, 65535, f"ip-{int(ip_proto)}")], True
            except (TypeError, ValueError):
                # Without an IP protocol number there is nothing to compare.
                return [], False

        # service-dce-rpc / service-rpc ride dynamic ports negotiated at
        # runtime. Claiming no-match would be a lie, so stay incomplete.
        return None

    def service_atoms_partial(
        self, uid: str, seen: set[str] | None = None
    ) -> tuple[list[PortAtom], bool]:
        """
        Resolve as much of a service object as possible.

        Returns (atoms, complete). A service group with one unsupported member
        still yields atoms for the members it does understand, so a query that
        hits a known member is a definite match. See address_atoms_partial for
        why matching and containment need different strictness.
        """
        seen = set() if seen is None else seen
        if uid in seen:
            return [], True
        seen.add(uid)

        o = self.obj(uid)
        t = str(o.get("type", "")).lower()

        if self.is_any_uid(uid):
            return [PortAtom(0, 65535, "any")], True

        is_group = (
            isinstance(o.get("members"), list)
            or "service-group" in t
            or t.endswith("group")
        )

        if not is_group:
            leaf = self._leaf_service_atoms(o, t)
            return leaf if leaf is not None else ([], False)

        atoms = []
        complete = True
        for cu in self._member_uids(o):
            part, part_complete = self.service_atoms_partial(cu, seen.copy())
            atoms.extend(part)
            complete = complete and part_complete
        if not atoms and not self._member_uids(o):
            return [], False
        return atoms, complete

    def service_atoms(self, uid: str, seen: set[str] | None=None) -> list[PortAtom] | None:
        """Strict resolution: None unless the object is fully modelled."""
        atoms, complete = self.service_atoms_partial(uid, seen)
        if not complete:
            return None
        return atoms if atoms else None

    def unmodelled_names(self, uid: str, kind: str, seen: set[str] | None = None) -> list[str]:
        """
        Names of the leaf objects that stop `uid` from resolving completely.

        Reporting the group name is not actionable - "AD-Services cannot be
        evaluated" does not say why. Naming the blocking leaf does:
        "AD-Services -> ALL_DCE_RPC [service-dce-rpc]".
        """
        seen = set() if seen is None else seen
        if uid in seen:
            return []
        seen.add(uid)

        obj = self.obj(uid)
        typ = str(obj.get("type") or "").lower()
        label = f"{obj.get('name') or uid} [{obj.get('type') or 'unknown'}]"

        is_group = (
            isinstance(obj.get("members"), list)
            or ("service-group" in typ if kind == "service" else False)
            or "group" in typ
        )

        if not is_group:
            resolve = (
                self.service_atoms_partial if kind == "service"
                else self.address_atoms_partial
            )
            _atoms, complete = resolve(uid, set())
            return [] if complete else [label]

        members = self._member_uids(obj)
        if not members:
            return [label]

        out = []
        for child in members:
            for name in self.unmodelled_names(child, kind, seen.copy()):
                if name not in out:
                    out.append(name)
        return out

    def describe_uid(self, uid: str) -> str:
        o=self.obj(uid); name=str(o.get("name") or uid); t=str(o.get("type","")).lower()
        if self.is_any_uid(uid): return "Any"
        if o.get("ip-address"): return f"{name} ({o['ip-address']})"
        subnet=o.get("subnet4") or o.get("subnet") or o.get("subnet6")
        ml=o.get("mask-length4") if o.get("mask-length4") is not None else o.get("mask-length")
        if ml is None: ml=o.get("mask-length6")
        if subnet is not None and ml is not None: return f"{name} ({subnet}/{ml})"
        if ("tcp" in t or "udp" in t) and o.get("port") is not None: return f"{name} ({'TCP' if 'tcp' in t else 'UDP'}/{o.get('port')})"
        return name

    def describe_list(self, values: Any, max_items: int=5) -> str:
        u=self.uids(values)
        parts=[self.describe_uid(x) for x in u[:max_items]]
        if len(u)>max_items: parts.append(f"+{len(u)-max_items} more")
        return ", ".join(parts) if parts else "—"
