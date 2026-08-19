from __future__ import annotations
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any
import re

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

    def address_atoms(self, uid: str, seen: set[str] | None=None) -> list[AddrAtom] | None:
        seen=set() if seen is None else seen
        if uid in seen: return []
        seen.add(uid); o=self.obj(uid); t=str(o.get("type","")).lower()
        if self.is_any_uid(uid):
            return [AddrAtom(0,2**32-1,4), AddrAtom(0,2**128-1,6)]
        ip=o.get("ip-address") or o.get("ipv4-address") or o.get("ipv6-address")
        if ip:
            try:
                a=ip_address(str(ip)); n=int(a); return [AddrAtom(n,n,a.version)]
            except ValueError: pass
        subnet=o.get("subnet4") or o.get("subnet") or o.get("subnet6")
        ml=o.get("mask-length4") if o.get("mask-length4") is not None else o.get("mask-length")
        if ml is None: ml=o.get("mask-length6")
        if subnet is not None and ml is not None:
            try:
                n=ip_network(f"{subnet}/{ml}",strict=False); return [AddrAtom(int(n.network_address),int(n.broadcast_address),n.version)]
            except ValueError: pass
        first=o.get("ipv4-address-first") or o.get("first-ip") or o.get("ipv6-address-first")
        last=o.get("ipv4-address-last") or o.get("last-ip") or o.get("ipv6-address-last")
        if first and last:
            try:
                a,b=ip_address(str(first)),ip_address(str(last));
                if a.version==b.version: return [AddrAtom(int(a),int(b),a.version)]
            except ValueError: pass
        members=o.get("members")
        if isinstance(members,list) or "group" in t:
            atoms=[]
            for x in members or []:
                cu=x if isinstance(x,str) else x.get("uid") if isinstance(x,dict) else None
                if not cu: continue
                part=self.address_atoms(cu,seen.copy())
                if part is None: return None
                atoms.extend(part)
            return atoms if atoms else None
        return None

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

    def service_atoms(self, uid: str, seen: set[str] | None=None) -> list[PortAtom] | None:
        seen=set() if seen is None else seen
        if uid in seen: return []
        seen.add(uid); o=self.obj(uid); t=str(o.get("type","")).lower()
        if self.is_any_uid(uid): return [PortAtom(0,65535,"any")]
        proto=None
        if "tcp" in t: proto="tcp"
        elif "udp" in t: proto="udp"
        if proto:
            ranges=self._port_ranges(o.get("port",""))
            return None if ranges is None else [PortAtom(a,b,proto) for a,b in ranges]
        members=o.get("members")
        if isinstance(members,list) or "service-group" in t or t.endswith("group"):
            atoms=[]
            for x in members or []:
                cu=x if isinstance(x,str) else x.get("uid") if isinstance(x,dict) else None
                if not cu: continue
                part=self.service_atoms(cu,seen.copy())
                if part is None: return None
                atoms.extend(part)
            return atoms if atoms else None
        return None

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
