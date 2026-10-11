"""
v4.43 - multi-rule (union) shadowing.

The pairwise check (analyzer.py) reports a rule only when ONE earlier rule
covers it. A rule can also be dead because several earlier rules together
cover every connection it could match (Hu et al., TDSC 2012, the "union"
case; FIREMAN finds the same with BDDs). This module finds that case by
exact box subtraction:

  * a rule is a union of boxes  source x destination x service, each side a
    set of integer intervals (the same atoms the pairwise check uses);
  * start from the later rule's boxes and subtract every eligible earlier
    rule's boxes; if nothing is left, the earlier rules together cover it.

Box subtraction gives an exact answer on intervals - it is not sampling and
not a heuristic - but it is only as good as the atoms. So the same
conservative gates as the pairwise check apply, on both sides:

  * the later rule must resolve completely (no unknown object on any side);
  * an earlier rule is used only if it resolves completely, is enabled, is
    not negated, is not an Inline Layer parent, carries no Time / Content /
    Install On restriction, uses no service with extra conditions (source
    port, protocol signature, ICMP code), and has the same VPN column.

Leaving an earlier rule out can only make the subtraction leave MORE
behind, so every exclusion errs towards not reporting. If the remainder
grows past MAX_BOXES the rule is not reported (and counted as given up).

Written for this release; it shares no code with the experiment oracle in
experiments/ (which tests coverage on an elementary-interval grid).
"""
from __future__ import annotations

from typing import Any

from .resolver import AddrAtom, PortAtom, ObjectResolver

MAX_BOXES = 20000

_V6 = 1 << 200                        # IPv6 keys sit above every IPv4 key
_ADDR_ALL = (0, _V6 + (1 << 128) - 1)
_PROTO_SPAN = 1 << 17
_PROTOS = {"tcp": 0, "udp": 1, "sctp": 2, "icmp": 3, "icmp6": 4}
_SVC_ALL = (0, (5 + 256) * _PROTO_SPAN - 1)

Box = tuple[tuple[int, int], tuple[int, int], tuple[int, int]]


def _addr_iv(atoms: list[AddrAtom]) -> list[tuple[int, int]]:
    out = []
    for a in atoms:
        base = _V6 if a.version == 6 else 0
        out.append((base + a.start, base + a.end))
    return out


def _svc_iv(atoms: list[PortAtom]) -> list[tuple[int, int]] | None:
    out = []
    for a in atoms:
        if a.proto == "any":
            out.append(_SVC_ALL)
            continue
        if a.proto in _PROTOS:
            idx = _PROTOS[a.proto]
        elif a.proto.startswith("ip-") and a.proto[3:].isdigit():
            idx = 5 + int(a.proto[3:])
        else:
            return None
        out.append((idx * _PROTO_SPAN + a.start, idx * _PROTO_SPAN + a.end))
    return out


def dimension(values: Any, res: ObjectResolver, kind: str) -> list[tuple[int, int]] | None:
    """Intervals of one rule column, or None when it cannot be fully resolved."""
    uids = res.uids(values)
    if not uids:
        return None                       # empty column: no data, never provable
    if res.is_any(values):
        return [_ADDR_ALL] if kind == "address" else [_SVC_ALL]
    out: list[tuple[int, int]] = []
    for uid in uids:
        if kind == "address":
            atoms = res.address_atoms(uid)
            if atoms is None:
                return None
            out.extend(_addr_iv(atoms))
        else:
            atoms = res.service_atoms(uid)
            if atoms is None:
                return None
            iv = _svc_iv(atoms)
            if iv is None:
                return None
            out.extend(iv)
    return out or None


def boxes(dims: tuple[list, list, list]) -> list[Box]:
    return [(a, b, c) for a in dims[0] for b in dims[1] for c in dims[2]]


def _minus(box: Box, cut: Box) -> list[Box]:
    """box minus cut, as at most six disjoint boxes."""
    for k in range(3):
        if box[k][1] < cut[k][0] or cut[k][1] < box[k][0]:
            return [box]                  # disjoint
    out: list[Box] = []
    cur = list(box)
    for k in range(3):
        lo, hi = cur[k]
        clo, chi = cut[k]
        if lo < clo:
            piece = list(cur); piece[k] = (lo, clo - 1); out.append(tuple(piece))
            lo = clo
        if chi < hi:
            piece = list(cur); piece[k] = (chi + 1, hi); out.append(tuple(piece))
            hi = chi
        cur[k] = (lo, hi)
    return out                            # what is left of cur is inside cut


def _intersects(a: Box, b: Box) -> bool:
    return all(not (a[k][1] < b[k][0] or b[k][1] < a[k][0]) for k in range(3))


def covered(later: list[Box], earlier: list[tuple[Any, list[Box]]]) -> tuple[bool, list[Any], bool]:
    """
    (is_covered, earlier keys that overlap the later rule, gave_up).

    `earlier` is [(key, boxes)] in rule order.
    """
    rest = list(later)
    used: list[Any] = []
    # cheap pre-filter: an earlier box that misses the later rule's bounding
    # box cannot remove anything from it
    hull = tuple((min(b[k][0] for b in later), max(b[k][1] for b in later)) for k in range(3)) if later else None
    earlier = [(key, [b for b in eb if _intersects(b, hull)]) for key, eb in earlier] if hull else []
    earlier = [(key, eb) for key, eb in earlier if eb]
    for key, eb in earlier:
        if not rest:
            break
        touched = False
        nxt: list[Box] = []
        for r in rest:
            pieces = [r]
            for cut in eb:
                if any(_intersects(p, cut) for p in pieces):
                    touched = True
                    pieces = [q for p in pieces for q in _minus(p, cut)]
            nxt.extend(pieces)
        if touched:
            used.append(key)
        rest = nxt
        if len(rest) > MAX_BOXES:
            return False, used, True
    return (not rest), used, False
