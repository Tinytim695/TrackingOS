"""Bug-bounty OSINT scope gate.

A program file is the asset boundary. DNS lookups run only after the name
matches that program and a separate grant allows network. Out-of-scope wins.
This module does not scan ports, fuzz, or send exploit payloads.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import threading
from dataclasses import dataclass
from typing import Callable

from trackingos.evidence import CASE_RE, CaseStore
from trackingos.models import AuthorizationGrant

PROGRAM_RE = re.compile(r"^PROG-[0-9A-F]{16}$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "private", "other"}

# Wildcard bases equal to these are rejected. They are public suffixes or
# shared hosting zones, not a single bounty program.
_PUBLIC_SUFFIXES = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "uk",
        "us",
        "de",
        "fr",
        "nl",
        "au",
        "ca",
        "jp",
        "br",
        "in",
        "ru",
        "cn",
        "app",
        "dev",
        "ai",
        "cloud",
        "info",
        "biz",
        "me",
        "tv",
        "cc",
        "xyz",
        "online",
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "co.nz",
        "com.br",
        "co.jp",
        "co.in",
        "com.mx",
        "co.za",
        "com.sg",
        "com.tr",
        "github.io",
        "blogspot.com",
        "amazonaws.com",
        "azurewebsites.net",
        "cloudfront.net",
        "herokuapp.com",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "firebaseapp.com",
        "s3.amazonaws.com",
        "localhost",
        "local",
        "internal",
    }
)

_MAX_DOMAINS = 256
_MAX_CIDRS = 32
Resolver = Callable[[str], tuple[str, ...]]


@dataclass(frozen=True)
class BountyProgram:
    program_id: str
    case_id: str
    name: str
    platform: str
    in_scope_domains: tuple[str, ...]
    out_of_scope_domains: tuple[str, ...]
    in_scope_cidrs: tuple[str, ...]
    out_of_scope_cidrs: tuple[str, ...]
    allow_dns: bool
    created_at: str

    def to_document(self) -> dict[str, object]:
        return {
            "schema": 1,
            "kind": "bounty-program",
            "program_id": self.program_id,
            "case_id": self.case_id,
            "name": self.name,
            "platform": self.platform,
            "in_scope_domains": list(self.in_scope_domains),
            "out_of_scope_domains": list(self.out_of_scope_domains),
            "in_scope_cidrs": list(self.in_scope_cidrs),
            "out_of_scope_cidrs": list(self.out_of_scope_cidrs),
            "allow_dns": self.allow_dns,
            "allow_active": False,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    kind: str
    value: str


def normalize_domain(value: str, *, wildcard_ok: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or "\x00" in value:
        raise ValueError("invalid domain")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
        raise ValueError("invalid domain")
    text = value.strip().lower()
    if text != value.strip().lower() or any(ch in text for ch in " %\\/@#?"):
        raise ValueError("invalid domain")
    wildcard = False
    if text.startswith("*."):
        if not wildcard_ok:
            raise ValueError("wildcard is not valid for this field")
        wildcard = True
        text = text[2:]
    if text.endswith(".") or "*" in text or ".." in text or text.startswith("."):
        raise ValueError("invalid domain")
    labels = text.split(".")
    if len(labels) < 2 or any(not _LABEL.match(label) for label in labels):
        raise ValueError("invalid domain")
    if text in _PUBLIC_SUFFIXES or (wildcard and text in _PUBLIC_SUFFIXES):
        raise ValueError("domain is too broad for a bounty program")
    if wildcard:
        return "*." + text
    return text


def normalize_cidr(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64 or any(ch.isspace() for ch in value):
        raise ValueError("invalid cidr")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("invalid cidr") from exc
    if network.version == 4 and network.prefixlen < 20:
        raise ValueError("cidr is too broad for a bounty program")
    if network.version == 6 and network.prefixlen < 48:
        raise ValueError("cidr is too broad for a bounty program")
    return str(network)


def make_program(
    *,
    program_id: str,
    case_id: str,
    name: str,
    platform: str,
    in_scope_domains: list[str],
    out_of_scope_domains: list[str],
    in_scope_cidrs: list[str],
    out_of_scope_cidrs: list[str],
    allow_dns: bool,
    created_at: str,
) -> BountyProgram:
    if not PROGRAM_RE.match(program_id):
        raise ValueError("invalid program id")
    if not CASE_RE.match(case_id):
        raise ValueError("invalid case id")
    if not isinstance(name, str) or not name.strip() or len(name) > 200 or any(ord(ch) < 32 for ch in name):
        raise ValueError("invalid program name")
    if platform not in _PLATFORMS:
        raise ValueError("invalid platform")
    if type(allow_dns) is not bool:
        raise ValueError("allow_dns must be a boolean")
    domains_in = _unique_domains(in_scope_domains, wildcard_ok=True)
    domains_out = _unique_domains(out_of_scope_domains, wildcard_ok=True)
    cidrs_in = _unique_cidrs(in_scope_cidrs)
    cidrs_out = _unique_cidrs(out_of_scope_cidrs)
    if not domains_in and not cidrs_in:
        raise ValueError("program needs at least one in-scope domain or cidr")
    return BountyProgram(
        program_id=program_id,
        case_id=case_id,
        name=name.strip(),
        platform=platform,
        in_scope_domains=tuple(domains_in),
        out_of_scope_domains=tuple(domains_out),
        in_scope_cidrs=tuple(cidrs_in),
        out_of_scope_cidrs=tuple(cidrs_out),
        allow_dns=allow_dns,
        created_at=created_at,
    )


def program_from_document(document: object) -> BountyProgram:
    if not isinstance(document, dict) or document.get("schema") != 1 or document.get("kind") != "bounty-program":
        raise ValueError("invalid bounty program")
    if document.get("allow_active") is not False:
        raise ValueError("osint programs cannot enable active testing")
    return make_program(
        program_id=document.get("program_id"),  # type: ignore[arg-type]
        case_id=document.get("case_id"),  # type: ignore[arg-type]
        name=document.get("name"),  # type: ignore[arg-type]
        platform=document.get("platform"),  # type: ignore[arg-type]
        in_scope_domains=list(document.get("in_scope_domains") or []),
        out_of_scope_domains=list(document.get("out_of_scope_domains") or []),
        in_scope_cidrs=list(document.get("in_scope_cidrs") or []),
        out_of_scope_cidrs=list(document.get("out_of_scope_cidrs") or []),
        allow_dns=document.get("allow_dns"),  # type: ignore[arg-type]
        created_at=document.get("created_at") if isinstance(document.get("created_at"), str) else "",
    )


def save_program(store: CaseStore, program: BountyProgram) -> None:
    store.write_record(program.case_id, "osint", f"{program.program_id}.json", program.to_document())


def load_programs(store: CaseStore, case_id: str) -> tuple[BountyProgram, ...]:
    programs = []
    for document in store.list_records(case_id, "osint"):
        if document.get("kind") != "bounty-program":
            continue
        program = program_from_document(document)
        if program.case_id != case_id:
            raise ValueError("program case id does not match")
        programs.append(program)
    programs.sort(key=lambda item: (item.created_at, item.program_id))
    return tuple(programs)


def select_program(programs: tuple[BountyProgram, ...], program_id: str | None) -> BountyProgram:
    if program_id is not None:
        if not PROGRAM_RE.match(program_id):
            raise ValueError("invalid program id")
        matches = [item for item in programs if item.program_id == program_id]
        if len(matches) != 1:
            raise ValueError("program not found")
        return matches[0]
    if len(programs) == 1:
        return programs[0]
    if not programs:
        raise ValueError("case has no bounty program")
    raise ValueError("case has multiple programs; pass --program")


def decide_target(program: BountyProgram, target: str) -> ScopeDecision:
    kind, value = parse_target(target)
    if kind == "ip":
        return _decide_ip(program, value)
    if _domain_matches(value, program.out_of_scope_domains):
        return ScopeDecision(False, "explicitly_out_of_scope", "host", value)
    if _domain_matches(value, program.in_scope_domains):
        return ScopeDecision(True, "in_scope", "host", value)
    return ScopeDecision(False, "out_of_scope", "host", value)


def authorize_dns(
    program: BountyProgram,
    target: str,
    grant: AuthorizationGrant | None,
    now: dt.datetime,
) -> ScopeDecision:
    decision = decide_target(program, target)
    if not decision.allowed:
        return decision
    if decision.kind != "host":
        return ScopeDecision(False, "dns_requires_hostname", decision.kind, decision.value)
    if not program.allow_dns:
        return ScopeDecision(False, "dns_not_authorised", "host", decision.value)
    if grant is None:
        return ScopeDecision(False, "missing_grant", "host", decision.value)
    if now.tzinfo is None:
        return ScopeDecision(False, "clock_naive", "host", decision.value)
    moment = now.astimezone(dt.timezone.utc)
    if moment < grant.not_before:
        return ScopeDecision(False, "grant_not_yet_valid", "host", decision.value)
    if moment >= grant.not_after:
        return ScopeDecision(False, "grant_expired", "host", decision.value)
    if not grant.allow_network:
        return ScopeDecision(False, "network_not_authorised", "host", decision.value)
    return ScopeDecision(True, "authorised", "host", decision.value)


def dns_lookup(
    program: BountyProgram,
    target: str,
    grant: AuthorizationGrant | None,
    *,
    now: dt.datetime,
    resolver: Resolver,
) -> dict[str, object]:
    decision = authorize_dns(program, target, grant, now)
    if not decision.allowed:
        return {
            "executed": False,
            "reason": decision.reason,
            "host": decision.value,
            "addresses": [],
            "outside_cidr": [],
        }
    addresses = tuple(resolver(decision.value))[:32]
    outside = [item for item in addresses if _address_outside_program(program, item)]
    return {
        "executed": True,
        "reason": "resolved",
        "host": decision.value,
        "addresses": list(addresses),
        "outside_cidr": outside,
    }


def parse_target(target: str) -> tuple[str, str]:
    if not isinstance(target, str) or not target or len(target) > 2048 or "\x00" in target:
        raise ValueError("invalid target")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in target):
        raise ValueError("invalid target")
    kind, sep, rest = target.partition(":")
    if sep != ":" or kind not in ("host", "ip", "url") or not rest:
        raise ValueError("invalid target")
    if kind == "host":
        return "host", normalize_domain(rest, wildcard_ok=False)
    if kind == "ip":
        try:
            address = ipaddress.ip_address(rest)
        except ValueError as exc:
            raise ValueError("invalid target") from exc
        if address.is_unspecified or address.is_multicast:
            raise ValueError("invalid target")
        return "ip", str(address)
    value = _host_from_url(rest)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "host", value
    if address.is_unspecified or address.is_multicast:
        raise ValueError("invalid target")
    return "ip", str(address)


def system_resolver(host: str) -> tuple[str, ...]:
    """Resolve A/AAAA only. One name, five-second cap, no follow-on connection."""
    box: dict[str, object] = {}

    def work() -> None:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            box["error"] = exc
            return
        found = []
        for info in infos:
            addr = info[4][0]
            if addr not in found:
                found.append(addr)
        box["addresses"] = tuple(found)

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(5)
    if thread.is_alive():
        raise TimeoutError("dns lookup timed out")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    addresses = box.get("addresses")
    if not isinstance(addresses, tuple):
        return ()
    return addresses


def _host_from_url(url: str) -> str:
    if "@" in url or "\\" in url or "%" in url or any(ch.isspace() for ch in url):
        raise ValueError("invalid target")
    scheme, sep, remainder = url.partition("://")
    if sep != "://" or scheme not in ("http", "https") or not remainder:
        raise ValueError("invalid target")
    authority = remainder.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not authority or "@" in authority:
        raise ValueError("invalid target")
    host = authority
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            raise ValueError("invalid target")
        inner = host[1:end]
        try:
            address = ipaddress.ip_address(inner)
        except ValueError as exc:
            raise ValueError("invalid target") from exc
        return str(address)
    host = host.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return normalize_domain(host, wildcard_ok=False)
    return str(address)


def _decide_ip(program: BountyProgram, value: str) -> ScopeDecision:
    address = ipaddress.ip_address(value)
    if _ip_in(address, program.out_of_scope_cidrs):
        return ScopeDecision(False, "explicitly_out_of_scope", "ip", value)
    if _ip_in(address, program.in_scope_cidrs):
        return ScopeDecision(True, "in_scope", "ip", value)
    return ScopeDecision(False, "out_of_scope", "ip", value)


def _ip_in(address: ipaddress._BaseAddress, cidrs: tuple[str, ...]) -> bool:
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=True)
        if address.version == network.version and address in network:
            return True
    return False


def _address_outside_program(program: BountyProgram, text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    if _ip_in(address, program.out_of_scope_cidrs):
        return True
    if not program.in_scope_cidrs:
        return True
    return not _ip_in(address, program.in_scope_cidrs)


def _domain_matches(host: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern.startswith("*."):
            base = pattern[2:]
            if host != base and host.endswith("." + base):
                return True
        elif host == pattern:
            return True
    return False


def _unique_domains(values: list[str], *, wildcard_ok: bool) -> list[str]:
    if len(values) > _MAX_DOMAINS:
        raise ValueError("too many domains")
    found: list[str] = []
    for value in values:
        domain = normalize_domain(value, wildcard_ok=wildcard_ok)
        if domain not in found:
            found.append(domain)
    return found


def _unique_cidrs(values: list[str]) -> list[str]:
    if len(values) > _MAX_CIDRS:
        raise ValueError("too many cidrs")
    found: list[str] = []
    for value in values:
        cidr = normalize_cidr(value)
        if cidr not in found:
            found.append(cidr)
    return found
