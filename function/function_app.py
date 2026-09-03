import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import azure.functions as func

# The azure-identity / azure-storage SDKs log every HTTP request at INFO, which
# buries this function's own one-line decision trace (the thing the Log Alert
# matches on). Quiet them to WARNING - real failures still surface.
logging.getLogger("azure").setLevel(logging.WARNING)

OPEN_SOURCE_TOKENS = {"*", "0.0.0.0/0", "internet", "::/0"}
STATE_BLOB_NAME = "last-alert.json"


@dataclass(frozen=True)
class ExposureFinding:
    nsg_name: str
    resource_group: str
    rule_name: str
    port: int
    source: str


@dataclass(frozen=True)
class ScanDecision:
    """Outcome of evaluating every NSG in the subscription against the risk criteria.

    outcome is one of: "no_nsgs", "clean", "exposed", "suppressed".
    findings holds one ExposureFinding per (rule, sensitive-port) match, populated
    for "exposed" and "suppressed", empty otherwise.
    """

    outcome: str
    findings: tuple = ()


def _port_spec_matches(spec, port: int) -> bool:
    """True when a destination-port spec covers `port`. A spec is "*", a single
    port "N", or an inclusive range "LO-HI". Comparison is by integer value, not
    string - so "3000-4000" covers 3389 and "100-200" does not cover 22."""
    spec = str(spec).strip()
    if spec == "*":
        return True
    if "-" in spec:
        lo, _, hi = spec.partition("-")
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    try:
        return int(spec) == port
    except ValueError:
        return False


def _open_source(rule):
    """Return the first source entry that makes this rule internet-facing, or None."""
    for s in rule.get("sources", []):
        if s and s.lower() in OPEN_SOURCE_TOKENS:
            return s
    return None


def _is_open_inbound_allow(rule) -> bool:
    return (
        (rule.get("direction") or "").lower() == "inbound"
        and (rule.get("access") or "").lower() == "allow"
        and (rule.get("protocol") or "").lower() in ("tcp", "*")
        and _open_source(rule) is not None
    )


def evaluate_exposure(
    nsgs,
    *,
    sensitive_ports,
    last_alert_utc,
    now,
    cooldown_days,
) -> ScanDecision:
    """Decide whether any NSG exposes a sensitive port to the internet, and whether
    this run should alert. Pure: no I/O, no clock, no globals.

    Only custom securityRules are considered - the caller strips defaultSecurityRules
    during normalization.
    """
    if not nsgs:
        return ScanDecision("no_nsgs")

    findings = []
    for nsg in nsgs:
        for rule in nsg.get("rules", []):
            if not _is_open_inbound_allow(rule):
                continue
            source = _open_source(rule)
            specs = rule.get("dest_ports", [])
            for port in sensitive_ports:
                if any(_port_spec_matches(s, port) for s in specs):
                    findings.append(
                        ExposureFinding(
                            nsg["name"], nsg["resourceGroup"], rule["name"], port, source
                        )
                    )

    if not findings:
        return ScanDecision("clean")

    findings = tuple(
        sorted(findings, key=lambda f: (f.nsg_name, f.rule_name, f.port))
    )
    if last_alert_utc is not None and (now - last_alert_utc) < timedelta(days=cooldown_days):
        return ScanDecision("suppressed", findings)
    return ScanDecision("exposed", findings)


def _merge_prefixes(singular, plural):
    """Azure populates exactly one of the singular ("sourceAddressPrefix") or
    plural ("sourceAddressPrefixes") form per field. Return a single list with the
    Nones and empties dropped."""
    out = []
    if isinstance(singular, str) and singular:
        out.append(singular)
    for p in plural or []:
        if p:
            out.append(p)
    return out


def build_nsg_list(rows):
    """Normalize Azure Resource Graph NSG rows into the flat shape evaluate_exposure
    consumes. Only custom securityRules are kept; defaultSecurityRules is ignored -
    none of the platform defaults allow inbound Internet -> a sensitive port."""
    result = []
    for row in rows:
        props = row.get("properties") or {}
        rules = []
        for r in props.get("securityRules") or []:
            rp = r.get("properties") or {}
            rules.append(
                {
                    "name": r.get("name"),
                    "priority": rp.get("priority"),
                    "direction": rp.get("direction"),
                    "access": rp.get("access"),
                    "protocol": rp.get("protocol"),
                    "sources": _merge_prefixes(
                        rp.get("sourceAddressPrefix"), rp.get("sourceAddressPrefixes")
                    ),
                    "dest_ports": _merge_prefixes(
                        rp.get("destinationPortRange"), rp.get("destinationPortRanges")
                    ),
                }
            )
        result.append(
            {
                "name": row.get("name"),
                "resourceGroup": row.get("resourceGroup"),
                "rules": rules,
            }
        )
    return result


app = func.FunctionApp()


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def nsg_scan(timer: func.TimerRequest) -> None:
    """Placeholder - fleshed out in Task 4."""
