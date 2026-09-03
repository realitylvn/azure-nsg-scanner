import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import azure.functions as func
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.storage.blob import BlobServiceClient

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


def _parse_ports(raw):
    """'22, 3389 ,1433' -> [22, 3389, 1433]. Whitespace tolerated, blanks skipped."""
    return [int(p.strip()) for p in raw.split(",") if p.strip()]


def _query_all_nsgs(credential, subscription_id):
    """One KQL query for every NSG in the subscription, paged via skip_token.
    Returns the raw Resource Graph row list (default objectArray result format)."""
    client = ResourceGraphClient(credential)
    query = (
        "Resources "
        "| where type =~ 'microsoft.network/networksecuritygroups' "
        "| project name, resourceGroup, properties"
    )
    rows = []
    skip_token = None
    while True:
        request = QueryRequest(
            subscriptions=[subscription_id],
            query=query,
            options=QueryRequestOptions(skip_token=skip_token) if skip_token else None,
        )
        response = client.resources(request)
        rows.extend(response.data or [])
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            return rows


def _state_container():
    """Container client for the dedupe-state blob, over an account-key connection
    string - NOT the managed identity. The identity holds only a network-read
    custom role and has no data-plane role on this storage account; granting one
    just to write a timestamp would widen it. STATE_STORAGE_CONNECTION_STRING is
    the same account key as AzureWebJobsStorage, wired in resources.bicep."""
    blob_service = BlobServiceClient.from_connection_string(
        os.environ["STATE_STORAGE_CONNECTION_STRING"]
    )
    return blob_service.get_container_client(os.environ["STATE_CONTAINER_NAME"])


def _get_last_alert_time(container):
    blob = container.get_blob_client(STATE_BLOB_NAME)
    if not blob.exists():
        return None
    data = json.loads(blob.download_blob().readall())
    return datetime.fromisoformat(data["last_alert_utc"])


def _read_last_alert_time(container):
    """_get_last_alert_time, but a storage failure returns None instead of raising.
    The dedupe timestamp is best-effort: worst case is one duplicate email, which
    beats crashing a run that might need to alert."""
    try:
        return _get_last_alert_time(container)
    except Exception as exc:  # noqa: BLE001
        logging.warning(f"Could not read dedupe state, treating as no prior alert: {exc}")
        return None


def _set_last_alert_time(container, when):
    blob = container.get_blob_client(STATE_BLOB_NAME)
    blob.upload_blob(json.dumps({"last_alert_utc": when.isoformat()}), overwrite=True)


app = func.FunctionApp()


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def nsg_scan(timer: func.TimerRequest) -> None:
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    sensitive_ports = _parse_ports(os.environ.get("SENSITIVE_PORTS", "22,3389"))
    cooldown_days = int(os.environ.get("ALERT_COOLDOWN_DAYS", "3"))

    credential = DefaultAzureCredential()

    try:
        rows = _query_all_nsgs(credential, subscription_id)
    except AzureError as exc:
        # Transient throttle / API error. Log and skip - do NOT prefix, this must
        # not fire the scanner-error alert on a one-off blip.
        logging.error(f"Resource Graph query failed, skipping this run: {exc}")
        return
    except Exception as exc:  # noqa: BLE001 - nothing here may crash the app
        logging.error(f"NsgScannerError: unexpected error querying Resource Graph: {exc}")
        return

    try:
        nsgs = build_nsg_list(rows)
    except Exception as exc:  # noqa: BLE001
        logging.error(f"NsgScannerError: could not parse Resource Graph results: {exc}")
        return

    now = datetime.now(timezone.utc)
    container = _state_container()
    last_alert = _read_last_alert_time(container)

    decision = evaluate_exposure(
        nsgs,
        sensitive_ports=sensitive_ports,
        last_alert_utc=last_alert,
        now=now,
        cooldown_days=cooldown_days,
    )

    if decision.outcome == "no_nsgs":
        logging.info("NsgScanner: no NSGs in the subscription to evaluate.")
    elif decision.outcome == "clean":
        logging.info(
            f"NsgScanner: {len(nsgs)} NSG(s) evaluated, 0 exposed rules found."
        )
    elif decision.outcome == "suppressed":
        n = len(decision.findings)
        logging.info(
            f"NsgScanner: {n} exposed rule/port combination(s) still present but "
            f"suppressed - last alert was within the {cooldown_days}-day cooldown."
        )
    elif decision.outcome == "exposed":
        n = len(decision.findings)
        nsg_count = len({f.nsg_name for f in decision.findings})
        detail = "; ".join(
            f"{f.nsg_name}/{f.rule_name} exposes port {f.port} to {f.source}"
            for f in decision.findings
        )
        # This "NsgExposureFound:" prefix is what infra/resources.bicep's exposure
        # scheduledQueryRules alert matches on - keep them in sync.
        logging.warning(
            f"NsgExposureFound: {n} exposed rule/port combination(s) across "
            f"{nsg_count} NSG(s) - {detail}"
        )
        # The alert is already raised via the trace above. A failure to persist the
        # cooldown timestamp must not fail the run - worst case is a duplicate email.
        try:
            _set_last_alert_time(container, now)
        except Exception as exc:  # noqa: BLE001
            logging.warning(f"Could not persist dedupe timestamp: {exc}")
