"""Unit tests for the pure exposure-decision logic in function_app.evaluate_exposure.
Deterministic: no Azure, no network, no clock. The function takes a list of
normalized NSG dicts plus config and returns a ScanDecision; all I/O stays in the
entrypoint."""

from datetime import datetime, timedelta, timezone

from function_app import evaluate_exposure

NOW = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc)
PORTS = [22, 3389, 1433, 3306, 5432]


def _rule(**over):
    base = dict(
        name="r",
        priority=100,
        direction="Inbound",
        access="Allow",
        protocol="Tcp",
        sources=["Internet"],
        dest_ports=["22"],
    )
    base.update(over)
    return base


def _nsg(rules, name="nsg-demo", rg="rg-demo"):
    return {"name": name, "resourceGroup": rg, "rules": rules}


def _decide(nsgs, *, last_alert_utc=None, cooldown_days=3, now=NOW, ports=PORTS):
    return evaluate_exposure(
        nsgs,
        sensitive_ports=ports,
        last_alert_utc=last_alert_utc,
        now=now,
        cooldown_days=cooldown_days,
    )


def test_no_nsgs_returns_no_nsgs():
    d = _decide([])
    assert d.outcome == "no_nsgs"
    assert d.findings == ()


def test_benign_https_rule_is_clean():
    d = _decide([_nsg([_rule(name="allow-https", dest_ports=["443"])])])
    assert d.outcome == "clean"


def test_ssh_open_to_internet_is_a_finding():
    d = _decide([_nsg([_rule(name="allow-ssh-from-internet", dest_ports=["22"])])])
    assert d.outcome == "exposed"
    assert len(d.findings) == 1
    f = d.findings[0]
    assert (f.rule_name, f.port, f.source) == ("allow-ssh-from-internet", 22, "Internet")


def test_port_range_that_contains_sensitive_ports_is_a_finding():
    # 3000-4000 spans both MySQL (3306) and RDP (3389) - both must be reported.
    d = _decide([_nsg([_rule(dest_ports=["3000-4000"])])])
    assert d.outcome == "exposed"
    assert {f.port for f in d.findings} == {3306, 3389}


def test_port_range_that_excludes_all_sensitive_ports_is_clean():
    d = _decide([_nsg([_rule(dest_ports=["100-200"])])])
    assert d.outcome == "clean"


def test_destination_port_ranges_array_form_is_evaluated():
    d = _decide([_nsg([_rule(dest_ports=["21-23", "8080"])])])
    assert d.outcome == "exposed"
    assert {f.port for f in d.findings} == {22}


def test_star_port_from_internet_flags_every_sensitive_port():
    d = _decide([_nsg([_rule(dest_ports=["*"])])])
    assert d.outcome == "exposed"
    assert {f.port for f in d.findings} == set(PORTS)


def test_cidr_zero_slash_zero_is_internet_facing():
    d = _decide([_nsg([_rule(sources=["0.0.0.0/0"])])])
    assert d.outcome == "exposed"


def test_private_cidr_source_is_clean():
    d = _decide([_nsg([_rule(sources=["10.0.0.0/8"])])])
    assert d.outcome == "clean"


def test_deny_rule_is_clean():
    d = _decide([_nsg([_rule(access="Deny")])])
    assert d.outcome == "clean"


def test_outbound_rule_is_clean():
    d = _decide([_nsg([_rule(direction="Outbound")])])
    assert d.outcome == "clean"


def test_udp_only_rule_is_clean():
    d = _decide([_nsg([_rule(protocol="Udp", dest_ports=["3389"])])])
    assert d.outcome == "clean"


def test_findings_only_come_from_the_exposed_nsg():
    exposed = _nsg([_rule(name="bad", dest_ports=["3389"])], name="nsg-a")
    clean = _nsg([_rule(name="ok", dest_ports=["443"])], name="nsg-b")
    d = _decide([exposed, clean])
    assert d.outcome == "exposed"
    assert {f.nsg_name for f in d.findings} == {"nsg-a"}


def test_findings_present_but_inside_cooldown_is_suppressed():
    d = _decide(
        [_nsg([_rule(dest_ports=["22"])])],
        last_alert_utc=NOW - timedelta(days=1),
        cooldown_days=3,
    )
    assert d.outcome == "suppressed"
    assert len(d.findings) == 1


def test_findings_alert_again_once_cooldown_expires():
    d = _decide(
        [_nsg([_rule(dest_ports=["22"])])],
        last_alert_utc=NOW - timedelta(days=5),
        cooldown_days=3,
    )
    assert d.outcome == "exposed"


def test_source_in_plural_field_only_is_internet_facing():
    d = _decide([_nsg([_rule(sources=["Internet"])])])
    assert d.outcome == "exposed"
