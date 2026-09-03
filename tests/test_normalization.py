"""build_nsg_list turns the Azure Resource Graph row shape into the flat dict
form evaluate_exposure consumes: merges the singular + plural address/port fields,
keeps only custom securityRules, tolerates missing keys."""

from datetime import datetime, timezone

from function_app import build_nsg_list, evaluate_exposure

# One Resource Graph row for an NSG that mixes the singular and plural ARM forms
# and carries a platform default rule that must be ignored.
ROW = {
    "name": "nsg-nsg-scanner-demo-dev",
    "resourceGroup": "rg-nsg-scanner-demo-dev",
    "properties": {
        "securityRules": [
            {
                "name": "allow-ssh-from-internet",
                "properties": {
                    "priority": 100,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "22",
                },
            },
            {
                "name": "allow-mixed",
                "properties": {
                    "priority": 105,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "sourceAddressPrefix": None,
                    "sourceAddressPrefixes": ["10.0.0.0/8", "Internet"],
                    "destinationPortRanges": ["3389", "8080"],
                },
            },
        ],
        "defaultSecurityRules": [
            {
                "name": "AllowInternetInBound-default-should-be-ignored",
                "properties": {
                    "priority": 65001,
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "*",
                },
            }
        ],
    },
}


def test_build_nsg_list_flattens_name_and_rg():
    [nsg] = build_nsg_list([ROW])
    assert nsg["name"] == "nsg-nsg-scanner-demo-dev"
    assert nsg["resourceGroup"] == "rg-nsg-scanner-demo-dev"


def test_default_security_rules_are_excluded():
    [nsg] = build_nsg_list([ROW])
    assert [r["name"] for r in nsg["rules"]] == ["allow-ssh-from-internet", "allow-mixed"]


def test_singular_source_and_port_become_single_element_lists():
    [nsg] = build_nsg_list([ROW])
    ssh = nsg["rules"][0]
    assert ssh["sources"] == ["Internet"]
    assert ssh["dest_ports"] == ["22"]


def test_plural_fields_merge_and_drop_none():
    [nsg] = build_nsg_list([ROW])
    mixed = nsg["rules"][1]
    assert mixed["sources"] == ["10.0.0.0/8", "Internet"]
    assert mixed["dest_ports"] == ["3389", "8080"]


def test_empty_row_list_yields_empty_and_evaluates_to_no_nsgs():
    nsgs = build_nsg_list([])
    assert nsgs == []
    d = evaluate_exposure(
        nsgs,
        sensitive_ports=[22, 3389],
        last_alert_utc=None,
        now=datetime(2026, 9, 2, tzinfo=timezone.utc),
        cooldown_days=3,
    )
    assert d.outcome == "no_nsgs"


def test_normalized_demo_row_evaluates_to_exposed_ssh_and_rdp():
    d = evaluate_exposure(
        build_nsg_list([ROW]),
        sensitive_ports=[22, 3389, 1433, 3306, 5432],
        last_alert_utc=None,
        now=datetime(2026, 9, 2, tzinfo=timezone.utc),
        cooldown_days=3,
    )
    assert d.outcome == "exposed"
    assert {(f.rule_name, f.port) for f in d.findings} == {
        ("allow-ssh-from-internet", 22),
        ("allow-mixed", 3389),
    }
