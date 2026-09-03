"""Unit tests for build_status_dict - the pure ScanDecision -> status.json
contract mapping - plus the non-fatal _publish_status helper. No Azure, no
network, no clock."""

from datetime import datetime, timezone

from function_app import ExposureFinding, ScanDecision, build_status_dict

NOW = datetime(2026, 9, 4, 6, 0, 0, tzinfo=timezone.utc)
TS = "2026-09-04T06:00:00Z"

FINDING = ExposureFinding(
    nsg_name="nsg-demo-exposed",
    resource_group="rg-nsg-scanner-demo-dev",
    rule_name="AllowSSH",
    port=22,
    source="Internet",
)


def _assert_fixed(d):
    assert d["schema_version"] == 1
    assert d["project"] == "azure-nsg-scanner"
    assert d["cadence"] == "scheduled-daily"
    assert d["repo_url"] == "https://github.com/realitylvn/azure-nsg-scanner"
    assert d["generated_at"] == TS
    assert d["last_run_at"] == TS


def test_no_nsgs_is_ok():
    d = build_status_dict(ScanDecision("no_nsgs"), NOW, nsgs_scanned=0)
    _assert_fixed(d)
    assert d["status"] == "ok"
    assert "No NSGs" in d["headline"]
    assert d["detail"] == {"nsgs_scanned": 0, "findings": []}


def test_clean_is_ok_with_the_count_in_the_headline():
    d = build_status_dict(ScanDecision("clean"), NOW, nsgs_scanned=3)
    assert d["status"] == "ok"
    assert "3" in d["headline"]
    assert d["detail"] == {"nsgs_scanned": 3, "findings": []}


def test_exposed_is_a_finding_with_findings_in_detail():
    d = build_status_dict(
        ScanDecision("exposed", (FINDING,)), NOW, nsgs_scanned=3
    )
    assert d["status"] == "finding"
    assert d["detail"]["nsgs_scanned"] == 3
    assert d["detail"]["findings"] == [
        {"nsg": "nsg-demo-exposed", "rule": "AllowSSH", "port": 22, "source": "Internet"}
    ]


def test_suppressed_is_a_finding_and_says_cooldown():
    d = build_status_dict(
        ScanDecision("suppressed", (FINDING,)), NOW, nsgs_scanned=3
    )
    assert d["status"] == "finding"
    assert "cooldown" in d["headline"]
    assert len(d["detail"]["findings"]) == 1


def test_error_reason_is_an_error():
    d = build_status_dict(
        None, NOW, nsgs_scanned=0, error_reason="Resource Graph scan failed"
    )
    _assert_fixed(d)
    assert d["status"] == "error"
    assert d["headline"] == "Resource Graph scan failed"
    assert d["detail"] == {"nsgs_scanned": 0, "findings": []}


def test_result_is_json_serializable():
    import json

    json.dumps(build_status_dict(ScanDecision("exposed", (FINDING,)), NOW, nsgs_scanned=3))


def test_web_container_uses_the_connection_string_and_web_container(monkeypatch):
    import function_app

    captured = {}

    class FakeBlobService:
        @classmethod
        def from_connection_string(cls, conn_str):
            captured["conn_str"] = conn_str
            return cls()

        def get_container_client(self, name):
            captured["container"] = name
            return "cc"

    monkeypatch.setattr(function_app, "BlobServiceClient", FakeBlobService)
    monkeypatch.setenv(
        "STATE_STORAGE_CONNECTION_STRING",
        "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=k;EndpointSuffix=core.windows.net",
    )
    assert function_app._web_container() == "cc"
    assert "AccountKey=" in captured["conn_str"]
    assert captured["container"] == "$web"


def test_publish_status_swallows_a_storage_failure(monkeypatch):
    import function_app

    def boom():
        raise RuntimeError("down")

    monkeypatch.setattr(function_app, "_web_container", boom)
    function_app._publish_status({"schema_version": 1})
