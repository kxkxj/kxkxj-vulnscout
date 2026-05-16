import json

import pytest

from vulnscout.models.schemas import Scan, Vulnerability
from vulnscout.utils.report_formatter import format_report


@pytest.fixture
def scan(db_session):
    s = Scan(source_type="local", source_path="/test", vuln_count_high=1)
    db_session.add(s)
    db_session.commit()
    return s


@pytest.fixture
def vulns(scan, db_session):
    v = Vulnerability(
        scan_id=scan.id,
        file_path="app.py",
        line_start=10,
        cwe_id="CWE-89",
        severity="high",
        title="SQL Injection",
    )
    db_session.add(v)
    db_session.commit()
    return [v]


def test_format_json(scan, vulns):
    content, media_type = format_report(scan, vulns, "json")
    assert media_type == "application/json"
    data = json.loads(content)
    assert data["summary"]["high"] == 1
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["cwe_id"] == "CWE-89"


def test_format_markdown(scan, vulns):
    content, media_type = format_report(scan, vulns, "markdown")
    assert media_type == "text/markdown"
    assert "VulnScout Scan Report" in content
    assert "SQL Injection" in content
    assert "CWE-89" in content


def test_format_sarif(scan, vulns):
    content, media_type = format_report(scan, vulns, "sarif")
    assert media_type == "application/json"
    data = json.loads(content)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_format_defaults_to_json(scan, vulns):
    content, media_type = format_report(scan, vulns)
    assert media_type == "application/json"


def test_format_json_empty_vulns(db_session):
    scan = Scan(source_type="local", source_path="/empty")
    db_session.add(scan)
    db_session.commit()
    content, media_type = format_report(scan, [], "json")
    assert media_type == "application/json"
    data = json.loads(content)
    assert len(data["vulnerabilities"]) == 0
