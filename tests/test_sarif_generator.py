import json
from pathlib import Path
import pytest
from sarif_generator import parse_markdown, find_declaration_line, build_sarif, main

# All tests must run from workspace root: /Users/shivani/appsecai-internship/
# Run with: pytest tests/ -v


def test_parse_markdown_table_fields():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["cve_id"] == "CVE-2023-41080"
    assert data["cwe_id"] == "CWE-601"
    assert data["cwe_description"] == "URL Redirection to Untrusted Site — Open Redirect"
    assert data["severity"] == "Moderate"
    assert data["d1_score"] == 1
