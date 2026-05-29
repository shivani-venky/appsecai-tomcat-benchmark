# SARIF Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sarif_generator.py`, a stdlib-only Python script that reads three CVE markdown files from `fixes/` and writes one SARIF 2.1.0 file per CVE to `sarif/`.

**Architecture:** Single script with four public functions — `parse_markdown` (six-state line-by-line parser), `find_declaration_line` (regex search against patched Tomcat source), `build_sarif` (assembles the JSON dict), and `main` (orchestrates and writes files). One private helper `_parse_affected_component`. Tests run from the workspace root against real files in `fixes/` and `tomcat/`.

**Tech Stack:** Python 3.12, stdlib only (`re`, `json`, `pathlib`, `argparse`), pytest 7.4 for tests.

---

## File Map

| File | Status | Responsibility |
|---|---|---|
| `sarif_generator.py` | Create | `LEVEL_MAP`, `_parse_affected_component`, `parse_markdown`, `find_declaration_line`, `build_sarif`, `main`, argparse entry point |
| `tests/__init__.py` | Create (empty) | Makes `tests/` a package importable by pytest |
| `tests/test_sarif_generator.py` | Create | All unit and integration tests |

Run all tests from workspace root: `pytest tests/ -v`

---

### Task 1: `parse_markdown` — metadata table fields

**Files:**
- Create: `sarif_generator.py`
- Create: `tests/__init__.py`
- Create: `tests/test_sarif_generator.py`

- [ ] **Step 1: Create test infrastructure**

Create `tests/__init__.py` as an empty file.

Create `tests/test_sarif_generator.py`:

```python
import json
from pathlib import Path
import pytest
from sarif_generator import parse_markdown, find_declaration_line, build_sarif, main

# All tests must run from workspace root: /Users/shivani/appsecai-internship/
# Run with: pytest tests/ -v
```

- [ ] **Step 2: Write failing test for table fields**

Add to `tests/test_sarif_generator.py`:

```python
def test_parse_markdown_table_fields():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["cve_id"] == "CVE-2023-41080"
    assert data["cwe_id"] == "CWE-601"
    assert data["cwe_description"] == "URL Redirection to Untrusted Site — Open Redirect"
    assert data["severity"] == "Moderate"
    assert data["d1_score"] == 1
```

- [ ] **Step 3: Run to verify it fails**

```
pytest tests/test_sarif_generator.py::test_parse_markdown_table_fields -v
```

Expected: `ModuleNotFoundError: No module named 'sarif_generator'`

- [ ] **Step 4: Create `sarif_generator.py` with full state machine, table fields implemented**

`_parse_affected_component` is stubbed here (returns neutral values so the table test can run); it is fully implemented in Task 2.

Create `sarif_generator.py`:

```python
import re
import json
import argparse
from pathlib import Path


LEVEL_MAP = {"Low": "note", "Moderate": "warning", "High": "error"}


def _parse_affected_component(raw: str) -> dict:
    # Stub — fully implemented in Task 2.
    # Returns neutral values so parse_markdown can complete for Task 1 tests.
    return {"grep_term": "", "is_class": False, "all_methods": []}


def parse_markdown(path: Path) -> dict:
    data = {}
    state = "SCANNING_TABLE"
    before_lines = []
    before_file_path = None
    after_file_path = None
    done = False

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if state == "SCANNING_TABLE":
                m = re.match(r'\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|', line)
                if m:
                    field, value = m.group(1), m.group(2)
                    if field == "CVE ID":
                        data["cve_id"] = value
                    elif field == "CWE":
                        cwe_m = re.search(r'CWE-\d+', value)
                        desc_m = re.search(r'\((.+?)\)', value)
                        data["cwe_id"] = cwe_m.group(0) if cwe_m else value
                        data["cwe_description"] = desc_m.group(1) if desc_m else ""
                    elif field == "Severity":
                        data["severity"] = value
                    elif field == "D1 Score":
                        d1_m = re.match(r'(\d+)', value)
                        data["d1_score"] = int(d1_m.group(1)) if d1_m else 0
                    elif field == "Affected Component":
                        data.update(_parse_affected_component(value))
                elif line.startswith("## Before"):
                    state = "SCANNING_BEFORE"

            elif state == "SCANNING_BEFORE":
                m = re.match(r'`(java/.+?)`', line)
                if m:
                    before_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_BEFORE_CODE"

            elif state == "IN_BEFORE_CODE":
                if line.strip() == "```":
                    state = "SCANNING_AFTER"
                else:
                    before_lines.append(line)

            elif state == "SCANNING_AFTER":
                m = re.match(r'`(java/.+?)`', line)
                if m:
                    after_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_AFTER_CODE"

            elif state == "IN_AFTER_CODE":
                if line.strip() == "```":
                    done = True
                    break

    if not done:
        raise ValueError(f"{path.name}: did not reach end of After code block")

    data["before_lines"] = before_lines
    data["before_file_path"] = before_file_path
    paths = {p for p in [before_file_path, after_file_path] if p}
    data["files_touched"] = len(paths)

    for key in ["cve_id", "cwe_id", "severity", "d1_score"]:
        if key not in data:
            raise ValueError(f"{path.name}: missing field '{key}'")

    return data


def find_declaration_line(src_file: Path, grep_term: str, is_class: bool) -> int | None:
    raise NotImplementedError


def build_sarif(cve_data: dict, start_line: int, end_line: int) -> dict:
    raise NotImplementedError


def main(fixes_dir: Path, sarif_dir: Path, tomcat_dir: Path) -> None:
    raise NotImplementedError


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF 2.1.0 files from CVE markdown")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--sarif-dir", type=Path, default=Path("sarif"))
    parser.add_argument("--tomcat-dir", type=Path, default=Path("tomcat"))
    args = parser.parse_args()
    main(args.fixes_dir, args.sarif_dir, args.tomcat_dir)
```

- [ ] **Step 5: Run to verify it passes**

```
pytest tests/test_sarif_generator.py::test_parse_markdown_table_fields -v
```

Expected: `PASSED`

- [ ] **Step 6: Commit**

```bash
git add sarif_generator.py tests/__init__.py tests/test_sarif_generator.py
git commit -m "feat: parse_markdown table fields with state machine scaffold"
```

---

### Task 2: `parse_markdown` — code blocks + `_parse_affected_component`

**Files:**
- Modify: `sarif_generator.py` (replace `_parse_affected_component` stub)
- Modify: `tests/test_sarif_generator.py`

- [ ] **Step 1: Write failing tests for code block extraction and affected component**

Add to `tests/test_sarif_generator.py`:

```python
def test_parse_markdown_before_block():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["before_file_path"] == "java/org/apache/catalina/authenticator/FormAuthenticator.java"
    assert data["files_touched"] == 1
    assert len(data["before_lines"]) > 0
    joined = "\n".join(data["before_lines"])
    assert "protected String savedRequestURL(Session session)" in joined


def test_parse_markdown_affected_component_simple():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["grep_term"] == "savedRequestURL"
    assert data["is_class"] is False
    assert data["all_methods"] == ["savedRequestURL()"]


def test_parse_markdown_affected_component_dotted():
    data = parse_markdown(Path("fixes/CVE-2026-34483_before_after.md"))
    assert data["grep_term"] == "RequestElement"
    assert data["is_class"] is True
    assert data["all_methods"] == ["RequestElement.addElement()", "RequestURIElement.addElement()"]


def test_parse_markdown_low_severity():
    data = parse_markdown(Path("fixes/CVE-2026-24880_before_after.md"))
    assert data["severity"] == "Low"
    assert data["d1_score"] == 3
    assert data["grep_term"] == "parseChunkHeader"
    assert data["is_class"] is False
```

- [ ] **Step 2: Run to verify tests fail**

```
pytest tests/test_sarif_generator.py::test_parse_markdown_before_block tests/test_sarif_generator.py::test_parse_markdown_affected_component_simple tests/test_sarif_generator.py::test_parse_markdown_affected_component_dotted tests/test_sarif_generator.py::test_parse_markdown_low_severity -v
```

Expected: `FAILED` — `test_parse_markdown_affected_component_simple` will fail because `grep_term` is `""` from the stub; `test_parse_markdown_before_block` may pass already (code block extraction is already implemented in Task 1).

- [ ] **Step 3: Replace `_parse_affected_component` stub with real implementation**

Replace the `_parse_affected_component` function in `sarif_generator.py`:

```python
def _parse_affected_component(raw: str) -> dict:
    # Strip backtick markup, split on Unicode rightwards arrow
    raw = re.sub(r'`', '', raw)
    parts = re.split(r'\s*→\s*', raw, maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Affected Component has no → separator: {raw!r}")

    rhs = parts[1].strip()
    all_methods = [t.strip() for t in rhs.split(',')]

    # First token: strip parens to get bare reference (e.g. "RequestElement.addElement")
    first = all_methods[0].rstrip('()')
    if '.' in first:
        # Dotted reference: "ClassName.method" → grep for the class declaration
        class_name = first.split('.')[0]
        return {"grep_term": class_name, "is_class": True, "all_methods": all_methods}
    else:
        # Bare method name → grep for method declaration with access modifier
        return {"grep_term": first, "is_class": False, "all_methods": all_methods}
```

- [ ] **Step 4: Run to verify all four tests pass**

```
pytest tests/test_sarif_generator.py::test_parse_markdown_before_block tests/test_sarif_generator.py::test_parse_markdown_affected_component_simple tests/test_sarif_generator.py::test_parse_markdown_affected_component_dotted tests/test_sarif_generator.py::test_parse_markdown_low_severity -v
```

Expected: all four `PASSED`

- [ ] **Step 5: Run full test suite to confirm no regressions**

```
pytest tests/ -v
```

Expected: all tests `PASSED`

- [ ] **Step 6: Commit**

```bash
git add sarif_generator.py tests/test_sarif_generator.py
git commit -m "feat: implement _parse_affected_component and verify code block extraction"
```

---

### Task 3: `find_declaration_line`

**Files:**
- Modify: `sarif_generator.py` (replace stub)
- Modify: `tests/test_sarif_generator.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_sarif_generator.py`:

```python
def test_find_declaration_line_method():
    src = Path("tomcat/java/org/apache/catalina/authenticator/FormAuthenticator.java")
    line = find_declaration_line(src, "savedRequestURL", is_class=False)
    assert line == 755


def test_find_declaration_line_method_chunked():
    src = Path("tomcat/java/org/apache/coyote/http11/filters/ChunkedInputFilter.java")
    line = find_declaration_line(src, "parseChunkHeader", is_class=False)
    assert line == 365


def test_find_declaration_line_class():
    src = Path("tomcat/java/org/apache/catalina/valves/AbstractAccessLogValve.java")
    line = find_declaration_line(src, "RequestElement", is_class=True)
    assert line == 1343


def test_find_declaration_line_missing():
    src = Path("tomcat/java/org/apache/catalina/authenticator/FormAuthenticator.java")
    assert find_declaration_line(src, "nonexistentMethod", is_class=False) is None


def test_find_declaration_line_file_missing():
    assert find_declaration_line(Path("tomcat/java/does/not/Exist.java"), "foo", is_class=False) is None
```

- [ ] **Step 2: Run to verify they fail**

```
pytest tests/test_sarif_generator.py::test_find_declaration_line_method tests/test_sarif_generator.py::test_find_declaration_line_method_chunked tests/test_sarif_generator.py::test_find_declaration_line_class tests/test_sarif_generator.py::test_find_declaration_line_missing tests/test_sarif_generator.py::test_find_declaration_line_file_missing -v
```

Expected: `FAILED` with `NotImplementedError`

- [ ] **Step 3: Implement `find_declaration_line`**

Replace the `find_declaration_line` stub in `sarif_generator.py`:

```python
def find_declaration_line(src_file: Path, grep_term: str, is_class: bool) -> int | None:
    if not src_file.exists():
        return None

    if is_class:
        pattern = re.compile(rf'\bclass\s+{re.escape(grep_term)}\b')
    else:
        pattern = re.compile(rf'\b(?:private|protected|public)\b.*\b{re.escape(grep_term)}\b')

    with open(src_file, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if pattern.search(line):
                return lineno
    return None
```

- [ ] **Step 4: Run to verify all five tests pass**

```
pytest tests/test_sarif_generator.py::test_find_declaration_line_method tests/test_sarif_generator.py::test_find_declaration_line_method_chunked tests/test_sarif_generator.py::test_find_declaration_line_class tests/test_sarif_generator.py::test_find_declaration_line_missing tests/test_sarif_generator.py::test_find_declaration_line_file_missing -v
```

Expected: all five `PASSED`

- [ ] **Step 5: Run full test suite**

```
pytest tests/ -v
```

Expected: all tests `PASSED`

- [ ] **Step 6: Commit**

```bash
git add sarif_generator.py tests/test_sarif_generator.py
git commit -m "feat: implement find_declaration_line with access-modifier filter"
```

---

### Task 4: `build_sarif`

**Files:**
- Modify: `sarif_generator.py` (replace stub)
- Modify: `tests/test_sarif_generator.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_sarif_generator.py`:

```python
# Shared fixture used by multiple build_sarif tests
_MODERATE_CVE = {
    "cve_id": "CVE-2023-41080",
    "cwe_id": "CWE-601",
    "cwe_description": "URL Redirection to Untrusted Site — Open Redirect",
    "severity": "Moderate",
    "d1_score": 1,
    "before_file_path": "java/org/apache/catalina/authenticator/FormAuthenticator.java",
    "before_lines": [
        "protected String savedRequestURL(Session session) {",
        "    return null;",
        "}",
    ],
    "files_touched": 1,
    "grep_term": "savedRequestURL",
    "is_class": False,
    "all_methods": ["savedRequestURL()"],
}


def test_build_sarif_top_level_structure():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1


def test_build_sarif_tool_driver():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tomcat-cve-benchmark"
    rules = driver["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CVE-2023-41080"
    assert rules[0]["properties"]["tags"] == ["CWE-601"]
    assert rules[0]["properties"]["cwe"] == ["CWE-601"]


def test_build_sarif_result_fields():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CVE-2023-41080"
    assert result["level"] == "warning"
    # Severity label comes from markdown Severity field, not SARIF level string
    assert "(Moderate)" in result["message"]["text"]
    assert "CVE-2023-41080" in result["message"]["text"]


def test_build_sarif_region():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 755
    assert region["endLine"] == 757
    assert region["startColumn"] == 1
    assert region["endColumn"] == 80
    # All region fields must be JSON integers, not strings
    assert isinstance(region["startLine"], int)
    assert isinstance(region["endLine"], int)
    assert isinstance(region["startColumn"], int)
    assert isinstance(region["endColumn"], int)
    assert "protected String savedRequestURL" in region["snippet"]["text"]


def test_build_sarif_artifact_uri():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "java/org/apache/catalina/authenticator/FormAuthenticator.java"


def test_build_sarif_properties():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["cve"] == "CVE-2023-41080"
    assert props["patch_complexity_score"] == 1
    assert props["files_touched"] == 1
    assert isinstance(props["patch_complexity_score"], int)
    assert isinstance(props["files_touched"], int)


def test_build_sarif_level_low():
    low_cve = {
        **_MODERATE_CVE,
        "cve_id": "CVE-2026-24880",
        "severity": "Low",
        "d1_score": 3,
        "all_methods": ["parseChunkHeader()"],
    }
    sarif = build_sarif(low_cve, start_line=365, end_line=412)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert "(Low)" in result["message"]["text"]


def test_build_sarif_message_multi_method():
    multi_cve = {
        **_MODERATE_CVE,
        "cve_id": "CVE-2026-34483",
        "cwe_id": "CWE-117",
        "cwe_description": "Improper Output Neutralization for Logs",
        "severity": "Low",
        "d1_score": 1,
        "grep_term": "RequestElement",
        "is_class": True,
        "all_methods": ["RequestElement.addElement()", "RequestURIElement.addElement()"],
    }
    sarif = build_sarif(multi_cve, start_line=1343, end_line=1344)
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "RequestElement.addElement()" in msg
    assert "RequestURIElement.addElement()" in msg


def test_build_sarif_rule_id_matches_result_rule_id():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    rule_id = sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"]
    result_rule_id = sarif["runs"][0]["results"][0]["ruleId"]
    assert rule_id == result_rule_id
```

- [ ] **Step 2: Run to verify they fail**

```
pytest tests/test_sarif_generator.py -k "build_sarif" -v
```

Expected: all `FAILED` with `NotImplementedError`

- [ ] **Step 3: Implement `build_sarif`**

Replace the `build_sarif` stub in `sarif_generator.py`:

```python
def build_sarif(cve_data: dict, start_line: int, end_line: int) -> dict:
    cve_id = cve_data["cve_id"]
    cwe_id = cve_data["cwe_id"]
    cwe_desc = cve_data["cwe_description"]
    severity = cve_data["severity"]
    all_methods = cve_data["all_methods"]
    file_path = cve_data["before_file_path"]
    filename = Path(file_path).name

    if len(all_methods) == 1:
        msg = f"{cve_id} ({severity}): {cwe_id} {cwe_desc} in {filename} {all_methods[0]}."
    else:
        methods_str = ", ".join(all_methods)
        msg = f"{cve_id} ({severity}): {cwe_id} {cwe_desc} in {filename}. Affected: {methods_str}."

    snippet = "\n".join(cve_data["before_lines"])

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tomcat-cve-benchmark",
                        "rules": [
                            {
                                "id": cve_id,
                                "name": f"Tomcat {cve_id}",
                                "shortDescription": {"text": f"{cwe_id} {cwe_desc}"},
                                "properties": {
                                    "tags": [cwe_id],
                                    "cwe": [cwe_id],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": cve_id,
                        "level": LEVEL_MAP.get(severity, "note"),
                        "message": {"text": msg},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file_path},
                                    "region": {
                                        "startLine": start_line,
                                        "endLine": end_line,
                                        "startColumn": 1,
                                        "endColumn": 80,
                                        "snippet": {"text": snippet},
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "cve": cve_id,
                            "patch_complexity_score": cve_data["d1_score"],
                            "files_touched": cve_data["files_touched"],
                        },
                    }
                ],
            }
        ],
    }
```

- [ ] **Step 4: Run to verify all build_sarif tests pass**

```
pytest tests/test_sarif_generator.py -k "build_sarif" -v
```

Expected: all `PASSED`

- [ ] **Step 5: Run full test suite**

```
pytest tests/ -v
```

Expected: all tests `PASSED`

- [ ] **Step 6: Commit**

```bash
git add sarif_generator.py tests/test_sarif_generator.py
git commit -m "feat: implement build_sarif with level mapping and message formatting"
```

---

### Task 5: `main` + integration

**Files:**
- Modify: `sarif_generator.py` (replace stub)
- Modify: `tests/test_sarif_generator.py`

- [ ] **Step 1: Write failing integration test**

Add to `tests/test_sarif_generator.py`:

```python
def test_main_creates_three_sarif_files(tmp_path):
    sarif_dir = tmp_path / "sarif"
    main(
        fixes_dir=Path("fixes"),
        sarif_dir=sarif_dir,
        tomcat_dir=Path("tomcat"),
    )
    sarif_files = sorted(sarif_dir.glob("CVE-*.sarif"))
    assert len(sarif_files) == 3
    assert {f.stem for f in sarif_files} == {
        "CVE-2023-41080",
        "CVE-2026-24880",
        "CVE-2026-34483",
    }


def test_main_sarif_files_are_valid(tmp_path):
    sarif_dir = tmp_path / "sarif"
    main(
        fixes_dir=Path("fixes"),
        sarif_dir=sarif_dir,
        tomcat_dir=Path("tomcat"),
    )
    for sarif_file in sarif_dir.glob("CVE-*.sarif"):
        sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "tomcat-cve-benchmark"
        result = run["results"][0]
        assert result["level"] in ("note", "warning", "error")
        region = result["locations"][0]["physicalLocation"]["region"]
        # Grep found real line numbers (not fallback line 1) for all three CVEs
        assert region["startLine"] > 1, f"{sarif_file.name}: startLine fell back to 1"


def test_main_creates_sarif_dir_if_missing(tmp_path):
    sarif_dir = tmp_path / "nested" / "sarif"
    assert not sarif_dir.exists()
    main(
        fixes_dir=Path("fixes"),
        sarif_dir=sarif_dir,
        tomcat_dir=Path("tomcat"),
    )
    assert sarif_dir.exists()
    assert len(list(sarif_dir.glob("CVE-*.sarif"))) == 3
```

- [ ] **Step 2: Run to verify tests fail**

```
pytest tests/test_sarif_generator.py -k "main" -v
```

Expected: all `FAILED` with `NotImplementedError`

- [ ] **Step 3: Implement `main`**

Replace the `main` stub in `sarif_generator.py`:

```python
def main(fixes_dir: Path, sarif_dir: Path, tomcat_dir: Path) -> None:
    sarif_dir.mkdir(parents=True, exist_ok=True)

    for md_path in sorted(fixes_dir.glob("CVE-*.md")):
        cve_data = parse_markdown(md_path)
        cve_id = cve_data["cve_id"]

        src_file = tomcat_dir / cve_data["before_file_path"]
        start_line = find_declaration_line(src_file, cve_data["grep_term"], cve_data["is_class"])

        if start_line is None:
            print(f"WARN: {cve_data['grep_term']!r} not found in {src_file}, using startLine=1")
            start_line = 1

        end_line = start_line + len(cve_data["before_lines"]) - 1

        sarif = build_sarif(cve_data, start_line, end_line)

        out_path = sarif_dir / f"{cve_id}.sarif"
        out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {out_path}")
```

- [ ] **Step 4: Run to verify all main tests pass**

```
pytest tests/test_sarif_generator.py -k "main" -v
```

Expected: all three `PASSED`

- [ ] **Step 5: Run full test suite**

```
pytest tests/ -v
```

Expected: all tests `PASSED`

- [ ] **Step 6: Run the script for real and spot-check one output file**

```
python sarif_generator.py
```

Expected output:
```
Wrote sarif/CVE-2023-41080.sarif
Wrote sarif/CVE-2026-24880.sarif
Wrote sarif/CVE-2026-34483.sarif
```

Spot-check `sarif/CVE-2023-41080.sarif`: verify `startLine` is 755, `level` is `"warning"`, `ruleId` is `"CVE-2023-41080"`, `rules[0].id` matches `ruleId`, `region.snippet.text` contains the vulnerable `savedRequestURL` code, `patch_complexity_score` is `1`.

- [ ] **Step 7: Commit**

```bash
git add sarif_generator.py tests/test_sarif_generator.py sarif/
git commit -m "feat: implement main, complete sarif_generator.py, generate 3 SARIF files"
```
