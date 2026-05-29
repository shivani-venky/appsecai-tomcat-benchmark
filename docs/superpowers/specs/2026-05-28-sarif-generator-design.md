# SARIF Generator Design

**Date:** 2026-05-28  
**Project:** AppSecAI CVE Benchmarking — Apache Tomcat  
**Status:** Approved

---

## Overview

A single Python script that reads three CVE markdown files from `fixes/` and writes one SARIF 2.1.0 file per CVE to `sarif/`. The output feeds the AppSecAI ingestion pipeline for AI-vs-human remediation benchmarking.

---

## Script

**File:** `sarif_generator.py` (workspace root: `/Users/shivani/appsecai-internship/`)  
**Invocation:** `python sarif_generator.py` (from workspace root)  
**CLI flags:**

| Flag | Default | Purpose |
|---|---|---|
| `--fixes-dir` | `fixes/` | Directory containing CVE markdown files |
| `--sarif-dir` | `sarif/` | Output directory for `.sarif` files |
| `--tomcat-dir` | `tomcat/` | Apache Tomcat source root |

**Dependencies:** stdlib only — `re`, `json`, `pathlib`, `argparse`  
**Output:** `sarif/{CVE_ID}.sarif` per CVE, one file per run

---

## Input Format

Each markdown file in `fixes/CVE-*.md` has this structure (all three current files conform):

1. **H1 title:** `# CVE-XXXX-XXXXX — Description`
2. **Metadata table:** `| **Field** | Value |` rows for: CVE ID, CWE, Severity, Affected Component, Fix Commit(s), D1 Score, (optional) Fix Complexity Notes
3. **`## Before (Vulnerable)`** section: a backtick-quoted repo-relative file path, then a fenced Java code block
4. **`## After (Patched)`** section: same structure (file path + fenced code block)
5. **`## Explanation`** section: prose (not parsed)

Files matching `fixes/CVE-*.md` are processed; all other `.md` files in `fixes/` are skipped.

---

## Architecture

Four functions plus `main`:

| Function | Inputs | Returns |
|---|---|---|
| `parse_markdown(path)` | `Path` to a CVE `.md` | `dict` of all extracted CVE fields |
| `find_declaration_line(src_file, grep_term, is_class)` | Tomcat source `Path`, search term, class flag | `int` line number (1-based), or `None` |
| `build_sarif(cve_data, start_line, end_line)` | Parsed data dict + line range | SARIF `dict` |
| `main(fixes_dir, sarif_dir, tomcat_dir)` | Three `Path` args | Writes `.sarif` files, prints progress |

`main` flow per file: `parse_markdown` → `find_declaration_line` → `build_sarif` → `json.dump` to `sarif/{CVE_ID}.sarif`.

---

## Markdown Parsing (State Machine)

States (in order): `SCANNING_TABLE → SCANNING_BEFORE → IN_BEFORE_CODE → SCANNING_AFTER → IN_AFTER_CODE → DONE`

**Fence detection:** A line stripped of whitespace that equals exactly ` ``` ` is a closing fence. A line that starts with ` ``` ` followed by a language tag (e.g., ```` ```java ````) is an opening fence. The two are mutually exclusive.

**Transitions:**

| State | Trigger | Action | Next state |
|---|---|---|---|
| `SCANNING_TABLE` | `\| **Field** \| Value \|` line | Record field → value | (stay) |
| `SCANNING_TABLE` | `## Before` line | — | `SCANNING_BEFORE` |
| `SCANNING_BEFORE` | Backtick-quoted `` `java/...` `` line | Record `before_file_path` | (stay) |
| `SCANNING_BEFORE` | ```` ```java ```` opening fence | — | `IN_BEFORE_CODE` |
| `IN_BEFORE_CODE` | ```` ``` ```` closing fence | — | `SCANNING_AFTER` |
| `IN_BEFORE_CODE` | Any other line | Append to `before_lines[]` | (stay) |
| `SCANNING_AFTER` | `## After` heading or blank lines | Ignored | (stay) |
| `SCANNING_AFTER` | Backtick-quoted `` `java/...` `` line | Record `after_file_path` | (stay) |
| `SCANNING_AFTER` | ```` ```java ```` opening fence | — | `IN_AFTER_CODE` |
| `IN_AFTER_CODE` | ```` ``` ```` closing fence | — | `DONE` |

The `after_lines` content is not stored — only `after_file_path` is captured (for `files_touched` calculation).

**Table field extraction:**

| Markdown field | Extraction |
|---|---|
| `CVE ID` | Stored as-is |
| `CWE` | `re.search(r'CWE-\d+')` → `"CWE-601"`; `re.search(r'\((.+?)\)')` → CWE description string |
| `Severity` | Stored as-is (`"Low"` or `"Moderate"`) |
| `D1 Score` | `int(re.match(r'(\d+)', value))` → integer |
| `Affected Component` | Parsed into method tokens (see below) |
| `Fix Commit(s)` | Ignored |

**Affected Component parsing:**

Input example: `` `AbstractAccessLogValve.java` → `RequestElement.addElement()`, `RequestURIElement.addElement()` ``

1. Strip backtick markup and split on ` → `; take RHS
2. Split on `,`; strip backticks, whitespace, and `()` from each token
3. Result: a list of method references, e.g. `["RequestElement.addElement", "RequestURIElement.addElement"]`
4. From the **first token**: if it contains `.`, take the LHS as `class_name` and set `is_class=True`; otherwise use the bare name and set `is_class=False`
5. All tokens are preserved for `message.text` construction

**files_touched:** `len({before_file_path, after_file_path})` — count of distinct file paths from the two section headers. Yields `1` for all three current CVEs.

---

## Line Lookup (Approach B)

Purpose: find the real line number in the patched Tomcat source so the SARIF region points to the correct method/class, while `snippet.text` carries the vulnerable *before* code for triage context.

```
find_declaration_line(src_file, grep_term, is_class):
    read all lines of src_file
    if is_class:
        pattern = r'\bclass\s+{grep_term}\b'
    else:
        pattern = r'\b(private|protected|public)\b.*\b{grep_term}\b'
    return 1-based line number of first match, or None
```

The access-modifier filter for non-class methods selects the **declaration** over call sites (e.g., line 755 not 321 for `savedRequestURL`, line 365 not 151 for `parseChunkHeader`).

**Region values:**

| Field | Value |
|---|---|
| `startLine` | Matched line number; fallback `1` |
| `endLine` | `startLine + len(before_lines) - 1` |
| `startColumn` | `1` |
| `endColumn` | `80` |
| `snippet.text` | `"\n".join(before_lines)` — the vulnerable before-code block |

On any fallback, print `WARN: <reason>, using startLine=1` to stdout.

---

## SARIF Assembly

**Level mapping** (SARIF `level` field only — independent of `message.text`):

| Markdown Severity | SARIF level |
|---|---|
| `Low` | `"note"` |
| `Moderate` | `"warning"` |
| `High` | `"error"` |

**message.text format:**

The severity label in parentheses is the raw markdown `Severity` value, not the SARIF level string.

- Single call-site:  
  `"CVE-2023-41080 (Moderate): CWE-601 URL Redirection to Untrusted Site — Open Redirect in FormAuthenticator.java savedRequestURL()."`
- Multiple call-sites (mention all in text, only one result emitted):  
  `"CVE-2026-34483 (Low): CWE-117 Improper Output Neutralization for Logs in AbstractAccessLogValve.java. Affected: RequestElement.addElement(), RequestURIElement.addElement()."`

**Complete SARIF shape:**

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "tomcat-cve-benchmark",
        "rules": [{
          "id": "{CVE_ID}",
          "name": "Tomcat {CVE_ID}",
          "shortDescription": { "text": "{CWE_ID} {CWE_description}" },
          "properties": {
            "tags": ["{CWE_ID}"],
            "cwe": ["{CWE_ID}"]
          }
        }]
      }
    },
    "results": [{
      "ruleId": "{CVE_ID}",
      "level": "{note|warning|error}",
      "message": { "text": "{message_text}" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "{repo_relative_path}"
          },
          "region": {
            "startLine": "{start_line}",
            "endLine": "{end_line}",
            "startColumn": 1,
            "endColumn": 80,
            "snippet": { "text": "{before_code_block}" }
          }
        }
      }],
      "properties": {
        "cve": "{CVE_ID}",
        "patch_complexity_score": "{d1_score}",
        "files_touched": "{files_touched}"
      }
    }]
  }]
}
```

`tool.driver.name` is `"tomcat-cve-benchmark"` — more meaningful than Kevin's placeholder `"sarif"` for AppSecAI ingestion grouping.  
`result.ruleId` exactly matches `tool.driver.rules[0].id` — required by Kevin's spec.

**Integer fields:** `startLine`, `endLine`, `startColumn`, `endColumn`, `patch_complexity_score`, and `files_touched` are JSON integers, not strings. The `{placeholder}` notation in the shape above is illustrative only.

---

## Error Handling

| Condition | Behavior |
|---|---|
| `sarif/` directory missing | Auto-create with `mkdir -p` equivalent before writing |
| Tomcat source file not found at `tomcat_dir / rel_path` | `WARN: <path> not found, using startLine=1` |
| Grep pattern not found in source file | `WARN: <term> not found in <file>, using startLine=1` |
| Malformed markdown (expected section not reached) | `raise ValueError(f"{filename}: missing section '<name>'")` — fast fail, no partial output |
| Non-CVE `.md` files in `fixes/` | Skipped by `CVE-*.md` glob in `main` |

---

## Expected Outputs

| CVE | SARIF file | Level | startLine (approx) |
|---|---|---|---|
| CVE-2023-41080 | `sarif/CVE-2023-41080.sarif` | `warning` | 755 |
| CVE-2026-24880 | `sarif/CVE-2026-24880.sarif` | `note` | 365 |
| CVE-2026-34483 | `sarif/CVE-2026-34483.sarif` | `note` | 1343 |
