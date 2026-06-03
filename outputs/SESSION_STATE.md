# Session State — AppSecAI Vulnerability Remediation Benchmarking
**Intern:** Shivani (shivani@appsecure.ai)
**Project:** Apache Tomcat CVE benchmarking pipeline — comparing AI-generated fixes against human patches

---

## Session 2 — 2026-06-03

### What We Accomplished

#### 1. SARIF Generator — Design, Spec, and Plan
- Brainstormed sarif_generator.py with Kevin's SARIF ingestion spec as input.
- Chose Approach B for line numbers: grep patched Tomcat source for method/class declaration, use "Before" code block as `snippet.text`.
- Decided: one result per CVE (multi-call-site CVEs mention extra call sites in `message.text` only).
- Level mapping: Low → `note`, Moderate → `warning`, High → `error`.
- Severity label in `message.text` uses the raw markdown Severity value, not the SARIF level string.
- Wrote and committed design spec: `docs/superpowers/specs/2026-05-28-sarif-generator-design.md`
- Wrote and committed implementation plan: `docs/superpowers/plans/2026-05-28-sarif-generator.md`

#### 2. TDD Implementation — sarif_generator.py
Implemented five functions following TDD (pytest 7.4, Python 3.12, stdlib only):

| Function | Responsibility |
|---|---|
| `_parse_affected_component(raw)` | Parses "Affected Component" table cell; extracts `grep_term`, `is_class`, `all_methods` |
| `_clean_before_lines(lines, is_class)` | Trims multi-class snippets to first brace block; strips annotation comments |
| `parse_markdown(path)` | Six-state line-by-line parser; extracts all metadata and before/after code blocks |
| `find_declaration_line(src_file, grep_term, is_class)` | Greps Tomcat source for method/class declaration; returns 1-based line number |
| `build_sarif(cve_data, start_line, end_line)` | Assembles SARIF 2.1.0 dict from parsed CVE data |
| `main(fixes_dir, sarif_dir, tomcat_dir)` | Orchestrates parsing → grepping → SARIF generation for all CVEs |

#### 3. End-to-End SARIF Review
Reviewed the 3 generated SARIF files. 8 issues found:

| # | Issue | Status |
|---|---|---|
| 1 | Snippet preamble offset: `startLine` points to declaration but snippet includes preceding Javadoc/comments (1–4 lines per CVE) | Deferred |
| 2 | CVE-2026-34483 snippet contained both `RequestElement` and `RequestURIElement` (436 lines apart in source) | **Fixed** |
| 3 | CVE-2026-24880 region [365, 414] covers ~67% of patched method (method continues to line 440) | Deferred |
| 4 | Inline annotation comments (`// ← unescaped`, `// ... remainder unchanged`) present in `snippet.text` | **Fixed** |
| 5 | No `fix_date` or temporal metadata on results | Deferred |
| 6 | `shortDescription.text` omits the CWE name | Deferred |
| 7 | `endColumn: 80` is a placeholder; doesn't reflect actual line length | Deferred |
| 8 | `fix_commits` missing from `result.properties` | **Fixed** |

#### 4. Priority Fixes (Issues 2, 4, 8)

**New helper `_clean_before_lines(lines, is_class)`:**
- When `is_class=True`: brace-depth counting trims lines to the first balanced block. Silent fallback to full lines on brace mismatch.
- Removes lines matching `^\s*//\s*\.\.\.` (truncation markers) entirely.
- Strips `// ← ...` annotation suffixes from inline code lines.

**`parse_markdown` additions:**
- Parses "Fix Commit" and "Fix Commit(s)" table fields via `re.findall(r'\`([0-9a-f]+)\`', value)`.
- Calls `_clean_before_lines` on accumulated `before_lines` before returning.

**`build_sarif` addition:**
- Adds `fix_commits` to `result.properties` only when non-empty; key omitted entirely when empty.

**Side effects verified:**
- CVE-2026-34483: endLine 1378 → 1366 (snippet trimmed from 36 to 24 lines, `RequestURIElement` removed)
- CVE-2026-24880: endLine 415 → 414 (removal of truncation marker shrinks `before_lines` by 1; `end_line = start_line + len(before_lines) - 1` auto-corrects)

**Commit:** `0bb42a6` — `fix: clean snippets and add fix_commits to SARIF output`

#### 5. Final State
- **34 tests passing** (22 original + 12 new covering `_clean_before_lines`, annotation stripping, fix_commits parsing, and build_sarif properties)
- **3 SARIF files regenerated** — clean snippets, no annotations, fix_commits present

---

## Current SARIF Output Summary

| CVE | File | startLine | endLine | level | fix_commits |
|---|---|---|---|---|---|
| CVE-2023-41080 | `FormAuthenticator.java` | 755 | 770 | warning | `e3703c9a` |
| CVE-2026-24880 | `ChunkedInputFilter.java` | 365 | 414 | note | `fde1a823`, `2cb06c34` |
| CVE-2026-34483 | `AbstractAccessLogValve.java` | 1343 | 1366 | note | `f9ddc24f` |

All 3 SARIF files at `sarif/CVE-<ID>.sarif`. Schema version 2.1.0.

---

## Next Steps

### Immediate
- **Kevin ingests SARIF files** into AppSecAI and returns AI-generated fix candidates for comparison.
- Review AppSecAI output format; decide on scoring dimensions (exact match, structural equivalence, semantic correctness).

### Deferred SARIF fixes (issues 1, 3, 5, 6, 7)
Low priority until Kevin's ingestion confirms whether they affect pipeline behavior:
- Issue 1: Align `startLine` with actual first line of snippet (currently may include preceding Javadoc)
- Issue 3: Extend CVE-2026-24880 region to full patched method (~365–440)
- Issues 5–7: `fix_date`, `shortDescription` CWE name, `endColumn` accuracy

### Longer term
- Expand CVE set (15–30+ for statistical significance)
- Add at least one D1=4 or D1=5 case to stress-test AI on larger diffs
- Build comparison scorer: diff AI output vs. "after" block
- Decide prompt strategy: vulnerable function only vs. full file vs. full file + CVE description

---

## Open Questions

1. **Scoring rubric for semantically equivalent fixes** — CVE-2026-24880 has multiple valid approaches (state machine, allowlist, reject-all). How do we score structurally different but correct fixes?
2. **CVE-2026-24880 follow-up commit** — is the gold patch `fde1a823` alone, or both commits together?
3. **AI model(s) to benchmark** — one model at multiple temperatures, multiple models, or models with vs. without RAG context?
4. **Prompt strategy** — significantly affects difficulty and result interpretation.
5. **Scale target** — how many CVEs for the final report?

---

## Workspace Layout

```
/Users/shivani/appsecai-internship/
├── tomcat/                          # Apache Tomcat source repo (.gitignored, read-only reference)
├── fixes/
│   ├── tomcat_cve_candidates.md
│   ├── CVE-2026-24880_before_after.md
│   ├── CVE-2026-34483_before_after.md
│   └── CVE-2023-41080_before_after.md
├── sarif/
│   ├── CVE-2023-41080.sarif         # Ready for Kevin
│   ├── CVE-2026-24880.sarif         # Ready for Kevin
│   └── CVE-2026-34483.sarif         # Ready for Kevin
├── tests/
│   └── test_sarif_generator.py      # 34 tests, all passing
├── docs/superpowers/
│   ├── specs/2026-05-28-sarif-generator-design.md
│   └── plans/2026-05-28-sarif-generator.md
├── sarif_generator.py
└── outputs/
    └── SESSION_STATE.md             # this file
```

---

## Session 1 — 2026-05-23

### What We Accomplished

#### 1. CVE Candidate Selection
Fetched https://tomcat.apache.org/security-11.html and screened ~52 CVEs against three criteria:
- Low or Moderate severity (simpler fixes for pipeline v1)
- Clean GitHub commit link available
- Variety in vulnerability class

Selected 3 candidates. Results saved to `fixes/tomcat_cve_candidates.md`.

#### 2. Before/After Diff Extraction
For each CVE, ran `git show <sha>` inside `tomcat/`, identified the core vulnerable method, and authored structured before/after documents. Each file includes: CVE metadata, CWE, D1 complexity score, Fix Complexity Notes, before/after code blocks, and a plain-English explanation.

#### 3. Complexity Scoring (D1)
Defined D1 as total source lines changed in the fix commit:
- ≤10 lines → D1 = 1
- ≤50 lines → D1 = 2
- ≤200 lines → D1 = 3
- ≤500 lines → D1 = 4
- 500+ lines → D1 = 5

---

## CVE Details

### CVE-2026-24880 — Request Smuggling
- **CWE:** CWE-444 — Inconsistent Interpretation of HTTP Requests
- **Severity:** Low / **D1:** 3
- **Component:** `ChunkedInputFilter.java` → `parseChunkHeader()`
- **Fix commits:** `fde1a823` (primary), `2cb06c34` (edge-case follow-up)
- **Root cause:** Chunk extensions after `;` accepted without structural validation — a plain boolean let all bytes through silently. Attacker could embed smuggled request data in a crafted extension.
- **Fix approach:** Replaced boolean flag with a typed `ChunkExtension` state-machine enum validating each byte against RFC 9112 grammar. Invalid tokens → 400.
- **Complexity note:** Most complex fix — spans 7 files, introduces new parser class, has follow-up commit.

### CVE-2026-34483 — Log Injection / Information Disclosure
- **CWE:** CWE-117 — Improper Output Neutralization for Logs
- **Severity:** Low / **D1:** 1
- **Component:** `AbstractAccessLogValve.java` → `RequestElement.addElement()`, `RequestURIElement.addElement()`
- **Fix commit:** `f9ddc24f`
- **Root cause:** URI and query string written with `buf.append(value)` rather than the existing `escapeAndAppend(value, buf)` helper applied to all other user-controlled fields.
- **Fix approach:** 4 `buf.append(x)` → `escapeAndAppend(x, buf)` substitutions. No new logic.

### CVE-2023-41080 — Open Redirect
- **CWE:** CWE-601 — URL Redirection to Untrusted Site
- **Severity:** Moderate / **D1:** 1
- **Component:** `FormAuthenticator.java` → `savedRequestURL()`
- **Fix commit:** `e3703c9a`
- **Root cause:** Post-login redirect to saved pre-auth URL without validation. A URI starting with `//` redirects to an attacker-controlled domain.
- **Fix approach:** Loop collapses `//evil.com/…` to `/evil.com/…`. 4 functional lines, single method.
- **Complexity note:** Cleanest fix — one correct solution, no ambiguity. Best first AI benchmark target.

---

## Complexity Ranking

| Rank | CVE | D1 | Source Files | New Classes | Follow-up Commit | AI Benchmark Difficulty |
|---|---|---|---|---|---|---|
| 1 (easiest) | CVE-2023-41080 | 1 | 1 | No | No | One correct solution, no ambiguity |
| 2 | CVE-2026-34483 | 1 | 1 | No | No | Pattern trivial; challenge is finding all 4 call sites |
| 3 (hardest) | CVE-2026-24880 | 3 | 7 | Yes | Yes | Requires RFC 9112 understanding + state machine |
