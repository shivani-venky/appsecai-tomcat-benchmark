import argparse
import html
import re
from pathlib import Path


GITHUB_COMMIT_BASE = "https://github.com/apache/tomcat/commit/"

_CSS = """\
    *, *::before, *::after { box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
        padding: 2rem;
        background: #f8fafc;
        color: #1e293b;
    }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .back { margin-bottom: 1rem; font-size: 0.875rem; }

    header {
        background: #fff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1rem;
    }
    header h1 { margin: 0 0 0.5rem; font-size: 1.5rem; }
    .meta { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.4rem; }
    .cwe { color: #475569; font-size: 0.9rem; }
    .component { font-family: monospace; font-size: 0.82rem; color: #334155; margin-top: 0.25rem; }

    .badge {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 4px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
    }
    .sev-low      { background: #dcfce7; color: #15803d; }
    .sev-moderate { background: #fef3c7; color: #b45309; }
    .sev-high     { background: #fee2e2; color: #b91c1c; }

    .comparison { display: flex; gap: 1rem; margin-bottom: 1rem; }
    .pane {
        flex: 1;
        min-width: 0;
        background: #fff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }
    .pane-header {
        padding: 0.5rem 1rem;
        font-size: 0.82rem;
        font-weight: 700;
        border-bottom: 1px solid #e2e8f0;
        letter-spacing: 0.02em;
    }
    .pane.before .pane-header { background: #fff1f2; color: #be123c; }
    .pane.after  .pane-header { background: #f0fdf4; color: #15803d; }
    .pane pre {
        margin: 0;
        padding: 1rem;
        overflow-x: auto;
        font-size: 0.78rem;
        line-height: 1.6;
        background: transparent;
        border: none;
        border-radius: 0;
    }
    .pane code { background: transparent !important; padding: 0 !important; }

    footer {
        background: #fff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 0.875rem 1.5rem;
        display: flex;
        gap: 2rem;
        align-items: center;
        flex-wrap: wrap;
        font-size: 0.875rem;
        color: #475569;
    }
    footer strong { color: #1e293b; }
"""

_INDEX_EXTRA_CSS = """\
    h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
    .subtitle { color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }
    table {
        width: 100%;
        border-collapse: collapse;
        background: #fff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }
    th {
        background: #f1f5f9;
        text-align: left;
        padding: 0.75rem 1rem;
        font-size: 0.8rem;
        font-weight: 700;
        color: #475569;
        border-bottom: 1px solid #e2e8f0;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    td {
        padding: 0.875rem 1rem;
        border-bottom: 1px solid #f1f5f9;
        font-size: 0.875rem;
        vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    td:first-child a { font-weight: 600; }
    td:nth-child(4) { text-align: center; font-weight: 600; color: #475569; }
"""


def parse_cve_md(path: Path) -> dict:
    data: dict = {}
    state = "SCANNING_TABLE"
    before_lines: list[str] = []
    after_lines: list[str] = []
    before_file_path = None
    after_file_path = None

    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")

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
                        clean = re.sub(r'`', '', value)
                        parts = re.split(r'\s*→\s*', clean, maxsplit=1)
                        data["affected_methods"] = parts[1].strip() if len(parts) > 1 else clean
                    elif field in ("Fix Commit", "Fix Commit(s)"):
                        data["fix_commits"] = re.findall(r'`([0-9a-f]+)`', value)
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
                    break
                else:
                    after_lines.append(line)

    data["before_lines"] = before_lines
    data["after_lines"] = after_lines
    data["before_file_path"] = before_file_path
    data["after_file_path"] = after_file_path
    data["files_touched"] = len({p for p in [before_file_path, after_file_path] if p})
    data.setdefault("fix_commits", [])
    return data


def _badge(severity: str) -> str:
    cls = {"Low": "sev-low", "Moderate": "sev-moderate", "High": "sev-high"}.get(severity, "sev-low")
    return f'<span class="badge {cls}">{html.escape(severity)}</span>'


def _commit_links(fix_commits: list[str]) -> str:
    if not fix_commits:
        return "—"
    return " ".join(
        f'<a href="{GITHUB_COMMIT_BASE}{c}" target="_blank" rel="noopener">'
        f'<code>{html.escape(c)}</code></a>'
        for c in fix_commits
    )


def render_comparison(data: dict) -> str:
    cve_id      = data["cve_id"]
    severity    = data["severity"]
    cwe_id      = data["cwe_id"]
    cwe_desc    = data["cwe_description"]
    before_path = data.get("before_file_path") or ""
    after_path  = data.get("after_file_path") or ""
    affected    = data.get("affected_methods", "")
    d1          = data["d1_score"]
    files_touched = data["files_touched"]
    fix_commits = data["fix_commits"]

    if before_path and after_path and before_path != after_path:
        file_display = f"{html.escape(before_path)} → {html.escape(after_path)}"
    else:
        file_display = html.escape(before_path or after_path)

    component_html = file_display
    if affected:
        component_html += f" &nbsp;·&nbsp; {html.escape(affected)}"

    before_code = html.escape("\n".join(data["before_lines"]))
    after_code  = html.escape("\n".join(data["after_lines"]))

    plural = "s" if len(fix_commits) != 1 else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(cve_id)} — Before/After Comparison</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/java.min.js"></script>
  <style>
{_CSS}
  </style>
</head>
<body>
  <p class="back"><a href="index.html">← Back to index</a></p>

  <header>
    <h1>{html.escape(cve_id)}</h1>
    <div class="meta">
      {_badge(severity)}
      <span class="cwe">{html.escape(cwe_id)} — {html.escape(cwe_desc)}</span>
    </div>
    <div class="component">{component_html}</div>
  </header>

  <div class="comparison">
    <div class="pane before">
      <div class="pane-header">Before — vulnerable</div>
      <pre><code class="language-java">{before_code}</code></pre>
    </div>
    <div class="pane after">
      <div class="pane-header">After — patched</div>
      <pre><code class="language-java">{after_code}</code></pre>
    </div>
  </div>

  <footer>
    <span><strong>D1 score:</strong> {d1}</span>
    <span><strong>Files touched:</strong> {files_touched}</span>
    <span><strong>Fix commit{plural}:</strong> {_commit_links(fix_commits)}</span>
  </footer>

  <script>hljs.highlightAll();</script>
</body>
</html>"""


def render_index(all_data: list[dict]) -> str:
    rows = []
    for data in all_data:
        cve_id = data["cve_id"]
        cwe_cell = html.escape(f"{data['cwe_id']} — {data['cwe_description']}")
        rows.append(
            f'      <tr>'
            f'<td><a href="{html.escape(cve_id)}_comparison.html">{html.escape(cve_id)}</a></td>'
            f'<td>{_badge(data["severity"])}</td>'
            f'<td>{cwe_cell}</td>'
            f'<td>{data["d1_score"]}</td>'
            f'</tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Apache Tomcat CVE Benchmark</title>
  <style>
{_CSS}
{_INDEX_EXTRA_CSS}
  </style>
</head>
<body>
  <h1>Apache Tomcat CVE Benchmark</h1>
  <p class="subtitle">Before/after comparisons for AppSecAI benchmarking. Click a CVE to view the diff.</p>
  <table>
    <thead>
      <tr>
        <th>CVE</th>
        <th>Severity</th>
        <th>CWE</th>
        <th>D1</th>
      </tr>
    </thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>
</body>
</html>"""


def main(fixes_dir: Path, outputs_dir: Path) -> None:
    outputs_dir.mkdir(parents=True, exist_ok=True)
    all_data = []

    for md_path in sorted(fixes_dir.glob("CVE-*.md")):
        data = parse_cve_md(md_path)
        all_data.append(data)
        out_path = outputs_dir / f"{data['cve_id']}_comparison.html"
        out_path.write_text(render_comparison(data), encoding="utf-8")
        print(f"Wrote {out_path}")

    index_path = outputs_dir / "index.html"
    index_path.write_text(render_index(all_data), encoding="utf-8")
    print(f"Wrote {index_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HTML before/after comparison pages from CVE markdown")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--outputs-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()
    main(args.fixes_dir, args.outputs_dir)
