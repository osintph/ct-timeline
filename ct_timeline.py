#!/usr/bin/env python3
"""
ct_timeline.py

Generate a forensic-style timeline report from Certificate Transparency logs.

Pulls CT data from crt.sh for a given domain, processes it chronologically,
detects pattern signals (new wildcards, CA shifts, issuance bursts), and
produces a self-contained HTML report. The report is print-friendly and
exports cleanly to PDF via any browser's print dialog.

Usage:
    python ct_timeline.py example.com
    python ct_timeline.py example.com --output report.html
    python ct_timeline.py example.com --include-expired
    python ct_timeline.py example.com --open

No third-party dependencies. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CRTSH_BASE = "https://crt.sh/"
USER_AGENT = "ct-timeline/1.0 (+https://blog.osintph.info)"
TIMEOUT_SECONDS = 90
TOOL_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Data acquisition
# ---------------------------------------------------------------------------

def fetch_ct_data(domain: str, include_expired: bool = False) -> list[dict]:
    """Query crt.sh for all certificates matching the given domain."""
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    if not include_expired:
        params["exclude"] = "expired"

    url = CRTSH_BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        print(f"crt.sh returned HTTP {e.code}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Failed to reach crt.sh: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except TimeoutError:
        print("crt.sh request timed out. Try again or split the query.", file=sys.stderr)
        sys.exit(1)

    if not raw.strip():
        return []

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Failed to parse crt.sh response as JSON: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Normalization and deduplication
# ---------------------------------------------------------------------------

def parse_dt(raw: str | None) -> datetime | None:
    """Parse a crt.sh ISO 8601 timestamp. Returns None on failure."""
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def normalize_issuer(raw: str) -> str:
    """Reduce an issuer DN to a clean human label."""
    if not raw:
        return "Unknown"
    parts = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            parts[k.strip()] = v.strip()
    org = parts.get("O") or parts.get("CN") or raw
    return org.strip()


def normalize_entries(raw_entries: list[dict]) -> list[dict]:
    """Deduplicate and clean crt.sh entries.

    crt.sh returns multiple rows per certificate (one for each log entry and
    often a precert + cert pair). We collapse by the cert serial + issuer +
    not_before tuple, keeping the earliest entry_timestamp we have seen.
    """
    seen: dict[tuple, dict] = {}

    for row in raw_entries:
        not_before = parse_dt(row.get("not_before"))
        not_after = parse_dt(row.get("not_after"))
        entry_ts = parse_dt(row.get("entry_timestamp"))
        name_value = (row.get("name_value") or "").strip()
        issuer = normalize_issuer(row.get("issuer_name") or "")
        serial = (row.get("serial_number") or "").strip().lower()

        if not name_value or not not_before:
            continue

        key = (serial, issuer, not_before.isoformat())
        names = [n.strip() for n in name_value.splitlines() if n.strip()]
        names = sorted(set(names))

        if key in seen:
            existing = seen[key]
            if entry_ts and (existing["entry_timestamp"] is None or entry_ts < existing["entry_timestamp"]):
                existing["entry_timestamp"] = entry_ts
            existing_names = set(existing["names"])
            existing_names.update(names)
            existing["names"] = sorted(existing_names)
        else:
            seen[key] = {
                "serial": serial,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "entry_timestamp": entry_ts,
                "names": names,
                "id": row.get("id"),
            }

    entries = list(seen.values())
    entries.sort(key=lambda e: e["not_before"])
    return entries


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def is_wildcard(names: list[str]) -> bool:
    return any(n.startswith("*.") for n in names)


def wildcard_bases(names: list[str]) -> list[str]:
    return sorted({n[2:] for n in names if n.startswith("*.")})


def analyze(domain: str, entries: list[dict]) -> dict:
    """Compute summary statistics and surface patterns."""
    if not entries:
        return {
            "total_certs": 0,
            "wildcard_count": 0,
            "unique_names": 0,
            "unique_issuers": 0,
            "date_min": None,
            "date_max": None,
            "issuer_breakdown": [],
            "wildcards": [],
            "unique_name_list": [],
            "signals": [],
        }

    all_names: set[str] = set()
    issuer_counter: Counter[str] = Counter()
    wildcards = []

    for e in entries:
        all_names.update(e["names"])
        issuer_counter[e["issuer"]] += 1
        if is_wildcard(e["names"]):
            wildcards.append(e)

    issuer_breakdown = [
        {"issuer": iss, "count": cnt, "pct": (cnt / len(entries)) * 100}
        for iss, cnt in issuer_counter.most_common()
    ]

    return {
        "total_certs": len(entries),
        "wildcard_count": len(wildcards),
        "unique_names": len(all_names),
        "unique_issuers": len(issuer_counter),
        "date_min": entries[0]["not_before"],
        "date_max": entries[-1]["not_before"],
        "issuer_breakdown": issuer_breakdown,
        "wildcards": wildcards,
        "unique_name_list": sorted(all_names),
        "signals": detect_signals(domain, entries),
    }


def detect_signals(domain: str, entries: list[dict]) -> list[dict]:
    """Surface notable patterns in the issuance timeline."""
    signals = []

    # Signal: first-ever wildcard for this target
    first_wildcard = next((e for e in entries if is_wildcard(e["names"])), None)
    if first_wildcard:
        prior_count = sum(1 for e in entries if e["not_before"] < first_wildcard["not_before"])
        if prior_count >= 3:
            bases = wildcard_bases(first_wildcard["names"])
            signals.append({
                "kind": "first_wildcard",
                "title": "First wildcard certificate appearance",
                "detail": (
                    f"Wildcard for {', '.join(bases)} appears after "
                    f"{prior_count} prior non-wildcard certificates. "
                    "This usually signals consolidation onto a load balancer, "
                    "CDN, or service mesh."
                ),
                "when": first_wildcard["not_before"],
            })

    # Signal: CA migration (issuer used for first time after >= 5 prior certs)
    seen_issuers: set[str] = set()
    for e in entries:
        if e["issuer"] in seen_issuers:
            seen_issuers.add(e["issuer"])
            continue
        prior_total = sum(1 for x in entries if x["not_before"] < e["not_before"])
        if prior_total >= 5 and seen_issuers:
            signals.append({
                "kind": "ca_shift",
                "title": f"New CA introduced: {e['issuer']}",
                "detail": (
                    f"First certificate from {e['issuer']} appears after "
                    f"{prior_total} certificates from other issuers. "
                    "Procurement, compliance, or platform migration signal."
                ),
                "when": e["not_before"],
            })
        seen_issuers.add(e["issuer"])

    # Signal: issuance bursts (>= 5 certs within any 24h window)
    bursts = []
    for i, e in enumerate(entries):
        window_end = e["not_before"] + timedelta(hours=24)
        count = sum(1 for x in entries[i:] if x["not_before"] <= window_end)
        if count >= 5:
            bursts.append((e["not_before"], count))
    # Deduplicate overlapping bursts: only keep the earliest in each cluster
    deduped_bursts = []
    last_end: datetime | None = None
    for start, count in bursts:
        if last_end is None or start > last_end:
            deduped_bursts.append((start, count))
            last_end = start + timedelta(hours=24)
    for start, count in deduped_bursts[:5]:
        signals.append({
            "kind": "burst",
            "title": f"Issuance burst: {count} certificates in 24 hours",
            "detail": (
                "Bursts typically indicate platform migrations, mass "
                "re-issuance after key rotation, or a CDN onboarding event."
            ),
            "when": start,
        })

    signals.sort(key=lambda s: s["when"])
    return signals


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CT Timeline Report: {target_safe}</title>
<meta name="generator" content="ct-timeline {tool_version}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Serif:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --paper: #f7f5f0;
  --paper-edge: #efece4;
  --ink: #161719;
  --ink-soft: #2a2b2d;
  --ink-mute: #5a5b5e;
  --rule: #c9c5bc;
  --rule-soft: #e2ddd1;
  --accent: #a8362c;
  --teal: #1f4e48;
  --amber: #8b6914;
  --highlight: #f0e9d6;
}}

* {{ box-sizing: border-box; }}

html, body {{
  margin: 0;
  padding: 0;
  background: var(--paper-edge);
  color: var(--ink);
  font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}}

.page {{
  max-width: 880px;
  margin: 0 auto;
  padding: 48px 56px 64px;
  background: var(--paper);
  box-shadow: 0 1px 0 var(--rule-soft), 0 24px 60px rgba(22, 23, 25, 0.08);
  min-height: 100vh;
  position: relative;
}}

/* ------- Masthead ------- */
.masthead {{
  background: var(--ink);
  color: var(--paper);
  padding: 22px 28px;
  margin: -48px -56px 36px;
  border-bottom: 4px solid var(--accent);
}}
.masthead .eyebrow {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--rule);
  margin: 0 0 6px;
}}
.masthead h1 {{
  font-family: "IBM Plex Serif", Georgia, serif;
  font-weight: 600;
  font-size: 26px;
  margin: 0 0 4px;
  line-height: 1.2;
}}
.masthead .target {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 15px;
  color: #d6cfb8;
}}
.masthead .meta-row {{
  display: flex;
  gap: 28px;
  margin-top: 14px;
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--rule);
  flex-wrap: wrap;
}}
.masthead .meta-row b {{
  color: var(--paper);
  font-weight: 500;
  margin-right: 6px;
}}

/* ------- Bates exhibit number ------- */
.exhibit {{
  position: absolute;
  top: 70px;
  right: 56px;
  font-family: "IBM Plex Mono", monospace;
  font-size: 10px;
  letter-spacing: 0.12em;
  color: var(--accent);
  border: 1.5px solid var(--accent);
  padding: 4px 8px;
  text-transform: uppercase;
  transform: rotate(-2deg);
}}

/* ------- Section headers ------- */
.section {{ margin: 44px 0 0; }}
.section-head {{
  display: flex;
  align-items: baseline;
  gap: 14px;
  border-bottom: 1px solid var(--ink);
  padding-bottom: 6px;
  margin-bottom: 18px;
}}
.section-head .num {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--accent);
  letter-spacing: 0.12em;
}}
.section-head h2 {{
  font-family: "IBM Plex Serif", Georgia, serif;
  font-weight: 600;
  font-size: 18px;
  margin: 0;
  letter-spacing: -0.005em;
}}
.section-head .right {{
  margin-left: auto;
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--ink-mute);
}}

/* ------- Summary grid ------- */
.summary {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0;
  border: 1px solid var(--ink);
}}
.summary .cell {{
  padding: 14px 16px;
  border-right: 1px solid var(--rule);
}}
.summary .cell:last-child {{ border-right: none; }}
.summary .label {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--ink-mute);
  margin: 0 0 6px;
}}
.summary .value {{
  font-family: "IBM Plex Serif", Georgia, serif;
  font-weight: 600;
  font-size: 24px;
  line-height: 1;
  color: var(--ink);
}}
.summary .unit {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--ink-mute);
  margin-top: 4px;
}}

/* ------- Signal callouts ------- */
.signal {{
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 18px;
  padding: 14px 0;
  border-bottom: 1px dotted var(--rule);
}}
.signal:last-child {{ border-bottom: none; }}
.signal .when {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--accent);
}}
.signal .title {{
  font-family: "IBM Plex Serif", Georgia, serif;
  font-weight: 600;
  font-size: 14px;
  margin: 0 0 3px;
}}
.signal .detail {{
  font-size: 13px;
  color: var(--ink-soft);
  margin: 0;
}}
.signal.kind-first_wildcard .title::before {{ content: "* "; color: var(--teal); }}
.signal.kind-ca_shift .title::before       {{ content: "# "; color: var(--accent); }}
.signal.kind-burst .title::before          {{ content: "> "; color: var(--amber); }}

/* ------- Timeline (the signature element) ------- */
.timeline {{
  position: relative;
  padding-left: 168px;
  margin-top: 8px;
}}
.timeline::before {{
  content: "";
  position: absolute;
  left: 150px;
  top: 6px;
  bottom: 6px;
  width: 1px;
  background: var(--ink);
}}
.timeline-item {{
  position: relative;
  padding: 10px 0 14px 22px;
  break-inside: avoid;
}}
.timeline-item::before {{
  content: "";
  position: absolute;
  left: -22px;
  top: 16px;
  width: 9px;
  height: 9px;
  background: var(--paper);
  border: 1.5px solid var(--ink);
  border-radius: 50%;
}}
.timeline-item.wildcard::before {{
  background: var(--teal);
  border-color: var(--teal);
}}
.timeline-item .bates {{
  position: absolute;
  left: -168px;
  top: 12px;
  width: 142px;
  text-align: right;
  font-family: "IBM Plex Mono", monospace;
  font-size: 11px;
  color: var(--ink-soft);
  line-height: 1.4;
}}
.timeline-item .bates .date {{ display: block; color: var(--accent); font-weight: 500; }}
.timeline-item .bates .time {{ display: block; color: var(--ink-mute); font-size: 10px; }}
.timeline-item .names {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
  color: var(--ink);
  font-weight: 500;
  word-break: break-all;
  margin: 0 0 4px;
}}
.timeline-item .names .name {{ display: block; }}
.timeline-item .names .wildcard-name {{ color: var(--teal); }}
.timeline-item .meta {{
  font-size: 11px;
  color: var(--ink-mute);
  font-family: "IBM Plex Mono", monospace;
}}
.timeline-item .meta .issuer {{ color: var(--ink-soft); }}

/* ------- Issuer breakdown ------- */
.issuers {{ margin-top: 8px; }}
.issuer-row {{
  display: grid;
  grid-template-columns: 1fr 60px 100px;
  align-items: center;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px dotted var(--rule);
  font-size: 13px;
}}
.issuer-row:last-child {{ border-bottom: none; }}
.issuer-row .name {{ font-family: "IBM Plex Sans", sans-serif; }}
.issuer-row .count {{
  font-family: "IBM Plex Mono", monospace;
  font-size: 12px;
  text-align: right;
  color: var(--ink-soft);
}}
.issuer-row .bar {{
  height: 6px;
  background: var(--rule-soft);
  position: relative;
  overflow: hidden;
}}
.issuer-row .bar .fill {{
  position: absolute;
  left: 0; top: 0; bottom: 0;
  background: var(--accent);
}}

/* ------- Wildcard list ------- */
.wildcard-list {{
  display: grid;
  grid-template-columns: 1fr;
  gap: 0;
  border: 1px solid var(--rule);
}}
.wildcard-row {{
  display: grid;
  grid-template-columns: 130px 1fr 1fr;
  gap: 18px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--rule-soft);
  font-size: 12px;
  background: var(--highlight);
}}
.wildcard-row:last-child {{ border-bottom: none; }}
.wildcard-row .when {{ font-family: "IBM Plex Mono", monospace; color: var(--accent); }}
.wildcard-row .name {{ font-family: "IBM Plex Mono", monospace; color: var(--teal); font-weight: 500; word-break: break-all; }}
.wildcard-row .issuer {{ font-family: "IBM Plex Sans", sans-serif; color: var(--ink-soft); }}

/* ------- Empty state ------- */
.empty {{
  padding: 24px;
  text-align: center;
  font-family: "IBM Plex Serif", Georgia, serif;
  font-style: italic;
  color: var(--ink-mute);
  border: 1px dashed var(--rule);
}}

/* ------- Footer ------- */
.colophon {{
  margin-top: 56px;
  padding-top: 18px;
  border-top: 2px solid var(--ink);
  font-family: "IBM Plex Mono", monospace;
  font-size: 10px;
  color: var(--ink-mute);
  line-height: 1.6;
}}
.colophon .row {{ display: flex; gap: 24px; flex-wrap: wrap; }}
.colophon .row b {{ color: var(--ink-soft); font-weight: 500; }}

/* ------- Print ------- */
@page {{
  size: A4;
  margin: 14mm 12mm 18mm;
}}

@media print {{
  html, body {{
    background: var(--paper);
    font-size: 11pt;
  }}
  .page {{
    max-width: none;
    margin: 0;
    padding: 0 0 16pt;
    box-shadow: none;
  }}
  .masthead {{
    margin: 0 0 18pt;
    padding: 14pt 18pt;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}
  .exhibit {{ top: 36pt; right: 0; }}
  .timeline-item {{ break-inside: avoid; }}
  .signal {{ break-inside: avoid; }}
  .summary {{ break-inside: avoid; }}
  .wildcard-row {{ break-inside: avoid; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .issuer-row .bar .fill {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style>
</head>
<body>
<div class="page">
  <header class="masthead">
    <p class="eyebrow">Certificate Transparency Timeline</p>
    <h1>Infrastructure Issuance Dossier</h1>
    <div class="target">{target_safe}</div>
    <div class="meta-row">
      <span><b>Generated</b>{generated_at}</span>
      <span><b>Source</b>crt.sh CT mirror</span>
      <span><b>Scope</b>{scope_label}</span>
      <span><b>Tool</b>ct-timeline v{tool_version}</span>
    </div>
  </header>

  <div class="exhibit">Exhibit {exhibit_id}</div>

  <section class="section">
    <div class="section-head">
      <span class="num">01</span>
      <h2>Summary</h2>
      <span class="right">{date_range_label}</span>
    </div>
    {summary_html}
  </section>

  {signals_section}

  <section class="section">
    <div class="section-head">
      <span class="num">{timeline_section_num}</span>
      <h2>Chronological Timeline</h2>
      <span class="right">{timeline_count_label}</span>
    </div>
    {timeline_html}
  </section>

  <section class="section">
    <div class="section-head">
      <span class="num">{wildcards_section_num}</span>
      <h2>Wildcard Certificates</h2>
      <span class="right">{wildcard_count_label}</span>
    </div>
    {wildcards_html}
  </section>

  <section class="section">
    <div class="section-head">
      <span class="num">{issuers_section_num}</span>
      <h2>Issuer Breakdown</h2>
      <span class="right">{issuer_count_label}</span>
    </div>
    {issuers_html}
  </section>

  <footer class="colophon">
    <div class="row">
      <span><b>Report ID</b>{exhibit_id}</span>
      <span><b>Query</b>q=%.{target_safe}{scope_query_label}</span>
      <span><b>Total entries</b>{total_entries}</span>
    </div>
    <div class="row" style="margin-top:6px;">
      <span>Certificate Transparency timestamps are signed by independent log operators per RFC 6962 / RFC 9162. The not_before field reflects CA-asserted issuance time; entry_timestamp reflects the log operator's signed ingestion time. For evidentiary use, verify against the originating log.</span>
    </div>
  </footer>
</div>
</body>
</html>
"""


def fmt_dt(dt: datetime | None, with_time: bool = True) -> str:
    if not dt:
        return ""
    if with_time:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    return dt.strftime("%Y-%m-%d")


def render_summary(analysis: dict) -> str:
    if analysis["total_certs"] == 0:
        return '<div class="empty">No certificates found for this target.</div>'

    span_days = ""
    if analysis["date_min"] and analysis["date_max"]:
        days = (analysis["date_max"] - analysis["date_min"]).days
        span_days = f"{days} days"

    cells = [
        ("Certificates", analysis["total_certs"], "logged"),
        ("Wildcard certs", analysis["wildcard_count"], "of total"),
        ("Unique names", analysis["unique_names"], "across all certs"),
        ("Unique CAs", analysis["unique_issuers"], span_days),
    ]
    html = '<div class="summary">'
    for label, value, unit in cells:
        html += (
            f'<div class="cell">'
            f'<p class="label">{escape(label)}</p>'
            f'<div class="value">{value}</div>'
            f'<div class="unit">{escape(unit)}</div>'
            f'</div>'
        )
    html += "</div>"
    return html


def render_signals(signals: list[dict]) -> str:
    if not signals:
        return ""
    rows = []
    for s in signals:
        rows.append(
            f'<div class="signal kind-{s["kind"]}">'
            f'<div class="when">{fmt_dt(s["when"], with_time=False)}</div>'
            f'<div>'
            f'<p class="title">{escape(s["title"])}</p>'
            f'<p class="detail">{escape(s["detail"])}</p>'
            f'</div>'
            f'</div>'
        )
    return (
        '<section class="section">'
        '<div class="section-head">'
        '<span class="num">02</span>'
        '<h2>Pattern Signals</h2>'
        f'<span class="right">{len(signals)} detected</span>'
        '</div>' + "".join(rows) +
        '</section>'
    )


def render_timeline(entries: list[dict]) -> str:
    if not entries:
        return '<div class="empty">No timeline entries to display.</div>'

    items = []
    for e in entries:
        wildcard_cls = " wildcard" if is_wildcard(e["names"]) else ""
        date_str = e["not_before"].strftime("%Y-%m-%d")
        time_str = e["not_before"].strftime("%H:%M UTC")
        sct_note = ""
        if e["entry_timestamp"]:
            sct_note = f'<span class="time">SCT {e["entry_timestamp"].strftime("%H:%M")}</span>'

        names_html_parts = []
        for n in e["names"]:
            cls = "wildcard-name" if n.startswith("*.") else ""
            names_html_parts.append(
                f'<span class="name {cls}">{escape(n)}</span>'
            )
        names_html = "".join(names_html_parts)

        meta = (
            f'<span class="issuer">{escape(e["issuer"])}</span>'
            f' &nbsp;&middot;&nbsp; valid through {fmt_dt(e["not_after"], with_time=False)}'
        )

        items.append(
            f'<div class="timeline-item{wildcard_cls}">'
            f'<div class="bates">'
            f'<span class="date">{date_str}</span>'
            f'<span class="time">{time_str}</span>'
            f'{sct_note}'
            f'</div>'
            f'<div class="names">{names_html}</div>'
            f'<div class="meta">{meta}</div>'
            f'</div>'
        )

    return '<div class="timeline">' + "".join(items) + "</div>"


def render_wildcards(wildcards: list[dict]) -> str:
    if not wildcards:
        return '<div class="empty">No wildcard certificates issued for this target.</div>'

    rows = []
    for w in wildcards:
        wc_names = [n for n in w["names"] if n.startswith("*.")]
        rows.append(
            f'<div class="wildcard-row">'
            f'<div class="when">{fmt_dt(w["not_before"], with_time=False)}</div>'
            f'<div class="name">{escape(", ".join(wc_names))}</div>'
            f'<div class="issuer">{escape(w["issuer"])}</div>'
            f'</div>'
        )
    return '<div class="wildcard-list">' + "".join(rows) + "</div>"


def render_issuers(breakdown: list[dict]) -> str:
    if not breakdown:
        return '<div class="empty">No issuer data available.</div>'

    max_pct = max((b["pct"] for b in breakdown), default=1)
    rows = []
    for b in breakdown:
        width = (b["pct"] / max_pct) * 100 if max_pct else 0
        rows.append(
            f'<div class="issuer-row">'
            f'<div class="name">{escape(b["issuer"])}</div>'
            f'<div class="count">{b["count"]}  ({b["pct"]:.1f}%)</div>'
            f'<div class="bar"><div class="fill" style="width:{width:.1f}%"></div></div>'
            f'</div>'
        )
    return '<div class="issuers">' + "".join(rows) + "</div>"


def render_html(
    domain: str,
    entries: list[dict],
    analysis: dict,
    include_expired: bool,
) -> str:
    target_safe = escape(domain)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scope_label = "All historical certs" if include_expired else "Unexpired certs only"
    scope_query = "" if include_expired else "&exclude=expired"

    date_range_label = ""
    if analysis["date_min"] and analysis["date_max"]:
        date_range_label = (
            f'{fmt_dt(analysis["date_min"], with_time=False)} '
            f'to {fmt_dt(analysis["date_max"], with_time=False)}'
        )

    exhibit_id = datetime.now(timezone.utc).strftime("CT-%Y%m%d-%H%M")

    summary_html = render_summary(analysis)
    signals_section = render_signals(analysis["signals"])
    timeline_html = render_timeline(entries)
    wildcards_html = render_wildcards(analysis["wildcards"])
    issuers_html = render_issuers(analysis["issuer_breakdown"])

    has_signals = bool(analysis["signals"])
    timeline_section_num = "03" if has_signals else "02"
    wildcards_section_num = "04" if has_signals else "03"
    issuers_section_num = "05" if has_signals else "04"

    return HTML_TEMPLATE.format(
        target_safe=target_safe,
        tool_version=TOOL_VERSION,
        generated_at=generated_at,
        scope_label=scope_label,
        scope_query_label=scope_query,
        exhibit_id=exhibit_id,
        date_range_label=date_range_label,
        summary_html=summary_html,
        signals_section=signals_section,
        timeline_section_num=timeline_section_num,
        wildcards_section_num=wildcards_section_num,
        issuers_section_num=issuers_section_num,
        timeline_count_label=f"{analysis['total_certs']} entries",
        wildcard_count_label=f"{analysis['wildcard_count']} of {analysis['total_certs']}",
        issuer_count_label=f"{analysis['unique_issuers']} unique",
        timeline_html=timeline_html,
        wildcards_html=wildcards_html,
        issuers_html=issuers_html,
        total_entries=analysis["total_certs"],
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a forensic CT timeline report for a domain."
    )
    parser.add_argument("domain", help="Target apex domain (e.g. example.com)")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output HTML file path (default: ct-timeline-<domain>-<date>.html)"
    )
    parser.add_argument(
        "--include-expired",
        action="store_true",
        help="Include expired certificates in the report"
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the report in the default browser after generation"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain or "/" in domain or " " in domain:
        print(f"Invalid domain: {domain!r}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[*] Querying crt.sh for {domain} ...", file=sys.stderr)

    raw = fetch_ct_data(domain, include_expired=args.include_expired)
    if not args.quiet:
        print(f"[*] Received {len(raw)} raw entries", file=sys.stderr)

    entries = normalize_entries(raw)
    if not args.quiet:
        print(f"[*] Deduplicated to {len(entries)} unique certificates", file=sys.stderr)

    analysis = analyze(domain, entries)
    if not args.quiet and analysis["signals"]:
        print(f"[*] Detected {len(analysis['signals'])} pattern signals", file=sys.stderr)

    html = render_html(domain, entries, analysis, include_expired=args.include_expired)

    if args.output:
        out_path = Path(args.output)
    else:
        date_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
        out_path = Path(f"ct-timeline-{domain}-{date_tag}.html")

    out_path.write_text(html, encoding="utf-8")

    if not args.quiet:
        print(f"[+] Report written: {out_path.resolve()}", file=sys.stderr)

    if args.open:
        webbrowser.open(out_path.resolve().as_uri())

    return 0


if __name__ == "__main__":
    sys.exit(main())
