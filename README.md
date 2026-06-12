# ct-timeline

Generate a forensic-style timeline report from Certificate Transparency logs.

`ct_timeline.py` pulls CT data from [crt.sh](https://crt.sh) for a given domain, processes it chronologically, detects pattern signals (first wildcard appearance, CA migrations, issuance bursts), and produces a self-contained HTML report. The report is print-friendly and exports cleanly to PDF via any browser's print dialog.

Written for OSINT investigators who want a defensible, dateable artifact rather than a screenshot of a search box.

Companion to the blog post: [Certificate Transparency as a Timeline Source](https://blog.osintph.info/ct-logs-as-osint-timeline/) on [blog.osintph.info](https://blog.osintph.info).

## Why this exists

crt.sh in a browser is fine for ad-hoc lookups. It is not fine for evidence work. The defaults sort by ID rather than chronology, the 10,000 row cap silently truncates results on busy domains, and there is no signal detection at all. This script wraps the JSON endpoint, deduplicates the precert and cert pairs, sorts properly, surfaces three useful pattern signals, and produces a report that looks like something you would attach to a case file.

## Requirements

Python 3.10 or newer. No third-party dependencies. Standard library only.

## Install

```bash
git clone https://github.com/osintph/ct-timeline.git
cd ct-timeline
chmod +x ct_timeline.py
```

Or just download the single `.py` file. It is self-contained.

## Usage

```bash
# Basic run, outputs HTML report in current directory
python3 ct_timeline.py example.com

# Custom output path
python3 ct_timeline.py example.com --output ./reports/example-2026.html

# Include expired certificates (much slower on big targets, often hits crt.sh row cap)
python3 ct_timeline.py example.com --include-expired

# Auto-open the report in your default browser after generation
python3 ct_timeline.py example.com --open

# Quiet mode for scripting
python3 ct_timeline.py example.com --quiet
```

## What the report contains

1. **Summary** with total certificates, wildcard count, unique names across all certs, and CA diversity.
2. **Pattern Signals** that surface automatically when detected: first-ever wildcard appearance, CA migrations, and bursts of 5 or more certs in a 24-hour window.
3. **Chronological Timeline** with each certificate plotted against a vertical rule, showing the `not_before` date, the SCT log timestamp where available, all SAN names, and the issuing CA. Wildcards are visually distinguished.
4. **Wildcard Certificates** in a dedicated highlight block. These are usually where the interesting infrastructure shifts show up.
5. **Issuer Breakdown** with proportional distribution. Useful for spotting procurement decisions and CA migrations.
6. **Provenance footer** with report ID, query parameters, and a note on CT timestamp semantics for evidentiary use.

## Exporting to PDF

The HTML is designed with print stylesheets and `@page` rules. To produce a PDF:

1. Open the generated HTML in any modern browser.
2. Print (`Cmd+P` or `Ctrl+P`).
3. Choose "Save as PDF" as the destination.
4. Use A4 paper size with default margins. The print stylesheet handles the rest.

For headless PDF generation, install [WeasyPrint](https://weasyprint.org) and run:

```bash
weasyprint ct-timeline-example.com-20260612.html report.pdf
```

WeasyPrint is not bundled because most users will not need it.

## Known limitations

These are limits of CT and crt.sh rather than the script, but worth knowing.

- **crt.sh has a 10,000 row hard cap.** On very high-volume domains like `google.com` or `facebook.com`, recent certificates may be missing from the response. Always run with the default `--exclude-expired` on big targets. For comprehensive monitoring of busy domains, use [Cert Spotter](https://sslmate.com/certspotter/) or [Censys](https://search.censys.io) instead.
- **Pre-2018 coverage is patchy.** Apple's mandatory CT policy came in October 2018. Earlier certificates may or may not be in the public logs.
- **`not_before` can be backdated.** CAs commonly set `not_before` a few minutes to a few hours before actual issuance. For minute-precision work, prefer the SCT `entry_timestamp` shown in the timeline.
- **Internal-only certs are invisible.** Anything issued by a private CA for an internal name will never appear in CT.

## Pattern signals: how they work

Three signals fire when their conditions are met in the data.

**`first_wildcard`** fires when the first wildcard certificate for the target appears after at least three prior non-wildcard certs. This usually indicates infrastructure consolidation onto a load balancer, CDN, or service mesh, which means the target's team was working on a project for weeks before the cert appeared.

**`ca_shift`** fires when a new CA issues for the target after at least five prior certs from other CAs. CA changes are procurement decisions, often driven by audits, compliance certifications, or platform migrations.

**`burst`** fires when 5 or more certificates are issued within any 24-hour window. Bursts indicate platform migrations, mass re-issuance after key rotation, or onboarding onto a CDN that re-issues for all names.

Signals are conservative by design. The intent is for the report to highlight things worth investigating, not to drown the reader in noise.

## Use responsibly

Certificate Transparency is public infrastructure. Using it to enumerate a target's infrastructure for unauthorized purposes is at minimum unethical and likely illegal in your jurisdiction. This script is intended for legitimate uses: brand protection, threat intelligence on infrastructure mimicking your own, defender visibility into shadow IT, attack surface management, and authorized red team engagements.

If you find an unannounced product or service via CT monitoring of someone else's domain, do not publish a teardown. Note it, file it, move on.

## License

MIT. Do what you want with it, just do not blame me.

## Author

Sigmund Brandstaetter, OSINT-PH. Blog: [blog.osintph.info](https://blog.osintph.info).
