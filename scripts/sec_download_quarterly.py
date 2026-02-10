#!/usr/bin/env python3
"""
Download quarterly reports (10-Q) from SEC EDGAR and organize as raw/{company}/{yyyy_qx.pdf}

- Reads sources_edgar.yaml for company list
- Downloads 10-Q filings from SEC EDGAR
- Converts HTML to PDF using weasyprint or wkhtmltopdf
- Organizes as: raw/{company_name}/{yyyy}_q{quarter}.pdf
"""

import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
import yaml

# Try to import PDF conversion libraries
PDF_CONVERTER = None
WeasyHTML = None
pdfkit = None

try:
    from weasyprint import HTML as WeasyHTML
    PDF_CONVERTER = "weasyprint"
except (ImportError, OSError):
    # OSError can occur on Windows if GTK libraries are missing
    pass

if not PDF_CONVERTER:
    try:
        import pdfkit
        PDF_CONVERTER = "pdfkit"
    except (ImportError, OSError):
        pass


TICKER_CIK_JSON = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik_padded}.json"
ARCHIVES_PRIMARY_DOC = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc_nodash}/{primary_doc}"


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


@dataclass
class Target:
    company: str
    ticker: str
    form: str = "10-Q"


class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.001)
        self.last = 0.0

    def wait(self):
        now = time.time()
        dt = now - self.last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self.last = time.time()


def sec_session(user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "application/json,text/html,*/*",
        }
    )
    return s


def get_json(s: requests.Session, url: str, limiter: RateLimiter, timeout: int = 30) -> Any:
    limiter.wait()
    r = s.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def get_bytes(s: requests.Session, url: str, limiter: RateLimiter, timeout: int = 60) -> bytes:
    limiter.wait()
    r = s.get(url, timeout=timeout)
    r.raise_for_status()
    return r.content


def load_targets(path: Path) -> List[Target]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out: List[Target] = []
    for t in data.get("targets", []):
        out.append(
            Target(
                company=t["company"],
                ticker=str(t["ticker"]).upper().strip(),
                form="10-Q",  # Force 10-Q for quarterly reports
            )
        )
    return out


def load_ticker_to_cik(s: requests.Session, limiter: RateLimiter) -> Dict[str, int]:
    data = get_json(s, TICKER_CIK_JSON, limiter=limiter)
    mapping: Dict[str, int] = {}
    for _, row in data.items():
        ticker = str(row.get("ticker", "")).upper().strip()
        cik = int(row.get("cik_str"))
        if ticker:
            mapping[ticker] = cik
    return mapping


def iter_recent_rows(submissions: Dict[str, Any]) -> Iterable[Dict[str, str]]:
    recent = submissions.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    accession = recent.get("accessionNumber", [])
    filing_date = recent.get("filingDate", [])
    report_date = recent.get("reportDate", [])
    primary_doc = recent.get("primaryDocument", [])

    n = len(forms)
    for i in range(n):
        yield {
            "form": str(forms[i]),
            "accessionNumber": str(accession[i]),
            "filingDate": str(filing_date[i]),
            "reportDate": str(report_date[i] or ""),
            "primaryDocument": str(primary_doc[i]),
        }


def iter_extra_file_urls(submissions: Dict[str, Any]) -> List[str]:
    files = submissions.get("filings", {}).get("files", [])
    urls = []
    for f in files:
        name = f.get("name")
        if name:
            urls.append("https://data.sec.gov/submissions/" + name)
    return urls


def collect_all_filings(
    s: requests.Session,
    limiter: RateLimiter,
    submissions: Dict[str, Any],
    target_form: str,
    timeout: int,
) -> List[Dict[str, str]]:
    target_form = target_form.upper().strip()
    out: List[Dict[str, str]] = []

    # Recent filings
    for row in iter_recent_rows(submissions):
        if row["form"].upper().strip() == target_form:
            out.append(row)

    # Extra files (older filings)
    for url in iter_extra_file_urls(submissions):
        try:
            extra = get_json(s, url, limiter=limiter, timeout=timeout)
        except Exception:
            continue
        for row in iter_recent_rows(extra):
            if row["form"].upper().strip() == target_form:
                out.append(row)

    # Dedup by accession number
    seen = set()
    deduped = []
    for r in out:
        acc = r["accessionNumber"]
        if acc not in seen:
            seen.add(acc)
            deduped.append(r)

    # Sort newest first
    deduped.sort(key=lambda x: x.get("filingDate", ""), reverse=True)
    return deduped


def extract_quarter_from_report_date(report_date: str) -> Optional[str]:
    """
    Extract quarter from report date (YYYY-MM-DD).
    Returns: yyyy_qX (e.g., "2025_q1")
    """
    if not report_date or len(report_date) < 10:
        return None

    try:
        year = report_date[:4]
        month = int(report_date[5:7])

        # Map months to quarters
        if month in [1, 2, 3]:
            quarter = "q1"
        elif month in [4, 5, 6]:
            quarter = "q2"
        elif month in [7, 8, 9]:
            quarter = "q3"
        else:
            quarter = "q4"

        return f"{year}_{quarter}"
    except (ValueError, IndexError):
        return None


def html_to_pdf(html_content: bytes, output_path: Path) -> bool:
    """Convert HTML to PDF using available converter."""
    if not PDF_CONVERTER:
        print("[WARN] No PDF converter available. Install: pip install weasyprint")
        return False

    try:
        if PDF_CONVERTER == "weasyprint":
            # Save HTML temporarily
            temp_html = output_path.with_suffix('.html')
            temp_html.write_bytes(html_content)

            # Convert to PDF
            WeasyHTML(filename=str(temp_html)).write_pdf(str(output_path))

            # Clean up temp HTML
            temp_html.unlink()
            return True

        elif PDF_CONVERTER == "pdfkit":
            # Save HTML temporarily
            temp_html = output_path.with_suffix('.html')
            temp_html.write_bytes(html_content)

            # Convert to PDF
            pdfkit.from_file(str(temp_html), str(output_path))

            # Clean up temp HTML
            temp_html.unlink()
            return True
    except Exception as e:
        print(f"[ERROR] PDF conversion failed: {e}")
        return False

    return False


def save_file(path: Path, content: bytes) -> None:
    ensure_dir(path.parent)
    path.write_bytes(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="sources_edgar.yaml")
    ap.add_argument("--out_dir", default="data/raw")
    ap.add_argument("--manifest", default="data/quarterly_manifest.jsonl")
    ap.add_argument(
        "--user_agent",
        default=os.getenv("SEC_USER_AGENT", "PostInvestmentAgent (your_email@example.com)"),
        help="Set env SEC_USER_AGENT to include real contact info.",
    )
    ap.add_argument("--rps", type=float, default=2.0, help="Keep well below SEC limits.")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--max_per_company", type=int, default=0, help="0=all; else limit downloads per company")
    ap.add_argument("--since_year", type=int, default=0, help="0=all years; else only reportDate year >= since_year")
    ap.add_argument("--no_pdf", action="store_true", help="Save as HTML instead of converting to PDF")

    args = ap.parse_args()

    if not args.no_pdf and not PDF_CONVERTER:
        print("[ERROR] No PDF converter found. Install one:")
        print("  pip install weasyprint")
        print("Or use --no_pdf to save HTML files")
        return

    targets_path = Path(args.targets)
    out_dir = Path(args.out_dir)
    manifest_path = Path(args.manifest)
    ensure_dir(manifest_path.parent)

    limiter = RateLimiter(rps=args.rps)
    s = sec_session(args.user_agent)

    print("[INFO] Loading ticker->CIK mapping...")
    ticker_to_cik = load_ticker_to_cik(s, limiter)

    targets = load_targets(targets_path)
    print(f"[INFO] Loaded {len(targets)} targets for 10-Q downloads")

    downloaded = 0

    for t in targets:
        cik = ticker_to_cik.get(t.ticker)
        if not cik:
            print(f"[WARN] No CIK found for {t.ticker} ({t.company})")
            continue

        cik_padded = f"{cik:010d}"
        sub_url = SUBMISSIONS_URL.format(cik_padded=cik_padded)

        try:
            submissions = get_json(s, sub_url, limiter=limiter, timeout=args.timeout)
        except Exception as e:
            print(f"[WARN] Failed submissions for {t.ticker}: {e}")
            continue

        filings = collect_all_filings(
            s=s,
            limiter=limiter,
            submissions=submissions,
            target_form="10-Q",
            timeout=args.timeout,
        )

        if not filings:
            print(f"[WARN] No 10-Q filings found for {t.ticker}")
            continue

        # Apply optional since_year filter
        if args.since_year:
            def year_ok(r: Dict[str, str]) -> bool:
                rd = (r.get("reportDate") or "").strip()
                return len(rd) >= 4 and rd[:4].isdigit() and int(rd[:4]) >= args.since_year
            filings = [r for r in filings if year_ok(r)]

        if args.max_per_company and args.max_per_company > 0:
            filings = filings[: args.max_per_company]

        print(f"[INFO] {t.ticker}: downloading {len(filings)} x 10-Q")

        for f in filings:
            accession_number = f["accessionNumber"]
            acc_nodash = accession_number.replace("-", "")
            primary_doc = f["primaryDocument"]
            filing_date = f["filingDate"]
            report_date = f.get("reportDate", "")

            # Extract quarter info
            quarter_str = extract_quarter_from_report_date(report_date)
            if not quarter_str:
                print(f"[WARN] Could not extract quarter from {report_date}, skipping")
                continue

            doc_url = ARCHIVES_PRIMARY_DOC.format(
                cik=cik,
                acc_nodash=acc_nodash,
                primary_doc=primary_doc,
            )

            try:
                content = get_bytes(s, doc_url, limiter=limiter, timeout=args.timeout)
            except Exception as e:
                print(f"[WARN] Download failed {t.ticker} {accession_number}: {e}")
                continue

            # Determine file extension
            ext = "pdf" if not args.no_pdf else "html"

            # Save to raw/{ticker}/{yyyy_qx.pdf}
            ticker_dir = out_dir / t.ticker
            ensure_dir(ticker_dir)

            save_path = ticker_dir / f"{quarter_str}.{ext}"

            # Check if file exists
            if save_path.exists():
                print(f"[INFO] Skipping {t.ticker} {quarter_str} (already exists)")
                continue

            # Convert to PDF if needed
            if not args.no_pdf:
                print(f"[INFO] Converting {t.ticker} {quarter_str} to PDF...")
                if html_to_pdf(content, save_path):
                    print(f"[OK] Saved {save_path}")
                else:
                    # Save as HTML if conversion fails
                    save_path = save_path.with_suffix('.html')
                    save_file(save_path, content)
                    print(f"[WARN] Saved as HTML: {save_path}")
            else:
                save_file(save_path, content)
                print(f"[OK] Saved {save_path}")

            # Log to manifest
            record = {
                "timestamp_utc": now_iso_utc(),
                "company": t.company,
                "ticker": t.ticker,
                "cik": str(cik),
                "form": "10-Q",
                "report_date": report_date,
                "filing_date": filing_date,
                "quarter": quarter_str,
                "accession_number": accession_number,
                "primary_document": primary_doc,
                "download_url": doc_url,
                "saved_path": str(save_path.as_posix()),
                "sha256": sha256_bytes(content),
            }
            with manifest_path.open("a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")

            downloaded += 1

    print(f"\n[DONE] Downloaded {downloaded} quarterly reports. Manifest: {manifest_path}")
    if not args.no_pdf and PDF_CONVERTER:
        print(f"[INFO] Using PDF converter: {PDF_CONVERTER}")


if __name__ == "__main__":
    main()
