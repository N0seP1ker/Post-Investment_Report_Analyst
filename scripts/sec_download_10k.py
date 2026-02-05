#!/usr/bin/env python3
"""
Download ALL 10-K filings for each target company from SEC EDGAR submissions JSON.

- Reads sources_edgar.yaml (company + ticker + optional fiscal_year/form)
- Resolves ticker -> CIK using SEC company_tickers.json
- Fetches https://data.sec.gov/submissions/CIK##########.json
- Collects all rows where form matches (default 10-K) from:
    - filings.recent
    - each extra JSON listed in filings.files (if present)
  SEC notes filings.files exists when there are additional filings beyond the recent set. :contentReference[oaicite:1]{index=1}
- Downloads each filing's primaryDocument from Archives
- Logs one line per downloaded filing in data/manifest.jsonl

This downloads HTML most of the time (10-K primary docs are commonly HTML).
You can convert HTML -> PDF later in a separate script.
"""

import argparse
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import yaml


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
    # Keep these for future flexibility, but “all 10-Ks” doesn’t need fiscal_year
    fiscal_year: Optional[int] = None
    form: str = "10-K"


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
                fiscal_year=t.get("fiscal_year"),
                form=str(t.get("form", "10-K")).strip(),
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
    """
    If the entity has additional filings, submissions JSON can contain filings.files
    which points to additional JSON files and date ranges. :contentReference[oaicite:2]{index=2}
    """
    files = submissions.get("filings", {}).get("files", [])
    urls = []
    for f in files:
        name = f.get("name")
        if name:
            # names look like "CIK0000320193-2020.json"
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

    # 1) recent
    for row in iter_recent_rows(submissions):
        if row["form"].upper().strip() == target_form:
            out.append(row)

    # 2) extra “files” (older filings buckets)
    for url in iter_extra_file_urls(submissions):
        try:
            extra = get_json(s, url, limiter=limiter, timeout=timeout)
        except Exception:
            continue
        for row in iter_recent_rows(extra):  # extra JSON uses same 'recent' column-array format
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


def save_file(path: Path, content: bytes) -> None:
    ensure_dir(path.parent)
    path.write_bytes(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="sources_edgar.yaml")
    ap.add_argument("--out_dir", default="data/sec_raw")
    ap.add_argument("--manifest", default="data/manifest.jsonl")
    ap.add_argument(
        "--user_agent",
        default=os.getenv("SEC_USER_AGENT", "PostInvestmentAgent (your_email@example.com)"),
        help="Set env SEC_USER_AGENT to include real contact info.",
    )
    ap.add_argument("--rps", type=float, default=2.0, help="Keep well below SEC limits.")
    ap.add_argument("--timeout", type=int, default=60)

    # Optional filters
    ap.add_argument("--max_per_company", type=int, default=0, help="0=all; else limit downloads per company")
    ap.add_argument("--since_year", type=int, default=0, help="0=all years; else only reportDate year >= since_year")
    args = ap.parse_args()

    targets_path = Path(args.targets)
    out_dir = Path(args.out_dir)
    manifest_path = Path(args.manifest)
    ensure_dir(manifest_path.parent)

    limiter = RateLimiter(rps=args.rps)
    s = sec_session(args.user_agent)

    print("[INFO] Loading ticker->CIK mapping...")
    ticker_to_cik = load_ticker_to_cik(s, limiter)

    targets = load_targets(targets_path)
    print(f"[INFO] Loaded {len(targets)} targets")

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
            target_form=t.form,
            timeout=args.timeout,
        )
        if not filings:
            print(f"[WARN] No {t.form} filings found for {t.ticker}")
            continue

        # Apply optional since_year filter using reportDate
        if args.since_year:
            def year_ok(r: Dict[str, str]) -> bool:
                rd = (r.get("reportDate") or "").strip()
                return len(rd) >= 4 and rd[:4].isdigit() and int(rd[:4]) >= args.since_year
            filings = [r for r in filings if year_ok(r)]

        if args.max_per_company and args.max_per_company > 0:
            filings = filings[: args.max_per_company]

        print(f"[INFO] {t.ticker}: downloading {len(filings)} x {t.form}")

        for f in filings:
            accession_number = f["accessionNumber"]
            acc_nodash = accession_number.replace("-", "")
            primary_doc = f["primaryDocument"]
            filing_date = f["filingDate"]
            report_date = f.get("reportDate", "")

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

            content_hash = sha256_bytes(content)

            save_path = out_dir / t.ticker / t.form / accession_number / primary_doc
            if save_path.exists():
                if sha256_bytes(save_path.read_bytes()) == content_hash:
                    continue
                save_path = save_path.with_name(f"{save_path.stem}_{content_hash[:8]}{save_path.suffix}")

            save_file(save_path, content)

            record = {
                "timestamp_utc": now_iso_utc(),
                "company": t.company,
                "ticker": t.ticker,
                "cik": str(cik),
                "form": t.form,
                "report_date": report_date,
                "filing_date": filing_date,
                "accession_number": accession_number,
                "primary_document": primary_doc,
                "source_submissions_url": sub_url,
                "download_url": doc_url,
                "saved_path": str(save_path.as_posix()),
                "sha256": content_hash,
                "content_type_hint": "html_or_text",
            }
            with manifest_path.open("a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")

            downloaded += 1

    print(f"[DONE] Downloaded {downloaded} filings. Manifest: {manifest_path}")


if __name__ == "__main__":
    main()