#!/usr/bin/env python3
"""
scanner_per_url_summary.py

Passive-ish, faster, per-URL aggregator:
 - Input: file with seed URLs (one per line)
 - Outputs:
    - reports.xlsx  (one row per URL; columns: URL, Findings Count, Types, Top Payloads, Max Severity, Sample Evidence)
    - report_summary.txt (aggregated counts by type, top hosts, totals)
 - Non-intrusive heuristics; default faster settings (many workers, small delay)
 - WARNING: run only against targets you are authorized to test.
"""

import os
import sys
import time
import json
import argparse
import signal
import warnings
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter

import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ---------- Heuristics & regex (trimmed for speed) ----------
HEADERS = {"User-Agent": "GoldMineLite/fast/1.0 (+passive)"}
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.]{10,}")
AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GENERIC_APIKEY = re.compile(r"(?i)(api[_-]?key|token|secret|client[_-]?secret)[\"'\s:=]{0,4}([A-Za-z0-9\-_]{16,})")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
WS_RE = re.compile(r"\b(wss?:\/\/[^\s\"'<>]+)")
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>()]+")
OPEN_REDIRECT_KEYS = re.compile(r"(?i)(redirect|next|return|url|dest|destination)")
DOM_XSS_SINKS = re.compile(r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\()")
UPLOAD_HINT = re.compile(r"(?i)(upload|multipart/form-data|file\s*:)")
RFI_RCE_HINT = re.compile(r"(?i)(exec\(|child_process|spawn\(|system\()")
ID_PARAM = re.compile(r"(?i)\b(id|user_id|account_id|order_id|uid|pid)\b")
NUM_IN_URL = re.compile(r"/\d{1,12}(/|$)")

OUTDATED_LIBS = [
    (re.compile(r"jquery-([12])\.\d+(\.\d+)?\.js", re.I), "jquery < 3.5 (XSS CVEs)"),
    (re.compile(r"lodash(?:\.|-)3\.", re.I), "lodash v3 (prototype pollution CVEs)"),
    (re.compile(r"angular(?:\.|-)1\.", re.I), "AngularJS 1.x (EOL)"),
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/config.json", "/settings.json", "/package.json", "/composer.json",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/admin", "/login", "/graphql", "/api/v1"
]

SEVERITY = {
    "Hardcoded Credentials": 10,
    "JWT / API Keys": 9,
    "Sensitive Info Leak": 8,
    "Config/Env Disclosure": 9,
    "Hidden Login/Portal": 6,
    "Outdated Library (CVE-prone)": 6,
    "Dependency/Package Disclosure": 5,
    "Upload Endpoint (potential)": 5,
    "RFI/RCE Hint": 9,
    "Open Redirect (param)": 6,
    "WebSocket Endpoint": 4,
    "IDOR Candidate": 5,
    "Service/Endpoint Map": 3,
    "DOM XSS Sink": 7
}

# ---------- Helpers ----------
def norm_url(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def http_get(url, timeout=8, headers=None, delay=0.1):
    if delay and delay > 0:
        time.sleep(delay)
    try:
        r = requests.get(url, headers=headers or HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None

def fetch_text(url, timeout=8, delay=0.1):
    r = http_get(url, timeout=timeout, delay=delay)
    if r is None:
        return None, None
    ctype = (r.headers.get("Content-Type") or "").lower()
    if any(b in ctype for b in ["image/","font/","octet-stream","pdf","video/"]):
        return None, r.headers
    return r.text, r.headers

def extract_assets(base_url, html, gold_keywords=None):
    soup = BeautifulSoup(html or "", "html.parser")
    assets = set()
    for tag in soup.find_all(["script","link","a","img","source"]):
        src = tag.get("src") or tag.get("href") or tag.get("data-src")
        if not src:
            continue
        if src.startswith("mailto:") or src.startswith("tel:"):
            continue
        full = urljoin(base_url, src)
        assets.add(full)
    # include raw URLs in JS/text (limited)
    for m in URL_IN_TEXT.findall(html or ""):
        assets.add(m)
    return list(assets)

def analyze_text(url, text):
    """
    Return list of findings: each is dict {type, detail, evidence, severity}
    """
    findings = []
    def add(kind, detail, evidence=None):
        findings.append({
            "type": kind,
            "detail": detail,
            "evidence": (evidence or "")[:300],
            "severity": SEVERITY.get(kind, 4)
        })

    if not text:
        return findings

    if AWS_ACCESS.search(text) or GCP_KEY.search(text) or GENERIC_APIKEY.search(text) or JWT_RE.search(text):
        m = JWT_RE.search(text)
        add("JWT / API Keys", "Token/API key pattern found", (m.group(0) if m else "key"))

    if re.search(r"(?i)(username|password|passwd|pwd).{0,40}[:=]\s*['\"]", text):
        add("Hardcoded Credentials", "Possible hardcoded credentials pattern")

    if re.search(r"(?i)(config|settings|env|secret|salt)", text):
        add("Sensitive Info Leak", "Config/Env like strings in source")

    emails = set(EMAIL_RE.findall(text))
    if emails:
        add("Sensitive Info Leak", f"Emails exposed: {', '.join(list(emails)[:3])}", ", ".join(list(emails)[:2]))

    if WS_RE.search(text):
        add("WebSocket Endpoint", "WebSocket URL found", WS_RE.search(text).group(0))

    if OPEN_REDIRECT_KEYS.search(text):
        add("Open Redirect (param)", "Redirect-like parameter mentioned in source")

    if UPLOAD_HINT.search(text):
        add("Upload Endpoint (potential)", "Upload related hints")

    if RFI_RCE_HINT.search(text):
        add("RFI/RCE Hint", "Possible server-side exec/child_process references")

    if DOM_XSS_SINKS.search(text):
        add("DOM XSS Sink", "Potential DOM sink found (innerHTML/document.write/eval)")

    if ID_PARAM.search(text) or NUM_IN_URL.search(url):
        add("IDOR Candidate", "ID-like parameter or numeric path detected")

    for rx, msg in OUTDATED_LIBS:
        if rx.search(text) or rx.search(url):
            add("Outdated Library (CVE-prone)", msg)

    if '"dependencies"' in text or '"devDependencies"' in text:
        add("Dependency/Package Disclosure", "package.json-like content visible")

    # embedded URLs -> service map
    embedded = [m for m in URL_IN_TEXT.findall(text) if not m.endswith((".png",".jpg",".jpeg",".gif",".svg"))]
    if embedded:
        add("Service/Endpoint Map", f"{min(len(embedded),8)} embedded URLs (sample)")

    return findings

# ---------- Per-URL scan logic ----------
def scan_single(seed, timeout, delay, max_asset_fetch=6):
    """
    Scan base URL + a few assets (prioritized) and return an aggregated record for that URL.
    """
    base = norm_url(seed)
    record = {
        "url": base,
        "findings": [],  # list of finding dicts
    }
    text, headers = fetch_text(base, timeout=timeout, delay=delay)
    if text:
        record["findings"].extend(analyze_text(base, text))
        assets = extract_assets(base, text)
    else:
        assets = []

    # prioritize assets heuristically (js/json/config first)
    def score(u):
        ul = u.lower()
        s = 0
        if any(x in ul for x in [".js", ".json", "config", "setting", "bundle", "main", "app"]):
            s += 2
        if "?" in ul:
            s += 1
        return s
    assets_sorted = sorted(set(assets), key=score, reverse=True)[:max_asset_fetch]

    # fetch assets quickly
    for a in assets_sorted:
        t, h = fetch_text(a, timeout=timeout, delay=delay)
        if t:
            record["findings"].extend(analyze_text(a, t))

    # check a few common sensitive paths (fast)
    for p in SENSITIVE_PATHS[:6]:
        try:
            sp = urljoin(base, p)
            r = http_get(sp, timeout=4, delay=delay)
            if r and r.status_code == 200:
                ctype = (r.headers.get("Content-Type") or "").lower()
                txt = r.text if "text" in ctype or "json" in ctype or ctype == "" else ""
                record["findings"].append({
                    "type": "Config/Env Disclosure",
                    "detail": f"{p} accessible (HTTP 200)",
                    "evidence": (txt or "")[:300],
                    "severity": SEVERITY.get("Config/Env Disclosure", 9)
                })
            elif r and r.status_code in (401,403):
                record["findings"].append({
                    "type": "Hidden Login/Portal",
                    "detail": f"{p} present but protected (HTTP {r.status_code})",
                    "evidence": "",
                    "severity": SEVERITY.get("Hidden Login/Portal", 6)
                })
        except Exception:
            continue

    # deduplicate findings by (type + truncated evidence)
    uniq = {}
    for f in record["findings"]:
        key = (f.get("type",""), (f.get("evidence") or "")[:120])
        if key not in uniq:
            uniq[key] = f
        else:
            # keep highest severity
            if f.get("severity",0) > uniq[key].get("severity",0):
                uniq[key] = f
    record["findings"] = list(uniq.values())
    return record

# ---------- Aggregation & outputs ----------
def build_reports(records, outdir):
    os.makedirs(outdir, exist_ok=True)
    # reports.xlsx rows: one per URL
    rows = []
    type_counter = Counter()
    host_counter = Counter()
    total_findings = 0

    for rec in records:
        url = rec["url"]
        host = urlparse(url).hostname or url
        host_counter[host] += 1
        findings = rec.get("findings", [])
        total_findings += len(findings)
        # aggregate types, top payload/evidence samples, max severity
        types = []
        sample_evidence = []
        severities = []
        for f in findings:
            t = f.get("type","Unknown")
            types.append(t)
            type_counter[t] += 1
            ev = f.get("evidence") or f.get("detail") or ""
            if ev:
                sample_evidence.append(ev[:200])
            severities.append(int(f.get("severity") or 4)
                              if isinstance(f.get("severity"), (int, float)) else 4)

        types_uniq = sorted(set(types))
        top_payloads = "; ".join(unique_preserve_order(sample_evidence)[:3]) if sample_evidence else ""
        max_sev = max(severities) if severities else 0

        rows.append({
            "URL": url,
            "Findings Count": len(findings),
            "Types": "; ".join(types_uniq),
            "Top Payloads / Evidence (sample)": top_payloads,
            "Max Severity": max_sev
        })

    df = pd.DataFrame(rows)
    df = df.sort_values(by=["Max Severity", "Findings Count"], ascending=[False, False])
    out_xlsx = os.path.join(outdir, "reports.xlsx")
    df.to_excel(out_xlsx, index=False, engine="openpyxl")

    # summary text
    out_txt = os.path.join(outdir, "report_summary.txt")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("GoldMine Lite - Per-URL Summary\n")
        f.write("Generated: " + time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()) + "\n")
        f.write("="*60 + "\n\n")
        f.write(f"Seeds scanned: {len(records)}\n")
        f.write(f"Total findings (deduped): {total_findings}\n\n")
        f.write("Top vulnerability types:\n")
        for t, c in type_counter.most_common(40):
            f.write(f" {t} : {c}\n")
        f.write("\nTop hosts (by rows):\n")
        for h, c in host_counter.most_common(30):
            f.write(f" {h} : {c}\n")
        f.write("\nNotes: This is a passive heuristic scan. Verify findings manually and ensure permission before testing.\n")

    return out_xlsx, out_txt

def unique_preserve_order(seq):
    seen = set()
    out = []
    for s in seq:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out

# ---------- CLI & runner ----------
def parse_args():
    p = argparse.ArgumentParser(description="GoldMine Lite - per-URL aggregated passive scanner (fast)")
    p.add_argument("urls", help="File with seed URLs (one per line)")
    p.add_argument("--out", "-o", default="reports", help="Output folder")
    p.add_argument("--workers", "-w", type=int, default=50, help="Thread workers (higher = faster, more load)")
    p.add_argument("--timeout", "-t", type=int, default=8, help="HTTP timeout seconds")
    p.add_argument("--delay", "-d", type=float, default=0.1, help="Delay between requests (per-thread) in seconds")
    p.add_argument("--assets", type=int, default=6, help="Max assets to fetch per site (for speed)")
    return p.parse_args()

global_state = {"records": [], "start": None, "outdir": "reports"}

def signal_handler(signum, frame):
    print("\n[!] Interrupted. Will save collected results so far...")
    if global_state.get("records"):
        build_reports(global_state["records"], global_state["outdir"])
        print("[+] Partial results saved.")
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

def main():
    args = parse_args()

    if not os.path.exists(args.urls):
        print(f"[!] URLs file not found: {args.urls}")
        sys.exit(1)

    seeds = []
    with open(args.urls, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                seeds.append(ln)

    if not seeds:
        print("[!] No seeds found in the input file.")
        sys.exit(1)

    global_state["start"] = time.time()
    global_state["outdir"] = args.out

    print(f"[+] Starting scan of {len(seeds)} seeds with {args.workers} workers (delay={args.delay}s, assets={args.assets})")
    records = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_map = {ex.submit(scan_single, s, args.timeout, args.delay, args.assets): s for s in seeds}
        for fut in as_completed(future_map):
            seed = future_map[fut]
            try:
                rec = fut.result()
                records.append(rec)
            except Exception as e:
                print(f"[x] Error scanning {seed}: {e}")

    # build outputs
    out_xlsx, out_txt = build_reports(records, args.out)
    print(f"[+] Done. Reports:\n - {out_xlsx}\n - {out_txt}")

if __name__ == "__main__":
    main()
