#!/usr/bin/env python3
import argparse, os, json, glob, pathlib, csv
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--in", dest="indir", required=True)
ap.add_argument("--evidence-root", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()

pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)

# load triage
triage_csv = pathlib.Path(args.indir).parent/"triage.csv"
triage = []
if triage_csv.exists():
    import csv as _csv
    with open(triage_csv) as f:
        r=_csv.DictReader(f)
        triage = list(r)

# group JSONL findings by host
byhost = defaultdict(list)
for p in glob.glob(os.path.join(args.indir,"*.jsonl")):
    for line in open(p):
        line=line.strip()
        if not line: continue
        try: rec=json.loads(line)
        except: continue
        h = rec.get("host") or "unknown"
        byhost[h].append(rec)

for host, items in byhost.items():
    har = f"{args.evidence_root}/har/{host}.har"
    png = f"{args.evidence_root}/screens/{host}.png"
    md_path = os.path.join(args.out, f"{host}.md")
    lines=[]
    lines.append(f"# {host} — Final Layer Findings\n")
    lines.append("## Evidence\n")
    if os.path.exists(png): lines.append(f"- Screenshot: `{png}`")
    if os.path.exists(har): lines.append(f"- HAR: `{har}`")
    lines.append("\n## Quick Triage\n")
    for row in (triage or []):
        if row.get("host")==host:
            lines.append(f"- [{row['priority']}] **{row['module']}** → {row.get('status','')} — {row.get('url','')}  \n  `{row.get('proof','')}`")

    cats = defaultdict(list)
    for it in items:
        cats[it.get("module","other")].append(it)

    for mod, arr in cats.items():
        lines.append(f"\n## {mod}\n")
        for r in arr:
            url = r.get("url", r.get("test_url",""))
            proof = (r.get("proof_snippet","") or "")[:300].replace("\n"," ")
            status = r.get("status","")
            extra = ""
            if mod=="cors": extra = f" (ACO={r.get('aco','')}, ACAC={r.get('acac','')})"
            lines.append(f"- `{status}` {url}{extra}  \n  `{proof}`")

    with open(md_path,"w") as f: f.write("\n".join(lines)+"\n")
    print(f"[report] {md_path}")
