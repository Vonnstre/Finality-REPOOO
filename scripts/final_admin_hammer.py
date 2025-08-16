#!/usr/bin/env python3
# final_admin_hammer.py — orchestrates the last aggressive layer end-to-end.
import argparse, os, sys, json, subprocess, time, shlex, concurrent.futures, httpx, re, csv
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--targets", required=True)
ap.add_argument("--ua", default="Mozilla/5.0")
ap.add_argument("--outdir", required=True)
ap.add_argument("--nuclei-templates", required=True)
ap.add_argument("--nuclei-rate", default="120")
ap.add_argument("--concurrency", type=int, default=4)
ap.add_argument("--perhost-rate", default="6")
ap.add_argument("--aggressive", default="false")
ap.add_argument("--dry-run", default="true")
args = ap.parse_args()

OUT = Path(args.outdir)
RAW = OUT/"raw"; EVID = OUT/"evidence"; FIND = OUT/"findings"
for d in (RAW, EVID/"har", EVID/"screens", FIND):
    d.mkdir(parents=True, exist_ok=True)

with open(args.targets) as f:
    TARGETS = [l.strip() for l in f if l.strip() and not l.startswith("#")]

def run(cmd, stdin_txt=None):
    p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE if stdin_txt else None,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(stdin_txt)
    return p.returncode, out, err

# 1) baseline via httpx
def baseline(targets):
    cmd = f'httpx -silent -status-code -title -ip -json -H "User-Agent: {args.ua}" -threads 100 -timeout 8 -ports 80,443'
    code, out, err = run(cmd, "\n".join(targets))
    with open(RAW/"baseline.jsonl","w") as w:
        for line in out.splitlines():
            try: json.loads(line); w.write(line+"\n")
            except: pass
    print(f"[baseline] {len(out.splitlines())} lines")

# 2) headless capture per host (HAR-lite, endpoints, cookies)
def headless(host):
    cmd = f'node scripts/headless_capture.js {shlex.quote(host)} {EVID} {RAW} "{args.ua}"'
    code, out, err = run(cmd)
    return {"host":host,"ok":code==0,"stdout":out.strip(),"stderr":err.strip()}

# 3) quick security headers + clickjacking/CSP sniff (fast wins)
def sec_headers(host):
    url = f"https://{host}"
    res = {"host":host,"module":"headers"}
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as cli:
            r = cli.get(url, headers={"User-Agent":args.ua})
            hx = {k.lower():v for k,v in r.headers.items()}
            res.update({
                "status": r.status_code,
                "xfo": hx.get("x-frame-options",""),
                "csp": hx.get("content-security-policy",""),
                "cors": hx.get("access-control-allow-origin",""),
                "refpol": hx.get("referrer-policy",""),
                "hsts": hx.get("strict-transport-security","")
            })
    except Exception as e:
        res.update({"error": str(e)})
    return res

# 4) CORS / preflight on discovered endpoints
def cors_probe():
    apis = RAW/"discovered_apis.jsonl"
    outp = FIND/"cors.jsonl"
    if not apis.exists(): return
    with open(outp,"w") as out, httpx.Client(timeout=6.0) as cli:
        for line in apis.read_text().splitlines():
            try: rec = json.loads(line)
            except: continue
            try:
                r = cli.options(rec["url"], headers={
                    "Origin":"http://evil.example","Access-Control-Request-Method":"GET"})
                aco = r.headers.get("Access-Control-Allow-Origin","")
                aca = r.headers.get("Access-Control-Allow-Credentials","")
                if aco == "*" or "evil.example" in aco or (aca and aca.lower()=="true"):
                    out.write(json.dumps({"host":rec["host"],"module":"cors","url":rec["url"],"aco":aco,"acac":aca})+"\n")
            except Exception:
                pass
    print("[cors] done")

# 5) token replay (read-only)
def token_replay():
    sessions = {}
    sp = RAW/"sessions.jsonl"
    if not sp.exists(): return
    for l in sp.read_text().splitlines():
        try: s=json.loads(l); sessions[s["host"]]=s
        except: pass
    apis = RAW/"discovered_apis.jsonl"
    if not apis.exists(): return
    outp = FIND/"token_replay.jsonl"
    with open(outp,"w") as out, httpx.Client(timeout=8.0, verify=True) as cli:
        for line in apis.read_text().splitlines():
            try: rec=json.loads(line)
            except: continue
            host,url = rec["host"], rec["url"]
            sess = sessions.get(host)
            if not sess: continue
            ck = "; ".join([f'{c["name"]}={c.get("value","")}' for c in sess.get("cookies",[]) if c.get("name")])
            hdr = {"User-Agent":"FinalAdminLayer/1.0"}
            if ck: hdr["Cookie"]=ck
            try:
                r = cli.get(url, headers=hdr, follow_redirects=True)
                if r.status_code in (200,206) and len(r.content)>50:
                    out.write(json.dumps({"host":host,"module":"token_replay","url":url,"status":r.status_code,"proof_snippet":r.text[:200].replace("\n"," ")})+"\n")
            except: pass
    print("[token_replay] done")

# 6) IDOR light (URL id swap)
ID_RX = re.compile(r"([?&/])(id|user_id|uid|account_id|org_id)=?(\d+)", re.I)
def swap_ids(url):
    m = ID_RX.search(url)
    if not m: return []
    current = m.group(3)
    outs=[]
    for alt in ("1","2","3","4","5"):
        if alt!=current: outs.append(ID_RX.sub(lambda g: f"{g.group(1)}{g.group(2)}={alt}", url, count=1))
    return outs

def idor_probe():
    apis = RAW/"discovered_apis.jsonl"
    sessions = { json.loads(l)["host"]: json.loads(l)
                 for l in RAW.open("r").read().splitlines()
                 if l and l.startswith('{') } if (RAW/"sessions.jsonl").exists() else {}
    outp = FIND/"idor.jsonl"
    if not apis.exists(): return
    with open(outp,"w") as out, httpx.Client(timeout=8.0, follow_redirects=True) as cli:
        for line in apis.read_text().splitlines():
            try: rec=json.loads(line)
            except: continue
            host,url = rec["host"], rec["url"]
            sess = sessions.get(host, {})
            ck = "; ".join([f'{c["name"]}={c.get("value","")}' for c in sess.get("cookies",[]) if c.get("name")])
            hdr={"User-Agent":"FinalAdminLayer/1.0"}; 
            if ck: hdr["Cookie"]=ck
            for test_url in swap_ids(url):
                try:
                    r = cli.get(test_url, headers=hdr)
                    if r.status_code in (200,206) and len(r.content)>50:
                        out.write(json.dumps({"host":host,"module":"idor","original":url,"test_url":test_url,"status":r.status_code,"proof_snippet":r.text[:200].replace("\n"," ")})+"\n")
                except: pass
    print("[idor] done")

# 7) ffuf small targeted list (bundled inline)
FFUF_WORDS = "/admin\n/login\n/signin\n/dashboard\n/console\n/wp-admin\n/.git/\n/config.json\n/api/graphql\n/graphql\n"

def ffuf_run(targets):
    wl = RAW/"admin-mini.txt"; wl.write_text(FFUF_WORDS)
    for h in targets:
        out = FIND/f"ffuf.{h}.json"
        cmd = f'ffuf -w "{wl}" -u "https://{h}/FUZZ" -mc 200,301,302 -t 40 -r -of json -o "{out}"'
        run(cmd)

# 8) nuclei targeted packs
def nuclei_run(targets):
    targetfile = RAW/"targets.txt"; targetfile.write_text("\n".join(targets)+"\n")
    base = f'-t {args.nuclei_templates}/http/takeovers -t {args.nuclei_templates}/http/exposures -t {args.nuclei_templates}/http/misconfiguration'
    if args.aggressive.lower() == "true":
        base += f' -t {args.nuclei_templates}/http/vulnerabilities -t {args.nuclei_templates}/http/cves'
    cmd = f'nuclei -l "{targetfile}" {base} -severity medium,high,critical --rate-limit {args.nuclei_rate} -jsonl -o "{FIND}/nuclei.jsonl"'
    run(cmd)

# 9) aggregate quick triage CSV (priority heuristic)
def aggregate():
    rows=[]
    for p in FIND.glob("*.jsonl"):
        mod=p.stem
        for line in p.read_text().splitlines():
            try: r=json.loads(line)
            except: continue
            r["_source"]=mod; rows.append(r)
    csvp = OUT/"triage.csv"
    with open(csvp,"w",newline="") as f:
        w=csv.DictWriter(f, fieldnames=["priority","host","module","url","status","proof"])
        w.writeheader()
        for r in rows:
            mod = r.get("module") or r.get("_source")
            url = r.get("url", r.get("test_url",""))
            status = r.get("status","")
            proof = (r.get("proof_snippet","") or "")[:180]
            pr = 1 if mod in ("token_replay","cors","idor") else 2
            w.writerow({"priority":pr,"host":r.get("host"),"module":mod,"url":url,"status":status,"proof":proof})
    print(f"[aggregate] {csvp}")

def main():
    print(f"[targets] {len(TARGETS)}")
    baseline(TARGETS)

    # headless per host (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        list(ex.map(headless, TARGETS))

    # security headers quick wins
    hdr_out = FIND/"headers.jsonl"
    with open(hdr_out,"w") as w:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            for rec in ex.map(sec_headers, TARGETS):
                w.write(json.dumps(rec)+"\n")

    cors_probe()
    token_replay()
    idor_probe()
    ffuf_run(TARGETS)
    nuclei_run(TARGETS)
    aggregate()
    print("[final] done")

if __name__=="__main__":
    main()
