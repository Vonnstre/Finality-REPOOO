#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

(async () => {
  const [,, host, evidenceDir, rawDir, ua] = process.argv;
  if (!host) process.exit(2);
  const url = `https://${host}`;
  const harPath = path.join(evidenceDir, "har", `${host}.har`);
  const pngPath = path.join(evidenceDir, "screens", `${host}.png`);
  const sessionsPath = path.join(rawDir, "sessions.jsonl");
  const apisPath = path.join(rawDir, "discovered_apis.jsonl");

  fs.mkdirSync(path.dirname(harPath), { recursive: true });
  fs.mkdirSync(path.dirname(pngPath), { recursive: true });
  fs.mkdirSync(path.dirname(sessionsPath), { recursive: true });
  fs.mkdirSync(path.dirname(apisPath), { recursive: true });

  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox","--disable-setuid-sandbox"]
  });
  const page = await browser.newPage();
  await page.setUserAgent(ua || "Mozilla/5.0");
  await page.setViewport({ width: 1366, height: 900 });

  const requests = [];
  page.on("requestfinished", async (req) => {
    try {
      const res = await req.response();
      const url = req.url();
      const method = req.method();
      const status = res ? res.status() : 0;
      const ct = res && res.headers()["content-type"] || "";
      requests.push({ url, method, status, ct });
    } catch {}
  });

  try {
    await page.goto(url, { waitUntil: "networkidle2", timeout: 45000 });
    await page.screenshot({ path: pngPath });
  } catch (e) {}

  const cookies = await page.cookies();
  const ls = await page.evaluate(() => {
    const out = {};
    try { for (let i=0;i<localStorage.length;i++){ const k=localStorage.key(i); out[k]=localStorage.getItem(k);} } catch(e){}
    return out;
  });

  fs.writeFileSync(harPath, JSON.stringify({ host, requests, ts: Date.now() }, null, 2));
  fs.appendFileSync(sessionsPath, JSON.stringify({ host, cookies, localStorage: ls, ts: Date.now() })+"\n");

  const apiGuesses = requests
    .map(r => r.url)
    .filter(u => /\/api\/|graphql|\/admin\/|\/v\d\//i.test(u))
    .filter((v,i,a)=>a.indexOf(v)===i);
  apiGuesses.forEach(u => fs.appendFileSync(apisPath, JSON.stringify({ host, url: u })+"\n"));

  await browser.close();
  console.log(`[headless] ${host} -> ${apiGuesses.length} endpoints`);
})();
