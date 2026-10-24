#!/usr/bin/env python3
"""sloth: a night shift for a small website, run by open-weight models on the same box.

Every night it reads yesterday's web server access log and answers the three questions a lazy site owner asks
in the morning:

  1. Did Google come by?   Which sitemap pages a *verified* Googlebot fetched (reverse + forward DNS), and which
                            pages it has never fetched since the sloth started watching.
  2. What broke?           Which URLs returned 404, which of those were attack probes, and for real-looking
                            pages, which live page they should redirect to. EmbeddingGemma shortlists candidates,
                            Gemma picks one or says "none". Redirects are written as suggestions, never applied.
  3. Two lines, please.     Gemma writes a two-sentence brief from the numbers. Every number in its text must
                            appear in the facts, or the brief falls back to a plain template.

Only the Python standard library and a local Ollama server are used. Logs (IP addresses, user agents) never leave
the machine.
"""
import argparse
import datetime as dt
import glob
import gzip
import ipaddress
import json
import math
import os
import re
import socket
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

__version__ = "0.1.0"

DEFAULTS = {
    "site": "https://example.com",
    "log_glob": "/var/log/caddy/access.log*",
    "sitemap": "/var/www/html/sitemap.xml",
    "site_root": "",                     # optional: static files, used to read page titles
    "out_dir": "/var/lib/sloth",
    "ollama": "http://127.0.0.1:11434",
    "chat_model": "gemma4:e2b",
    "embed_model": "embeddinggemma",
    "window_hours": 24,
    "min_similarity": 0.45,              # below this, no candidate is sent to the chat model
    "max_404_paths": 25,                 # page-like 404s judged per night (the slow part)
}

# requests that are attack probes or scanner noise, not lost pages
PROBE = re.compile(
    r"(\.(php\d?|aspx?|jsp|cgi|env|ini|sql|bak|old|swp|log|ya?ml|sh|git)(/|$)|/wp-|/wordpress|/xmlrpc|/cgi-bin|"
    r"/phpmyadmin|/pma|/\.git|/\.env|/\.aws|/\.ssh|/vendor/|/actuator|/boaform|/hnap1|/owa/|/autodiscover|"
    r"/admin(/|$)|/login(/|$)|/setup(/|$)|/console(/|$)|/server-status|/druid|/solr|/telescope|/debug)", re.I)
ASSET = re.compile(r"\.(css|js|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|map|json|txt|xml|pdf|mp4|webm)$", re.I)
PAGE = re.compile(r"^/(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*/?$", re.I)
BOTS = {  # user-agent token -> (name, reverse-DNS suffixes that prove it)
    "googlebot": ("Googlebot", (".googlebot.com", ".google.com", ".googleusercontent.com")),
    "bingbot": ("Bingbot", (".search.msn.com",)),
}


# ---------------------------------------------------------------- config and state
def load_config(path):
    cfg = dict(DEFAULTS)
    if path:
        with open(path, "rb") as f:
            cfg.update(tomllib.load(f))
    return cfg


def load_state(out):
    p = Path(out) / "state.json"
    if p.exists():
        return json.loads(p.read_text())
    return {"since": None, "crawl": {}, "dns": {}, "seen_404": {}}


def save_state(out, state):
    p = Path(out) / "state.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(p)


# ---------------------------------------------------------------- reading the log
def open_any(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


def read_log(pattern, since_ts, until_ts):
    """Caddy JSON access log lines -> dicts. Rotated (.1, .2.gz) files are read too; old lines are skipped."""
    out = []
    for path in sorted(glob.glob(pattern)):
        with open_any(path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                ts = d.get("ts")
                req = d.get("request") or {}
                if not isinstance(ts, (int, float)) or not (since_ts <= ts < until_ts):
                    continue
                h = {k.lower(): (v[0] if isinstance(v, list) and v else v) for k, v in (req.get("headers") or {}).items()}
                uri = req.get("uri") or "/"
                out.append({
                    "ts": ts,
                    "status": int(d.get("status") or 0),
                    "method": req.get("method", ""),
                    "path": uri.split("?", 1)[0] or "/",
                    "ip": h.get("cf-connecting-ip") or req.get("remote_ip") or "",
                    "ua": h.get("user-agent") or "",
                    "referer": h.get("referer") or "",
                })
    return out


def sitemap_paths(src):
    """Paths listed in sitemap.xml (a local file or an URL)."""
    if re.match(r"https?://", src):
        with urllib.request.urlopen(src, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    else:
        text = Path(src).read_text()
    urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)
    return [re.sub(r"^https?://[^/]+", "", u) or "/" for u in urls]


def page_title(site_root, path):
    if site_root:
        f = Path(site_root) / path.strip("/") / "index.html"
        if f.exists():
            m = re.search(r"<title>([^<]{3,200})</title>", f.read_text(errors="replace"))
            if m:
                return re.sub(r"\s+", " ", m.group(1)).strip()
    return slug_words(path)


def slug_words(path):
    return re.sub(r"[-_/.]+", " ", path).strip() or "home"


# ---------------------------------------------------------------- crawler verification
def claimed_bot(ua):
    low = ua.lower()
    for token, (name, _) in BOTS.items():
        if token in low:
            return token, name
    return None, None


def verify_ip(ip, suffixes, cache, resolver=socket):
    """Google's documented check: reverse DNS must end in the crawler's domain, and the forward lookup of that
    hostname must return the same IP. Results are cached for 7 days."""
    key = ip
    hit = cache.get(key)
    if hit and time.time() - hit["at"] < 7 * 86400:
        return hit["ok"], hit.get("host", "")
    ok, host = False, ""
    try:
        ipaddress.ip_address(ip)
        host = resolver.gethostbyaddr(ip)[0].rstrip(".").lower()
        if host.endswith(suffixes):
            addrs = {a[4][0] for a in resolver.getaddrinfo(host, None)}
            ok = ip in addrs
    except (OSError, ValueError, socket.herror, socket.gaierror):
        ok = False
    cache[key] = {"ok": ok, "host": host, "at": time.time()}
    return ok, host


# ---------------------------------------------------------------- ollama
class Ollama:
    def __init__(self, base, chat_model, embed_model, timeout=900):
        self.base, self.chat_model, self.embed_model, self.timeout = base.rstrip("/"), chat_model, embed_model, timeout
        self.calls, self.seconds = 0, 0.0

    def _post(self, path, body):
        t0 = time.time()
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        self.calls += 1
        self.seconds += time.time() - t0
        return data

    def embed(self, texts):
        return self._post("/api/embed", {"model": self.embed_model, "input": texts})["embeddings"]

    def chat_json(self, prompt, schema):
        body = {"model": self.chat_model, "stream": False, "format": schema, "options": {"temperature": 0},
                "think": False,      # a yes/no pick doesn't need a reasoning trace; about 7x fewer tokens on CPU
                "messages": [{"role": "user", "content": prompt}]}
        try:
            data = self._post("/api/chat", body)
        except urllib.error.HTTPError as e:
            if e.code != 400:
                raise
            body.pop("think")        # models without a thinking switch reject the field
            data = self._post("/api/chat", body)
        return json.loads(data["message"]["content"])


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------- the night shift
def classify_404(path, live):
    if PROBE.search(path):
        return "probe"
    if path + "/" in live:
        return "slash"
    if ASSET.search(path):
        return "asset"
    if PAGE.match(path):
        return "page"
    return "other"


JUDGE_SCHEMA = {"type": "object", "properties": {"pick": {"type": "integer"}, "reason": {"type": "string"}},
                "required": ["pick", "reason"]}


def judge_prompt(site, path, cands):
    lines = "\n".join(f"{i}. {c['path']} ({c['title']})" for i, c in enumerate(cands, 1))
    return (f"A request for {site}{path} returned 404 Not Found. These live pages exist on the same site:\n{lines}\n\n"
            "Pick the page that covers the same topic, so a permanent redirect would give the reader what they "
            "were looking for. If none of them is about the same thing, pick 0. A loosely related page is not "
            "good enough. Reply as JSON: {\"pick\": <number>, \"reason\": \"<one short sentence>\"}.")


def suggest_redirects(site, paths, live_pages, llm, min_sim, limit):
    """EmbeddingGemma shortlists 3 live pages per lost path; Gemma picks one or none."""
    out = []
    if not paths:
        return out
    page_vecs = llm.embed([f"{p['title']} ({slug_words(p['path'])})" for p in live_pages])
    lost_vecs = llm.embed([slug_words(p) for p in paths[:limit]])
    for path, vec in zip(paths[:limit], lost_vecs):
        scored = sorted(((cosine(vec, pv), p) for pv, p in zip(page_vecs, live_pages)), key=lambda x: -x[0])[:3]
        cands = [dict(p, sim=round(s, 3)) for s, p in scored if s >= min_sim]
        if not cands:
            out.append({"path": path, "target": None, "reason": "no live page is close enough", "candidates": []})
            continue
        try:
            ans = llm.chat_json(judge_prompt(site, path, cands), JUDGE_SCHEMA)
            pick = int(ans.get("pick", 0))
        except (ValueError, KeyError, TypeError, OSError) as e:
            ans, pick = {"reason": f"model error: {e}"}, 0
        target = cands[pick - 1] if 1 <= pick <= len(cands) else None
        out.append({"path": path, "target": target["path"] if target else None,
                    "sim": target["sim"] if target else None, "reason": str(ans.get("reason", ""))[:240],
                    "candidates": [{"path": c["path"], "sim": c["sim"]} for c in cands]})
    return out


BRIEF_SCHEMA = {"type": "object", "properties": {"brief": {"type": "string"}}, "required": ["brief"]}


def numbers_in(text):
    return set(re.findall(r"\d+(?:\.\d+)?", text))


def morning_brief(facts, llm):
    """Two sentences from the model; any number not present in the facts sends us back to the template."""
    allowed = numbers_in(json.dumps(facts))
    template = (f"Verified Googlebot fetched {facts['sitemap_pages_fetched_by_verified_googlebot']} sitemap pages in "
                f"the last {facts['hours_covered']} hours, and {facts['sitemap_pages_never_fetched_by_googlebot']} of "
                f"{facts['sitemap_pages_total']} have not been fetched since {facts['watching_since']}. "
                f"{facts['lost_page_urls']} lost URLs returned 404, {facts['redirects_waiting_for_approval']} redirects "
                f"are waiting for your approval, and {facts['attack_probe_404s']} 404s were attack probes.")
    if llm is None:
        return template, "template"
    prompt = ("Write a two-sentence morning note for a busy website owner from the facts below. Sentence one: how "
              "far Google's crawler has got through the sitemap. Sentence two: what broke and what is waiting for "
              "approval (if nothing, say so). Plain and calm, no exclamation marks, no advice the facts don't "
              "support, and use only numbers that appear in the facts. Say \"in the last N hours\", not \"window\".\n"
              f"Facts (JSON): {json.dumps(facts)}\nReply as JSON: {{\"brief\": \"...\"}}")
    try:
        text = str(llm.chat_json(prompt, BRIEF_SCHEMA).get("brief", "")).strip()
    except (ValueError, KeyError, TypeError, OSError):
        return template, "template (model error)"
    bad = numbers_in(text) - allowed
    if not text or bad or len(text) > 600:
        return template, f"template (model text rejected: {', '.join(sorted(bad)) or 'empty or too long'})"
    return text, "model"


def caddy_line(s):
    return f"redir {s['path']} {s['target']} permanent    # {s['reason']}"


def run(cfg, now=None, llm=None, resolver=socket, dry=False):
    now = now or time.time()
    out = Path(cfg["out_dir"])
    (out / "reports").mkdir(parents=True, exist_ok=True)
    state = load_state(out)
    since = now - cfg["window_hours"] * 3600
    rows = read_log(cfg["log_glob"], since, now)
    # "watching since" = the oldest log line the sloth has ever seen, not the start of its first window
    state["since"] = state["since"] or (min(r["ts"] for r in rows) if rows else now)
    sitemap = sitemap_paths(cfg["sitemap"])
    live = set(sitemap)

    # 1. crawlers
    claims, verified_pages, fakes = {}, {}, {}
    for r in rows:
        token, name = claimed_bot(r["ua"])
        if not token:
            continue
        ok, host = verify_ip(r["ip"], BOTS[token][1], state["dns"], resolver)
        claims.setdefault(name, [0, 0])
        claims[name][0 if ok else 1] += 1
        if not ok:
            fakes[r["ip"]] = fakes.get(r["ip"], 0) + 1
        elif name == "Googlebot" and r["path"] in live:
            verified_pages.setdefault(r["path"], r["status"])
            c = state["crawl"].setdefault(r["path"], {"count": 0})
            c["count"] += 1
            c["last"] = max(c.get("last", 0), r["ts"])
            c["status"] = r["status"]
    never = [p for p in sitemap if p not in state["crawl"]]

    # 2. what broke
    lost, buckets = {}, {"probe": 0, "slash": 0, "asset": 0, "page": 0, "other": 0}
    for r in rows:
        if r["status"] != 404:
            continue
        kind = classify_404(r["path"], live)
        buckets[kind] += 1
        if kind in ("page", "slash"):
            e = lost.setdefault(r["path"], {"hits": 0, "kind": kind, "referers": set(), "bots": 0})
            e["hits"] += 1
            if r["referer"]:
                e["referers"].add(r["referer"])
            if claimed_bot(r["ua"])[0]:
                e["bots"] += 1
    ranked = sorted(lost, key=lambda p: -lost[p]["hits"])
    suggestions = [{"path": p, "target": p + "/", "reason": "same page without the trailing slash", "sim": None,
                    "candidates": []} for p in ranked if lost[p]["kind"] == "slash"]
    page_paths = [p for p in ranked if lost[p]["kind"] == "page"]
    if page_paths and llm is not None:
        live_pages = [{"path": p, "title": page_title(cfg.get("site_root"), p)} for p in sitemap if p != "/"]
        suggestions += suggest_redirects(cfg["site"], page_paths, live_pages, llm, cfg["min_similarity"],
                                         cfg["max_404_paths"])
    for p in ranked:
        s = state["seen_404"].setdefault(p, {"first": now})
        s["last"], s["hits"] = now, s.get("hits", 0) + lost[p]["hits"]

    # 3. two lines
    todo = [s for s in suggestions if s["target"]]
    facts = {   # key names are written for the model, which reads this dict as JSON
        "hours_covered": cfg["window_hours"], "requests_read": len(rows),
        "sitemap_pages_fetched_by_verified_googlebot": len(verified_pages), "sitemap_pages_total": len(sitemap),
        "sitemap_pages_never_fetched_by_googlebot": len(never),
        "watching_since": dt.datetime.fromtimestamp(state["since"], dt.timezone.utc).strftime("%Y-%m-%d"),
        "requests_from_fake_crawlers": sum(fakes.values()), "not_found_responses": sum(buckets.values()),
        "attack_probe_404s": buckets["probe"], "lost_page_urls": len(lost),
        "redirects_waiting_for_approval": len(todo),
    }
    brief, brief_src = morning_brief(facts, llm)
    day = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
    report = render(cfg, day, facts, brief, brief_src, claims, verified_pages, never, buckets, lost, suggestions, llm)
    if not dry:
        (out / "reports" / f"{day}.md").write_text(report)
        (out / "reports" / f"{day}.caddy").write_text(
            "# Suggested by sloth. Nothing here is applied automatically: review, then paste into your site block.\n"
            + "".join(caddy_line(s) + "\n" for s in todo))
        (out / "latest.md").write_text(report)
        save_state(out, state)
    return {"facts": facts, "brief": brief, "brief_source": brief_src, "suggestions": suggestions, "report": report}


def render(cfg, day, facts, brief, brief_src, claims, verified_pages, never, buckets, lost, suggestions, llm):
    L = [f"# sloth night shift: {day}", "", f"> {brief}", "", f"*Brief written by: {brief_src}.*", ""]
    L += ["## Did Google come by?", ""]
    for name, (ok, bad) in sorted(claims.items()):
        L.append(f"- {name}: {ok} verified requests, {bad} from IPs that only claimed to be {name}.")
    if not claims:
        L.append("- No crawler requests in this window.")
    L.append(f"- Sitemap pages fetched by verified Googlebot in the last {facts['hours_covered']} h: "
             f"{len(verified_pages)} of {facts['sitemap_pages_total']}.")
    L.append(f"- Never fetched by verified Googlebot since {facts['watching_since']}: {len(never)}.")
    if never:
        L += [""] + [f"  - {p}" for p in never[:20]]
        if len(never) > 20:
            L.append(f"  - and {len(never) - 20} more")
    L += ["", "## What broke?", "",
          f"404 responses: {facts['not_found_responses']} (probes {buckets['probe']}, missing assets {buckets['asset']}, "
          f"lost pages {buckets['page']}, missing trailing slash {buckets['slash']}, other {buckets['other']}).", ""]
    if suggestions:
        L += ["| Lost URL | Hits | Suggested redirect | Why |", "|---|---|---|---|"]
        for s in suggestions:
            hits = lost.get(s["path"], {}).get("hits", "")
            tgt = f"`{s['target']}`" + (f" (similarity {s['sim']})" if s.get("sim") else "") if s["target"] else "none"
            L.append(f"| `{s['path']}` | {hits} | {tgt} | {s['reason'].replace('|', '/')} |")
        L += ["", "Ready-to-review Caddy lines are in the matching `.caddy` file. Nothing was applied.", ""]
    else:
        L.append("No lost pages in this window.")
    L += ["", "## How the sloth worked", "",
          f"- Requests read: {facts['requests_read']} (last {facts['hours_covered']} h).",
          f"- Models: {cfg['chat_model']} and {cfg['embed_model']} on {cfg['ollama']} "
          + (f"({llm.calls} calls, {llm.seconds:.0f} s of model time)." if llm else "(not used).")]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sloth", description=__doc__.split("\n")[0])
    ap.add_argument("-c", "--config", default=os.environ.get("SLOTH_CONFIG", "/etc/sloth/sloth.toml"))
    ap.add_argument("--no-model", action="store_true", help="skip the models (template brief, no redirect picks)")
    ap.add_argument("--dry", action="store_true", help="print the report, write nothing")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    cfg = load_config(a.config if Path(a.config).exists() else None)
    llm = None if a.no_model else Ollama(cfg["ollama"], cfg["chat_model"], cfg["embed_model"])
    t0 = time.time()
    res = run(cfg, llm=llm, dry=a.dry)
    print(res["report"] if a.dry else res["brief"])
    print(f"done in {time.time() - t0:.0f} s", file=sys.stderr)


if __name__ == "__main__":
    main()
