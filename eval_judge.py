#!/usr/bin/env python3
"""Replay one night's lost URLs through the redirect judge, with Gemma's thinking off and on, and time both.

    python3 eval_judge.py -c /etc/sloth/sloth.toml --until 2026-10-24T22:32:44Z --out eval.json

Writes every outcome (kind, target, reason, candidates) and the seconds each judgement took. Score it against a
reference-label file (examples/labels-*.json: path -> {"ok_targets": [...], "ok_hubs": [...], "why": "..."}) with
--labels.
"""
import argparse
import datetime as dt
import json
import time

import sloth


class Timed:
    """Wraps the Ollama client and records how long each chat (redirect judgement) takes."""
    def __init__(self, llm):
        self.llm, self.chat_seconds = llm, []

    def embed(self, texts):
        return self.llm.embed(texts)

    def chat_json(self, prompt, schema, think=False):
        t0 = time.time()
        try:
            return self.llm.chat_json(prompt, schema, think=think)
        finally:
            self.chat_seconds.append(round(time.time() - t0, 1))


def replay(cfg, until, think, llm):
    rows = sloth.read_log(cfg["log_glob"], until - cfg["window_hours"] * 3600, until, cfg["client_ip_header"],
                          cfg["trusted_proxies"])
    sitemap = sloth.sitemap_paths(cfg["sitemap"])
    live = set(sitemap)
    hits = {}
    for r in rows:
        if r["status"] == 404 and sloth.classify_404(r["path"], live) == "page":
            hits[r["path"]] = hits.get(r["path"], 0) + 1
    paths = sorted(hits, key=lambda p: -hits[p])[:cfg["max_404_paths"]]
    pages = [{"path": p, "title": sloth.page_title(cfg.get("site_root"), p)} for p in sitemap if p != "/"]
    timed = Timed(llm)         # same call pattern as a real night: embed everything first, then one chat per URL
    out = sloth.suggest_redirects(cfg["site"], paths, pages, timed, cfg["min_similarity"], len(paths), think=think,
                                  hub_prefix=cfg["hub_prefix"])
    times = iter(timed.chat_seconds)
    for s in out:
        s["hits"] = hits[s["path"]]
        s["seconds"] = next(times) if s["candidates"] else 0.0
    return out


def score(results, labels):
    """Strict score against reference labels. Only an active redirect (kind "redirect") counts as shipped; section-page
    suggestions are commented out in the .caddy file, so they never count as a redirect.
      right:   the label lists accepted pages and the redirect goes to one of them, or the label lists none and
               nothing was redirected
      found:   redirects to an accepted page
      wrong:   redirects to a page the label doesn't accept
      hubs_ok: section-page suggestions the label also lists in ok_hubs (lenient view)"""
    r = {"n": 0, "right": 0, "found": 0, "wrong": 0, "hubs": 0, "hubs_ok": 0, "wrong_list": []}
    for s in results:
        lab = labels.get(s["path"])
        if lab is None:
            continue
        r["n"] += 1
        active = s["target"] if s["kind"] == "redirect" else None
        if active and active in lab["ok_targets"]:
            r["found"] += 1
        elif active:
            r["wrong"] += 1
            r["wrong_list"].append(f"{s['path']} -> {active}")
        r["right"] += (active in lab["ok_targets"]) if lab["ok_targets"] else (active is None)
        if s["kind"] == "hub":
            r["hubs"] += 1
            r["hubs_ok"] += s["target"] in lab.get("ok_hubs", [])
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default="/etc/sloth/sloth.toml")
    ap.add_argument("--until", help="end of the 24 h window, e.g. 2026-10-24T22:32:44Z")
    ap.add_argument("--out", default="eval.json")
    ap.add_argument("--labels")
    ap.add_argument("--rescore", metavar="EVAL_JSON", help="score an earlier run against --labels; no model calls")
    a = ap.parse_args()
    if a.rescore:
        res, labels = json.load(open(a.rescore)), json.load(open(a.labels))
        for k in ("think_off", "think_on"):
            print(k, res[k + "_seconds"], "s", json.dumps(score(res[k], labels)))
        return
    if not a.until:
        ap.error("--until is required unless --rescore is given")
    cfg = sloth.load_config(a.config)
    until = dt.datetime.fromisoformat(a.until.replace("Z", "+00:00")).timestamp()
    llm = sloth.Ollama(cfg["ollama"], cfg["chat_model"], cfg["embed_model"])
    res = {"until": a.until, "model": cfg["chat_model"], "think_off": replay(cfg, until, False, llm),
           "think_on": replay(cfg, until, True, llm)}
    for k in ("think_off", "think_on"):
        res[k + "_seconds"] = round(sum(s["seconds"] for s in res[k]), 1)
    if a.labels:
        labels = json.load(open(a.labels))
        for k in ("think_off", "think_on"):
            res[k + "_score"] = score(res[k], labels)
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if not isinstance(v, list)}))


if __name__ == "__main__":
    main()
