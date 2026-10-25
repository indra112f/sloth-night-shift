# sloth night shift

A night shift for a small website, run by open-weight models on the same box that serves the site.

Once a day, sloth reads the web server's access log and leaves a short report for the morning. It answers the three
questions a site owner otherwise checks by hand:

1. **Did Google come by?** It lists which sitemap pages a *verified* Googlebot fetched, and which pages Google has
   never fetched since sloth started watching. A crawler only counts as verified when its IP's reverse DNS ends in
   `googlebot.com`, `google.com` or `googleusercontent.com` and the forward lookup returns the same IP. That is
   Google's documented check, so a scraper that only copies Googlebot's user agent doesn't count. Bingbot is checked
   the same way against `search.msn.com`.
2. **What broke?** It splits every 404 into four groups:
   - attack probes (`/wp-login.php`, `/.env`, and so on), which are counted and ignored
   - missing assets
   - URLs that only lack a trailing slash
   - real-looking pages that used to exist

   For each lost page:
   - **EmbeddingGemma** shortlists the three closest live pages, plus the closest section page.
   - **Gemma** labels every candidate `same_topic`, `same_area` or `different`, then picks one or answers "none".
   - Only a pick that Gemma itself labeled `same_topic` becomes a redirect. A section page labeled `same_area` is
     written as a weaker suggestion, commented out.
   - A lost URL that keeps getting requested with no equivalent goes on a **worth restoring** list.

   Redirects are written as Caddy `redir` lines **for you to review**. Nothing is ever applied automatically.
3. **Two lines, please.** Gemma writes a two-sentence brief from the numbers. Every number in its text has to appear
   in the facts it was given. If one doesn't, the brief is thrown away and a plain template is used instead.

```text
access.log (JSON, stays on the box)
   │
   ├─ verify crawlers ── reverse + forward DNS ──► crawl coverage vs sitemap.xml (kept across nights)
   │
   └─ 404s ── probe / asset / slash / page
                                   │
                                   ├─ EmbeddingGemma: 3 closest live pages + closest section page
                                   └─ Gemma 4 (e2b): label each candidate, pick one or 0
                                                         │
                            redirect (same topic) / section page (weaker, commented out) / worth restoring
                                                         │
                                       reports/YYYY-MM-DD.md  +  reports/YYYY-MM-DD.caddy (suggestions only)
```

## Why it runs on open models, on the same machine

- **The log is personal data.** It holds visitors' IP addresses and user agents. sloth sends none of it anywhere.
  The models run on `127.0.0.1` and only see URLs, page titles and counts. The only network traffic is DNS lookups
  for IPs that claim to be a crawler (plus the sitemap, if you give a URL), and those DNS results are dropped from
  `state.json` after 7 days.
- **No GPU, no bill.** It runs on the same 4 vCPU / 8 GB droplet that serves the site, on CPU, at low priority.
  Night jobs don't need to be fast, so a small open-weight model at a few tokens per second is fine.
- **Swappable.** `chat_model` and `embed_model` are just Ollama tags in the config.
- **Measured, not assumed.** Gemma 4 can reason before it answers (`judge_think = true`). On coremesh.online's first
  night that was 4.6x slower and made twice as many wrong redirects (6 vs 3), so it's off by default.
  `eval_judge.py` replays a night's lost URLs with thinking off and on, so you can measure it on your own log.

## Install (Ubuntu 24.04, Caddy, Ollama)

```bash
# 1. models (CPU is fine)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull gemma4:e2b
ollama pull embeddinggemma

# 2. keep the website first: cap Ollama at 3 cores / 6 GB, lower priority
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo cp systemd/ollama-limits.conf /etc/systemd/system/ollama.service.d/limits.conf

# 3. sloth itself (standard library only, Python 3.11+)
sudo mkdir -p /opt/sloth /etc/sloth
sudo cp sloth.py /opt/sloth/
sudo cp sloth.example.toml /etc/sloth/sloth.toml       # edit site, log_glob, sitemap
sudo cp systemd/sloth.service systemd/sloth.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl restart ollama && sudo systemctl enable --now sloth.timer
```

Caddy needs a JSON access log in the site block:

```text
log {
    output file /var/log/caddy/access.log
    format json
}
```

Then:
- read the latest report with `cat /var/lib/sloth/latest.md`
- try a run without writing anything: `python3 sloth.py -c /etc/sloth/sloth.toml --dry`
- run without the models: `--no-model` gives the template brief and makes no redirect picks

## Safety rails

- **Redirects are suggestions.** The `.caddy` file starts with "Nothing here is applied automatically".
- **Bounded picks.** The model can only pick one of the shortlisted pages, and only a pick it labeled `same_topic`
  counts. If its answer is out of range, malformed, or the model errors, the result is "no redirect".
- **Numbers are checked.** Any number in the brief that isn't in the facts throws out the model's text.
- **Forged headers don't count.** Behind Cloudflare, the visitor's address is in `Cf-Connecting-Ip`. sloth trusts
  that header only when the connection itself came from one of Cloudflare's published ranges (built in, see
  `CLOUDFLARE` in `sloth.py`). Anyone else could write a Googlebot IP into it. Not behind a proxy? Set
  `client_ip_header = ""`.
- **The website comes first.** The service runs as a `DynamicUser` with `Nice=19`, `CPUQuota=100%`,
  `MemoryMax=512M` and `ProtectSystem=strict`. Its only extra right is read access to the log through the `caddy`
  group.

## Tests

```bash
python3 -m unittest -v      # offline: fake DNS resolver, fake model

# replay one night's lost URLs through the judge, thinking off and on, scored against reference labels
python3 eval_judge.py -c /etc/sloth/sloth.toml --until 2026-10-24T22:32:44Z --labels examples/labels-2026-10-24.json
```

`examples/` holds the real first-night report from coremesh.online (made by v0.1), a replay of the same night with
v0.2, the reference labels and the evaluation output.

| Judge on night 1 (25 lost URLs) | Right outcome (strict) | Wrong redirects | Model time |
|---|---|---|---|
| v0.1: single pick, no labels | 6 of 24 | 17 | 289 s (whole run, 22 calls) |
| v0.2, thinking off (default) | 18 of 25 | 3 | 649 s (judge calls only) |
| v0.2, thinking on | 16 of 25 | 6 | 2964 s (judge calls only) |

- **Right** means a redirect to a page the label accepts, or no redirect where the label accepts nothing. A
  section-page suggestion never counts, because it ships commented out.
- **v0.1's 17** includes 3 redirects to a fitting section page, because v0.1 made those live redirects.
- **v0.1 has 24 rows.** It judged `/config.json.save` (no label; v0.2 calls it a probe) and not
  `/claude-api-user-profiles/`.
- **Timing.** 22 of the 25 URLs had a close enough candidate to judge, so thinking off is about 30 s per judged URL
  and thinking on about 2 min 15 s. A whole v0.2 run of that night took 769 s of model time.
- **Caveat.** v0.2's prompt was written after seeing night 1's mistakes and scored on the same URLs, so v0.1 vs v0.2
  is not a held-out test. Thinking off vs on is like for like.

Labels (each with a reason) and scoring rules are in `examples/labels-2026-10-24.json` and `eval_judge.py`. Disagree
with a label? Change it and re-score the saved outcomes without running any model:

```bash
python3 eval_judge.py --rescore examples/eval-2026-10-24.json --labels examples/labels-2026-10-24.json
```

## Disclosure

The code, the evaluation and this README were written by an AI coding agent (Claude) working on the owner's server
at the owner's direction. The reference labels were written by the agent too, each with a reason, so you can check
them. One label (`/claude-code-skills/`) was corrected after an independent review.

## License

MIT
