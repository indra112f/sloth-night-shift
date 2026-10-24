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

   For the lost pages, **EmbeddingGemma** shortlists the three closest live pages, and **Gemma** picks one or answers
   "none of these". The picks are written as Caddy `redir` lines **for you to review**. Nothing is ever applied
   automatically.
3. **Two lines, please.** Gemma writes a two-sentence brief from the numbers. Every number in its text has to appear
   in the facts it was given. If one doesn't, the brief is thrown away and a plain template is used instead.

```text
access.log (JSON, stays on the box)
   │
   ├─ verify crawlers ── reverse + forward DNS ──► crawl coverage vs sitemap.xml (kept across nights)
   │
   └─ 404s ── probe / asset / slash / page
                                   │
                                   ├─ EmbeddingGemma: 3 closest live pages (cosine, min 0.45)
                                   └─ Gemma 4 (e2b): pick 1-3 or 0, one-line reason
                                                         │
                                       reports/YYYY-MM-DD.md  +  reports/YYYY-MM-DD.caddy (suggestions only)
```

## Why it runs on open models, on the same machine

- **The log is personal data.** It holds visitors' IP addresses and user agents. sloth sends none of it anywhere.
  The models run on `127.0.0.1`, and the only network traffic is DNS lookups for crawler IPs.
- **No GPU, no bill.** It runs on the same 4 vCPU / 8 GB droplet that serves the site, on CPU, at low priority.
  Night jobs don't need to be fast, so a small open-weight model at a few tokens per second is fine.
- **Swappable.** `chat_model` and `embed_model` are just Ollama tags in the config.

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
- **Bounded picks.** The model can only pick one of the shortlisted pages. If its answer is out of range, malformed,
  or the model errors, the result is "no redirect".
- **Numbers are checked.** Any number in the brief that isn't in the facts throws out the model's text.
- **The website comes first.** The service runs as a `DynamicUser` with `Nice=19`, `CPUQuota=100%`,
  `MemoryMax=512M` and `ProtectSystem=strict`. Its only extra right is read access to the log through the `caddy`
  group.

## Tests

```bash
python3 -m unittest -v      # offline: fake DNS resolver, fake model
```

## Disclosure

The code and this README were written by an AI coding agent (Claude) working on the owner's server at the owner's
direction. The owner reviewed and published it.

## License

MIT
