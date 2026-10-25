"""Offline tests: no network, no Ollama. Run with `python3 -m unittest -v`."""
import json
import socket
import tempfile
import time
import unittest
from pathlib import Path

import sloth

NOW = 1_800_000_000.0
GOOD_IP, FAKE_IP, HUMAN_IP = "66.249.66.1", "203.0.113.9", "198.51.100.7"


def line(path, status, ua="Mozilla/5.0", ip=HUMAN_IP, ago=3600, referer=None):
    h = {"User-Agent": [ua], "Cf-Connecting-Ip": [ip]}
    if referer:
        h["Referer"] = [referer]
    return json.dumps({"ts": NOW - ago, "status": status, "request": {"method": "GET", "uri": path, "headers": h,
                                                                       "remote_ip": "162.158.1.1"}})


class Resolver:
    """Stands in for socket: only GOOD_IP reverse-resolves to a googlebot.com host that resolves back."""
    def gethostbyaddr(self, ip):
        if ip == GOOD_IP:
            return ("crawl-66-249-66-1.googlebot.com.", [], [ip])
        if ip == FAKE_IP:
            return ("vps.example.net", [], [ip])
        raise socket.herror("no PTR")

    def getaddrinfo(self, host, port):
        if host == "crawl-66-249-66-1.googlebot.com":
            return [(2, 1, 6, "", (GOOD_IP, 0))]
        return [(2, 1, 6, "", ("192.0.2.1", 0))]


class FakeLLM:
    """Bag-of-words vectors for embed; scripted answers for chat. `match` is the verdict given to every candidate."""
    def __init__(self, brief="Googlebot fetched 2 pages; 1 lost page has a suggested redirect.", pick=1,
                 match="same_topic"):
        self.brief, self.pick, self.match, self.calls, self.seconds = brief, pick, match, 0, 0.0
        self.vocab, self.thinks = {}, []

    def embed(self, texts):
        out = []
        for t in texts:
            v = [0.0] * 64
            for w in t.lower().replace("(", " ").replace(")", " ").split():
                v[self.vocab.setdefault(w, len(self.vocab) % 64)] += 1
            out.append(v)
        return out

    def chat_json(self, prompt, schema, think=False):
        self.calls += 1
        self.thinks.append(think)
        if "brief" in schema["properties"]:
            return {"brief": self.brief}
        n = len([l for l in prompt.splitlines() if l[:1].isdigit() and ". /" in l])      # numbered candidates
        return {"lost_topic": "x", "pick": self.pick, "reason": "same topic",
                "verdicts": [{"n": i, "match": self.match} for i in range(1, n + 1)]}


class SlothTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "sitemap.xml").write_text(
            "<urlset>" + "".join(f"<url><loc>https://example.com{p}</loc></url>" for p in
                                 ["/", "/python-virtual-environment/", "/git-rebase-vs-merge/", "/cors-error/",
                                  "/topics/python/"]) + "</urlset>")
        self.log = self.d / "access.log"
        self.cfg = dict(sloth.DEFAULTS, site="https://example.com", log_glob=str(self.d / "access.log*"),
                        sitemap=str(self.d / "sitemap.xml"), out_dir=str(self.d / "out"), min_similarity=0.2)

    def write(self, lines):
        self.log.write_text("\n".join(lines) + "\n")

    def test_googlebot_verified_and_fake(self):
        gb = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        self.write([line("/python-virtual-environment/", 200, gb, GOOD_IP),
                    line("/git-rebase-vs-merge/", 200, gb, GOOD_IP),
                    line("/cors-error/", 200, gb, FAKE_IP),
                    line("/old-page/", 200, ago=3 * 86400)])          # outside the window
        res = sloth.run(self.cfg, now=NOW, llm=None, resolver=Resolver())
        f = res["facts"]
        self.assertEqual(f["sitemap_pages_fetched_by_verified_googlebot"], 2)
        self.assertEqual(f["requests_from_fake_crawlers"], 1)
        self.assertEqual(f["sitemap_pages_never_fetched_by_googlebot"], 3)  # "/", /cors-error/ (fake bot), /topics/python/
        self.assertEqual(f["requests_read"], 3)

    def test_404_buckets_and_redirects(self):
        self.write([line("/wp-login.php", 404), line("/.env", 404), line("/assets/old.css", 404),
                    line("/cors-error", 404),                              # missing trailing slash
                    line("/python-virtual-env-guide/", 404), line("/python-virtual-env-guide/", 404),
                    line("/totally-unrelated-zebra/", 404)])
        llm = FakeLLM(pick=1)
        res = sloth.run(self.cfg, now=NOW, llm=llm, resolver=Resolver())
        f = res["facts"]
        self.assertEqual(f["attack_probe_404s"], 2)
        self.assertEqual(f["lost_page_urls"], 3)
        by = {s["path"]: s for s in res["suggestions"]}
        self.assertEqual(by["/cors-error"]["target"], "/cors-error/")
        self.assertEqual(by["/python-virtual-env-guide/"]["target"], "/python-virtual-environment/")
        caddy = (Path(self.cfg["out_dir"]) / "reports").glob("*.caddy")
        text = next(caddy).read_text()
        self.assertIn("redir /python-virtual-env-guide/ /python-virtual-environment/ permanent", text)
        self.assertTrue(text.startswith("# Suggested by sloth. Nothing here is applied automatically"))

    def test_model_pick_zero_means_no_redirect(self):
        self.write([line("/python-venv-guide/", 404)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(pick=0), resolver=Resolver())
        self.assertNotEqual(res["suggestions"][0]["kind"], "redirect")
        self.assertEqual(res["facts"]["redirects_waiting_for_approval"], 0)

    def test_out_of_range_pick_is_ignored(self):
        self.write([line("/python-venv-guide/", 404)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(pick=7), resolver=Resolver())
        self.assertNotEqual(res["suggestions"][0]["kind"], "redirect")
        self.assertEqual(res["facts"]["redirects_waiting_for_approval"], 0)

    def test_brief_with_invented_number_falls_back(self):
        self.write([line("/", 200)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(brief="Traffic grew 340 percent overnight."), resolver=Resolver())
        self.assertTrue(res["brief_source"].startswith("template"))
        self.assertIn("340", res["brief_source"])

    def test_brief_from_model_when_numbers_check_out(self):
        self.write([line("/", 200)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(brief="Quiet night: 1 request and 0 lost pages."),
                        resolver=Resolver())
        self.assertEqual(res["brief_source"], "model")

    def test_coverage_persists_across_nights(self):
        gb = "Googlebot/2.1"
        self.write([line("/python-virtual-environment/", 200, gb, GOOD_IP)])
        sloth.run(self.cfg, now=NOW, llm=None, resolver=Resolver())
        self.write([line("/git-rebase-vs-merge/", 200, gb, GOOD_IP, ago=3600 - 86400)])
        res = sloth.run(self.cfg, now=NOW + 86400, llm=None, resolver=Resolver())
        self.assertEqual(res["facts"]["sitemap_pages_never_fetched_by_googlebot"], 3)     # 5 pages, 2 fetched over two nights

    def test_forged_proxy_header_is_ignored(self):
        gb = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        forged = json.loads(line("/python-virtual-environment/", 200, gb, GOOD_IP))
        forged["request"]["remote_ip"] = FAKE_IP          # not a Cloudflare address, so its header can't be trusted
        self.log.write_text(json.dumps(forged) + "\n")
        f = sloth.run(self.cfg, now=NOW, llm=None, resolver=Resolver())["facts"]
        self.assertEqual(f["sitemap_pages_fetched_by_verified_googlebot"], 0)
        self.assertEqual(f["requests_from_fake_crawlers"], 1)

    def test_old_dns_results_are_dropped(self):
        out = self.d / "state"
        out.mkdir()
        sloth.save_state(out, {"since": None, "crawl": {}, "seen_404": {},
                               "dns": {FAKE_IP: {"ok": False, "at": NOW - 8 * 86400}, GOOD_IP: {"ok": True, "at": NOW}}},
                         now=NOW)
        self.assertEqual(list(sloth.load_state(out)["dns"]), [GOOD_IP])

    def test_dns_cache(self):
        cache = {}
        ok, host = sloth.verify_ip(GOOD_IP, (".googlebot.com",), cache, Resolver())
        self.assertTrue(ok)
        self.assertEqual(host, "crawl-66-249-66-1.googlebot.com")
        self.assertIn(GOOD_IP, cache)
        self.assertFalse(sloth.verify_ip("not-an-ip", (".googlebot.com",), {}, Resolver())[0])

    def test_pick_needs_its_own_same_topic_verdict(self):
        self.write([line("/python-venv-guide/", 404)] * 3)
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(pick=1, match="same_area"), resolver=Resolver())
        s = res["suggestions"][0]
        self.assertNotEqual(s["kind"], "redirect")          # the model picked 1 but called it only same_area
        self.assertEqual(res["facts"]["redirects_waiting_for_approval"], 0)
        self.assertEqual(s["kind"], "hub")                  # section page offered as the weaker fallback
        self.assertEqual(s["target"], "/topics/python/")
        self.assertEqual([r["path"] for r in res["restore"]], ["/python-venv-guide/"])   # 3 hits, no equivalent
        caddy = next((Path(self.cfg["out_dir"]) / "reports").glob("*.caddy")).read_text()
        self.assertIn("# weaker, section page only: redir /python-venv-guide/ /topics/python/ permanent", caddy)

    def test_thinking_is_a_config_switch(self):
        self.write([line("/python-venv-guide/", 404)])
        llm = FakeLLM(pick=1)
        sloth.run(self.cfg, now=NOW, llm=llm, resolver=Resolver())
        self.assertEqual(llm.thinks, [False, False])        # default: no reasoning trace for the judge or the brief
        llm = FakeLLM(pick=1)
        sloth.run(dict(self.cfg, judge_think=True, out_dir=str(self.d / "out2")), now=NOW, llm=llm, resolver=Resolver())
        self.assertEqual(llm.thinks, [True, False])         # judge thinks when asked; the brief never does

    def test_backup_files_are_probes(self):
        self.assertEqual(sloth.classify_404("/config.json.save", set()), "probe")
        self.assertEqual(sloth.classify_404("/wp-login.php", set()), "probe")
        self.assertEqual(sloth.classify_404("/claude-code-skills/", set()), "page")

    def test_section_page_is_never_a_full_redirect(self):
        ans = {"pick": 1, "verdicts": [{"n": 1, "match": "same_topic"}]}
        kind, c = sloth.decide(ans, [{"path": "/topics/python/"}], "/topics/")
        self.assertEqual(kind, "hub")
        kind, c = sloth.decide(ans, [{"path": "/python-json-examples/"}], "/topics/")
        self.assertEqual(kind, "redirect")
        self.assertFalse(sloth.is_hub("/topics/", "/topics/"))     # the index itself is not a section page


if __name__ == "__main__":
    unittest.main()
