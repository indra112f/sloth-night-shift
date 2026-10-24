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
    """Bag-of-words vectors for embed; scripted answers for chat."""
    def __init__(self, brief="Googlebot fetched 2 pages; 1 lost page has a suggested redirect.", pick=1):
        self.brief, self.pick, self.calls, self.seconds = brief, pick, 0, 0.0
        self.vocab = {}

    def embed(self, texts):
        out = []
        for t in texts:
            v = [0.0] * 64
            for w in t.lower().replace("(", " ").replace(")", " ").split():
                v[self.vocab.setdefault(w, len(self.vocab) % 64)] += 1
            out.append(v)
        return out

    def chat_json(self, prompt, schema):
        self.calls += 1
        if "brief" in schema["properties"]:
            return {"brief": self.brief}
        return {"pick": self.pick, "reason": "same topic"}


class SlothTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "sitemap.xml").write_text(
            "<urlset>" + "".join(f"<url><loc>https://example.com{p}</loc></url>" for p in
                                 ["/", "/python-virtual-environment/", "/git-rebase-vs-merge/", "/cors-error/"]) + "</urlset>")
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
        self.assertEqual(f["sitemap_pages_never_fetched_by_googlebot"], 2)            # "/" and /cors-error/ (fake bot doesn't count)
        self.assertEqual(f["requests_read"], 3)

    def test_404_buckets_and_redirects(self):
        self.write([line("/wp-login.php", 404), line("/.env", 404), line("/assets/old.css", 404),
                    line("/cors-error", 404),                              # missing trailing slash
                    line("/python-venv-guide/", 404), line("/python-venv-guide/", 404),
                    line("/totally-unrelated-zebra/", 404)])
        llm = FakeLLM(pick=1)
        res = sloth.run(self.cfg, now=NOW, llm=llm, resolver=Resolver())
        f = res["facts"]
        self.assertEqual(f["attack_probe_404s"], 2)
        self.assertEqual(f["lost_page_urls"], 3)
        by = {s["path"]: s for s in res["suggestions"]}
        self.assertEqual(by["/cors-error"]["target"], "/cors-error/")
        self.assertEqual(by["/python-venv-guide/"]["target"], "/python-virtual-environment/")
        caddy = (Path(self.cfg["out_dir"]) / "reports").glob("*.caddy")
        text = next(caddy).read_text()
        self.assertIn("redir /python-venv-guide/ /python-virtual-environment/ permanent", text)
        self.assertTrue(text.startswith("# Suggested by sloth. Nothing here is applied automatically"))

    def test_model_pick_zero_means_no_redirect(self):
        self.write([line("/python-venv-guide/", 404)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(pick=0), resolver=Resolver())
        self.assertIsNone(res["suggestions"][0]["target"])
        self.assertEqual(res["facts"]["redirects_waiting_for_approval"], 0)

    def test_out_of_range_pick_is_ignored(self):
        self.write([line("/python-venv-guide/", 404)])
        res = sloth.run(self.cfg, now=NOW, llm=FakeLLM(pick=7), resolver=Resolver())
        self.assertIsNone(res["suggestions"][0]["target"])

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
        self.assertEqual(res["facts"]["sitemap_pages_never_fetched_by_googlebot"], 2)     # 4 pages, 2 fetched over two nights

    def test_dns_cache(self):
        cache = {}
        ok, host = sloth.verify_ip(GOOD_IP, (".googlebot.com",), cache, Resolver())
        self.assertTrue(ok)
        self.assertEqual(host, "crawl-66-249-66-1.googlebot.com")
        self.assertIn(GOOD_IP, cache)
        self.assertFalse(sloth.verify_ip("not-an-ip", (".googlebot.com",), {}, Resolver())[0])


if __name__ == "__main__":
    unittest.main()
