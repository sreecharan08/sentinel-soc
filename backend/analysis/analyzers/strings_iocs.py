"""StringsIocAnalyzer (source=strings). Stage 3 section 4.6. IOCs are extracted and only ever shown defanged."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from analysis.context import AnalysisContext, Analyzer, AnalyzerResult

from .code import dex_infos

ALLOWLIST_FILE = Path(__file__).resolve().parent.parent / "data" / "allowlists" / "domains.txt"
URL_RE = re.compile(r"https?://[\x21-\x7e]{4,200}")  # printable ASCII only; no quotes or angle brackets
URL_STOP = re.compile(r"[\"'<>\\]")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CAP = 500
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy")
DYNDNS = ("duckdns.org", "no-ip.org", "ddns.net", "dynu.com", "hopto.org", "serveo.net", "ngrok.io")
PASTE = ("pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "transfer.sh")
INTERESTING = ("/system/bin", "/system/xbin/su", "chmod", "pm install", "content://sms", "getprop")


def _allowlist() -> set[str]:
    return {line.strip().lower() for line in ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


def _allowed(host: str, allow: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allow)


def _kind(host: str) -> str | None:
    for group, label in ((SHORTENERS, "url shortener"), (DYNDNS, "dynamic DNS"), (PASTE, "paste host")):
        if any(host == d or host.endswith("." + d) for d in group):
            return label
    return None


class StringsIocAnalyzer(Analyzer):
    name = "strings"
    source = "strings"

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        strings: list[str] = []
        for info in dex_infos(ctx):
            strings.extend(s for s in info.strings if len(s) >= 6)
        manifest = ctx.cache.get("manifest_xml", b"").decode("utf-8", "replace")
        text_blob = "\n".join(strings) + "\n" + manifest

        allow = _allowlist()
        urls = []
        seen = set()
        for match in URL_RE.finditer(text_blob):
            url = URL_STOP.split(match.group(0))[0].rstrip(".,;)")
            # Templates such as "http://%s/launch-js-devtools" are format strings, not destinations.
            if len(url) < 12 or "%" in url:
                continue
            if url in seen:
                continue
            seen.add(url)
            host = (urlparse(url).hostname or "").lower()
            if host and not _allowed(host, allow):
                urls.append(url)

        # An IP only counts when an app actually uses it as a URL host; loose dotted numbers in data tables do not.
        url_hosts_text = " ".join(urls)
        ips = []
        for ip in set(IP_RE.findall(url_hosts_text)):
            try:
                if ipaddress.ip_address(ip).is_global:
                    ips.append(ip)
            except ValueError:
                continue

        hosts = sorted({(urlparse(u).hostname or "").lower() for u in urls} - {""})
        flagged = {}
        for host in hosts:
            kind = _kind(host)
            if kind:
                flagged[host] = kind
        interesting = sorted({s[:160] for s in strings if any(tok in s for tok in INTERESTING)})

        return AnalyzerResult({
            "urls": urls[:CAP], "url_count": len(urls),
            "domains": hosts[:CAP], "ips": sorted(ips)[:CAP],
            "flagged_hosts": flagged,
            "telegram_bot": "api.telegram.org/bot" in text_blob,
            "interesting": interesting[:50],
            "string_count": len(strings),
        })
