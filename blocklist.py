import re
from pathlib import Path

import aiohttp

# You can add more lists here as URLs (one domain per line).
SOURCES = [
    "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.txt",
]

BASE = Path(__file__).parent
CACHE = BASE / "blocklist_cache.txt"      # downloaded list (automatic)
CUSTOM = BASE / "custom_blocklist.txt"    # your own blocked domains
ALLOW = BASE / "allowlist.txt"            # exceptions for false positives

# also finds domains without "https://" (scammers often leave it out)
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


def _parse(text: str) -> set:
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith(("#", "!")):
            continue
        line = re.sub(r"^https?://", "", line)
        line = line.split("/")[0].split("?")[0].split("@")[-1]
        if "." in line:
            domains.add(line)
    return domains


def _append(path: Path, domain: str):
    with path.open("a", encoding="utf-8") as f:
        f.write(domain + "\n")


class Blocklist:
    def __init__(self):
        self.remote = set()
        self.custom = set()
        self.allow = set()
        self.reload_local()

    @staticmethod
    def _read(path: Path) -> set:
        return _parse(path.read_text(encoding="utf-8")) if path.exists() else set()

    def reload_local(self):
        self.remote = self._read(CACHE)
        self.custom = self._read(CUSTOM)
        self.allow = self._read(ALLOW)

    async def update(self) -> int:
        """Reloads all sources. Returns the number of domains."""
        new = set()
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url in SOURCES:
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            new |= _parse(await resp.text())
                        else:
                            print(f"[Blocklist] {url} -> HTTP {resp.status}")
                except Exception as e:
                    print(f"[Blocklist] Error for {url}: {e}")
        if new:  # only overwrite if the download worked
            self.remote = new
            CACHE.write_text("\n".join(sorted(new)), encoding="utf-8")
        return len(self.remote)

    def add_block(self, domain: str):
        domain = _parse(domain).pop() if _parse(domain) else None
        if domain:
            self.custom.add(domain)
            _append(CUSTOM, domain)
        return domain

    def add_allow(self, domain: str):
        domain = _parse(domain).pop() if _parse(domain) else None
        if domain:
            self.allow.add(domain)
            _append(ALLOW, domain)
        return domain

    def find(self, text: str):
        """Returns the blocked domain if the text contains one."""
        for d in DOMAIN_RE.findall(text.lower()):
            parts = d.split(".")
            # also checks parent domains: a.b.evil.com -> b.evil.com -> evil.com
            for i in range(len(parts) - 1):
                candidate = ".".join(parts[i:])
                if candidate in self.allow:
                    break
                if candidate in self.custom or candidate in self.remote:
                    return candidate
        return None

    def __len__(self):
        return len(self.remote) + len(self.custom)
