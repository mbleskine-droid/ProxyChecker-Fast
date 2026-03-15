#!/usr/bin/env python3
"""
Proxy Scraper, Checker & Anonymity Verifier v5.0
=================================================
Améliorations:
  1. Cache persistant des proxies morts/transparents pour les exclure
  2. Utilisation de proxies vérifiés pour accéder à l'API (fallback IP normale)
"""

from __future__ import annotations

import asyncio
import sys
import os
import time
import re
import random
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, Set, Tuple, List, FrozenSet
from enum import IntEnum
from collections import defaultdict
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import aiofiles

try:
    import orjson
    def json_dumps(obj): return orjson.dumps(obj, option=orjson.OPT_INDENT_2).decode()
    def json_loads(s): return orjson.loads(s) if isinstance(s, (bytes, str)) else s
    JSON_ENGINE = "orjson"
except ImportError:
    import json
    def json_dumps(obj): return json.dumps(obj, indent=2, ensure_ascii=False)
    def json_loads(s): return json.loads(s) if isinstance(s, str) else s
    JSON_ENGINE = "json"


# ══════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════

PROXY_SOURCES: Tuple[Tuple[str, str, str], ...] = (
    ("http",   "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",   "http"),
    ("socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
)

PROXYSCRAPE_API = "https://api.proxyscrape.com/v4/online_check"
HTTPBIN_URL     = "http://httpbin.org/get"

BATCH_SIZE         = 1000
CONCURRENT_BATCHES = 1
MAX_WORKERS_ANON   = 50
PROXY_TIMEOUT      = 6
LOOP_INTERVAL      = 120
API_DELAY          = 1.0

OUTPUT_DIR       = "output"
PERSISTENT_FILE  = os.path.join(OUTPUT_DIR, "VERIFIED_PROXIES.txt")
PERSISTENT_ELITE = os.path.join(OUTPUT_DIR, "VERIFIED_ELITE.txt")
PERSISTENT_JSON  = os.path.join(OUTPUT_DIR, "VERIFIED_DETAILED.json")

# ── Nouveaux fichiers pour le cache de rejet ──
REJECTED_CACHE_FILE = os.path.join(OUTPUT_DIR, "REJECTED_CACHE.json")
REJECTED_EXPIRY_HOURS = 6          # Durée avant qu'un proxy rejeté soit retesté
REJECTED_MAX_FAILURES = 3          # Nombre d'échecs avant exclusion longue durée
REJECTED_LONG_EXPIRY_HOURS = 48    # Durée d'exclusion après trop d'échecs

# ── Config proxy-through-proxy pour l'API ──
API_PROXY_ATTEMPTS  = 3            # Nombre de proxies à essayer pour l'API
API_PROXY_TIMEOUT   = 15           # Timeout quand on passe par un proxy
USE_PROXY_FOR_API   = True         # Activer/désactiver cette fonctionnalité

PROXYSCRAPE_HEADERS: Dict[str, str] = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
    "Origin": "https://proxyscrape.com",
    "Referer": "https://proxyscrape.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Content-Type": "application/x-www-form-urlencoded",
}

HTTPBIN_HEADERS: Dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,*/*;q=0.8",
}


# ══════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════

class AnonymityLevel(IntEnum):
    UNKNOWN     = 0
    TRANSPARENT = 1
    ANONYMOUS   = 2
    ELITE       = 3


@dataclass(slots=True)
class Proxy:
    ip: str
    port: int
    source: str = "http"
    alive: bool = False
    country: str = ""
    proxy_type: str = ""
    anonymity: AnonymityLevel = AnonymityLevel.UNKNOWN
    response_time_ms: float = 0.0
    leaked_headers: Tuple[str, ...] = ()
    httpbin_origin: str = ""
    pass1_alive: bool = False
    pass2_alive: bool = False

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    def __hash__(self) -> int:
        return hash((self.ip, self.port))

    def __eq__(self, other) -> bool:
        return isinstance(other, Proxy) and self.ip == other.ip and self.port == other.port


PROXY_HEADERS_LOWER: FrozenSet[str] = frozenset({
    "x-forwarded-for", "x-real-ip", "via", "forwarded",
    "x-forwarded", "forwarded-for", "x-forwarded-proto",
    "x-forwarded-host", "x-originating-ip", "x-remote-ip",
    "x-remote-addr", "x-proxy-id", "proxy-connection",
    "client-ip", "true-client-ip", "x-client-ip",
    "cf-connecting-ip", "x-bluecoat-via", "x-proxy-connection",
})

PROXY_HEADERS_DISPLAY: Dict[str, str] = {h.lower(): h for h in [
    "X-Forwarded-For", "X-Real-Ip", "Via", "Forwarded", "X-Forwarded",
    "Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
    "X-Originating-Ip", "X-Remote-Ip", "X-Remote-Addr", "X-Proxy-Id",
    "Proxy-Connection", "Client-Ip", "True-Client-Ip", "X-Client-Ip",
    "Cf-Connecting-Ip", "X-Bluecoat-Via", "X-Proxy-Connection",
]}


# ══════════════════════════════════════════════
#  TERMINAL
# ══════════════════════════════════════════════

class C:
    R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
    B  = "\033[94m"; M  = "\033[95m"; CY = "\033[96m"
    W  = "\033[97m"; BD = "\033[1m";  DM = "\033[2m"; X = "\033[0m"


def banner():
    print(f"""{C.CY}{C.BD}
    ╔════════════════════════════════════════════════════════════════╗
    ║   🔒  PROXY SCRAPER v5.0 — Cache + Proxy-through-Proxy  🔒   ║
    ║                                                                ║
    ║   ⚡ Cache rejet persistant · Exclusion auto dead/transparent  ║
    ║   ⚡ API via proxy vérifié · Fallback IP normale              ║
    ║   ⚡ {JSON_ENGINE:>6} engine · Double-check · Anonymity test         ║
    ╚════════════════════════════════════════════════════════════════╝
    {C.X}""")


def section(step: int, title: str):
    print(f"\n{C.BD}{C.CY}{'━'*70}\n  ÉTAPE {step} │ {title}\n{'━'*70}{C.X}")


# ══════════════════════════════════════════════
#  REJECTED PROXY CACHE (FEATURE 1)
# ══════════════════════════════════════════════

class RejectedCache:
    """
    Cache persistant des proxies rejetés (dead, transparent, unknown).
    Chaque entrée stocke:
      - reason: pourquoi le proxy a été rejeté
      - fail_count: nombre de fois qu'il a échoué
      - first_seen: première détection
      - last_seen: dernière détection
      - expires: quand il peut être retesté
    """

    def __init__(self, filepath: str = REJECTED_CACHE_FILE):
        self.filepath = filepath
        self.entries: Dict[str, Dict] = {}
        self._dirty = False
        self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            return
        try:
            with open(self.filepath, "rb") as f:
                raw = json_loads(f.read())
            if isinstance(raw, dict):
                self.entries = raw
            elif isinstance(raw, list):
                # Migration depuis ancien format
                for entry in raw:
                    addr = entry.get("proxy", "")
                    if addr:
                        self.entries[addr] = entry
            self._purge_expired()
            print(f"  {C.DM}📋 Cache rejet chargé: {len(self.entries)} proxies blacklistés{C.X}")
        except Exception as e:
            print(f"  {C.R}⚠ Erreur chargement cache rejet: {e}{C.X}")
            self.entries = {}

    def _purge_expired(self):
        """Supprime les entrées expirées"""
        now = datetime.now()
        to_remove = []
        for addr, entry in self.entries.items():
            expires_str = entry.get("expires", "")
            if expires_str:
                try:
                    expires = datetime.fromisoformat(expires_str)
                    if now > expires:
                        to_remove.append(addr)
                except (ValueError, TypeError):
                    to_remove.append(addr)

        for addr in to_remove:
            del self.entries[addr]

        if to_remove:
            self._dirty = True
            print(f"  {C.DM}  ♻ {len(to_remove)} entrées expirées purgées{C.X}")

    def reject(self, proxy: Proxy, reason: str):
        """Ajoute ou met à jour un proxy dans le cache de rejet"""
        addr = proxy.address
        now = datetime.now()

        if addr in self.entries:
            entry = self.entries[addr]
            entry["fail_count"] = entry.get("fail_count", 0) + 1
            entry["last_seen"] = now.isoformat()
            entry["reason"] = reason

            # Plus d'échecs = exclusion plus longue
            if entry["fail_count"] >= REJECTED_MAX_FAILURES:
                expiry = now + timedelta(hours=REJECTED_LONG_EXPIRY_HOURS)
                entry["expires"] = expiry.isoformat()
                entry["long_ban"] = True
            else:
                expiry = now + timedelta(hours=REJECTED_EXPIRY_HOURS)
                entry["expires"] = expiry.isoformat()
        else:
            expiry = now + timedelta(hours=REJECTED_EXPIRY_HOURS)
            self.entries[addr] = {
                "proxy": addr,
                "ip": proxy.ip,
                "port": proxy.port,
                "reason": reason,
                "fail_count": 1,
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "expires": expiry.isoformat(),
                "long_ban": False,
            }

        self._dirty = True

    def reject_batch(self, proxies: List[Proxy], reason: str):
        """Rejette un lot de proxies d'un coup"""
        for proxy in proxies:
            self.reject(proxy, reason)

    def is_rejected(self, addr: str) -> bool:
        """Vérifie si un proxy est actuellement blacklisté"""
        if addr not in self.entries:
            return False

        entry = self.entries[addr]
        expires_str = entry.get("expires", "")

        if not expires_str:
            return True

        try:
            expires = datetime.fromisoformat(expires_str)
            if datetime.now() > expires:
                # Expiré, on le retire
                del self.entries[addr]
                self._dirty = True
                return False
            return True
        except (ValueError, TypeError):
            return True

    def filter_proxies(self, proxies: List[Proxy]) -> Tuple[List[Proxy], int]:
        """
        Filtre les proxies en retirant ceux qui sont blacklistés.
        Retourne (proxies_filtrés, nombre_exclus)
        """
        filtered = []
        excluded = 0

        for proxy in proxies:
            if self.is_rejected(proxy.address):
                excluded += 1
            else:
                filtered.append(proxy)

        return filtered, excluded

    def get_stats(self) -> Dict[str, int]:
        """Statistiques du cache"""
        stats = defaultdict(int)
        for entry in self.entries.values():
            reason = entry.get("reason", "unknown")
            stats[reason] += 1
            if entry.get("long_ban"):
                stats["long_ban"] += 1
        stats["total"] = len(self.entries)
        return dict(stats)

    async def save_async(self):
        if not self._dirty:
            return

        os.makedirs(OUTPUT_DIR, exist_ok=True)

        try:
            async with aiofiles.open(self.filepath, "w", encoding="utf-8") as f:
                await f.write(json_dumps(self.entries))
            self._dirty = False
        except Exception as e:
            print(f"  {C.R}⚠ Erreur sauvegarde cache rejet: {e}{C.X}")

    def save_sync(self):
        if not self._dirty:
            return
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(json_dumps(self.entries))
            self._dirty = False
        except Exception as e:
            print(f"  {C.R}⚠ Erreur sauvegarde cache rejet: {e}{C.X}")


# ══════════════════════════════════════════════
#  PERSISTENT STORAGE (proxies vérifiés)
# ══════════════════════════════════════════════

class ProxyStore:
    __slots__ = ('verified', '_dirty')

    def __init__(self):
        self.verified: Dict[str, Dict] = {}
        self._dirty = False
        self._load()

    def _load(self):
        if os.path.exists(PERSISTENT_JSON):
            try:
                with open(PERSISTENT_JSON, "rb") as f:
                    data = json_loads(f.read())
                self.verified = {entry["proxy"]: entry for entry in data}
                print(f"  {C.DM}Chargé {len(self.verified)} proxies vérifiés depuis le cache{C.X}")
            except Exception:
                pass

    def add(self, proxy: Proxy):
        self.verified[proxy.address] = {
            "proxy": proxy.address,
            "ip": proxy.ip,
            "port": proxy.port,
            "source": proxy.source,
            "anonymity": AnonymityLevel(proxy.anonymity).name.lower(),
            "country": proxy.country,
            "type": proxy.proxy_type,
            "response_time_ms": proxy.response_time_ms,
            "httpbin_origin": proxy.httpbin_origin,
            "leaked_headers": list(proxy.leaked_headers),
            "last_checked": datetime.now().isoformat(),
        }
        self._dirty = True

    def remove(self, address: str):
        """Retire un proxy du store"""
        if address in self.verified:
            del self.verified[address]
            self._dirty = True

    def get_random_elite_proxies(self, count: int = 3) -> List[Dict]:
        """
        Récupère N proxies élites aléatoires du pool vérifié.
        Priorise les plus rapides et récents.
        """
        elites = [
            e for e in self.verified.values()
            if e.get("anonymity") == "elite"
        ]

        if not elites:
            # Fallback sur anonymous
            elites = [
                e for e in self.verified.values()
                if e.get("anonymity") in ("elite", "anonymous")
            ]

        if not elites:
            return []

        # Trier par temps de réponse (les plus rapides d'abord)
        elites.sort(key=lambda e: e.get("response_time_ms") or 99999)

        # Prendre dans le top 50% les plus rapides pour augmenter les chances
        top_half = elites[:max(len(elites) // 2, min(count * 2, len(elites)))]

        return random.sample(top_half, min(count, len(top_half)))

    async def save_async(self):
        if not self._dirty:
            return

        os.makedirs(OUTPUT_DIR, exist_ok=True)

        entries = sorted(
            self.verified.values(),
            key=lambda e: (
                0 if e["anonymity"] == "elite" else 1,
                e.get("response_time_ms") or 99999,
            ),
        )

        async with aiofiles.open(PERSISTENT_JSON, "w", encoding="utf-8") as f:
            await f.write(json_dumps(entries))

        async with aiofiles.open(PERSISTENT_FILE, "w", encoding="utf-8") as f:
            await f.write('\n'.join(e['proxy'] for e in entries) + '\n')

        async with aiofiles.open(PERSISTENT_ELITE, "w", encoding="utf-8") as f:
            elite_list = [e['proxy'] for e in entries if e["anonymity"] == "elite"]
            await f.write('\n'.join(elite_list) + '\n' if elite_list else '')

        self._dirty = False
        print(f"  {C.G}💾 Sauvegardé: {len(entries)} proxies vérifiés{C.X}")

    @property
    def count(self) -> int:
        return len(self.verified)

    @property
    def elite_count(self) -> int:
        return sum(1 for e in self.verified.values() if e["anonymity"] == "elite")

    @property
    def anon_count(self) -> int:
        return sum(1 for e in self.verified.values() if e["anonymity"] == "anonymous")


# ══════════════════════════════════════════════
#  PROXY-THROUGH-PROXY API CALLER (FEATURE 2)
# ══════════════════════════════════════════════

class ProxiedAPICaller:
    """
    Essaie d'appeler l'API ProxyScrape via des proxies vérifiés.
    Fallback sur IP normale si aucun proxy ne fonctionne.
    """

    def __init__(self, store: ProxyStore):
        self.store = store
        self.last_working_proxy: Optional[str] = None
        self._failed_api_proxies: Set[str] = set()

    def _build_proxy_dict(self, proxy_entry: Dict) -> Dict[str, str]:
        """Construit le dict proxies pour requests"""
        addr = proxy_entry["proxy"]
        ptype = proxy_entry.get("type", "http").lower()

        if ptype in ("socks4", "socks5"):
            scheme = ptype
        else:
            scheme = "http"

        url = f"{scheme}://{addr}"
        return {"http": url, "https": url}

    def call_api_with_proxy(
        self,
        proxy_entry: Dict,
        files: List,
    ) -> Optional[object]:
        """Tente un appel API via un proxy spécifique"""
        import requests

        proxy_addr = proxy_entry["proxy"]
        proxy_dict = self._build_proxy_dict(proxy_entry)

        try:
            resp = requests.post(
                PROXYSCRAPE_API,
                files=files,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Origin": "https://proxyscrape.com",
                    "Referer": "https://proxyscrape.com/",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
                                  "Gecko/20100101 Firefox/128.0",
                },
                proxies=proxy_dict,
                timeout=API_PROXY_TIMEOUT,
            )

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    self.last_working_proxy = proxy_addr
                    return data
                else:
                    return None
            else:
                return None

        except Exception:
            self._failed_api_proxies.add(proxy_addr)
            return None

    def call_api_direct(self, files: List) -> Optional[object]:
        """Appel API direct (sans proxy)"""
        import requests

        try:
            resp = requests.post(
                PROXYSCRAPE_API,
                files=files,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Origin": "https://proxyscrape.com",
                    "Referer": "https://proxyscrape.com/",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
                                  "Gecko/20100101 Firefox/128.0",
                },
                timeout=120,
            )

            if resp.status_code == 200:
                return resp.json()
            return None

        except Exception:
            return None

    def call_api(self, files: List, batch_label: str = "") -> Tuple[Optional[object], str]:
        """
        Stratégie d'appel:
          1. Essayer via 3 proxies élites aléatoires du pool
          2. Fallback sur IP normale

        Returns: (data, method_used)
        """
        method_used = "direct"

        if USE_PROXY_FOR_API and self.store.count > 0:
            candidates = self.store.get_random_elite_proxies(API_PROXY_ATTEMPTS)

            # Filtrer ceux qui ont déjà échoué pour l'API
            candidates = [
                c for c in candidates
                if c["proxy"] not in self._failed_api_proxies
            ]

            if candidates:
                for i, candidate in enumerate(candidates):
                    addr = candidate["proxy"]
                    data = self.call_api_with_proxy(candidate, files)

                    if data is not None:
                        anon = candidate.get("anonymity", "?")
                        print(
                            f"    {C.G}🔀 API via proxy {addr} "
                            f"({anon}){C.X}"
                        )
                        return data, f"proxy:{addr}"

                # Tous les proxies ont échoué
                print(f"    {C.Y}⚠ {len(candidates)} proxies testés pour l'API → échec, fallback direct{C.X}")

        # Fallback direct
        data = self.call_api_direct(files)
        return data, "direct"


# ══════════════════════════════════════════════
#  ÉTAPE 1 : FETCH ASYNC
# ══════════════════════════════════════════════

PROXY_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$')


async def fetch_source(
    session: aiohttp.ClientSession,
    name: str,
    url: str,
    seen: Set[str],
) -> List[Proxy]:
    proxies = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                print(f"  {C.R}✗ {name.upper()}: HTTP {resp.status}{C.X}")
                return proxies

            text = await resp.text()

            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = PROXY_PATTERN.match(line)
                if match:
                    ip, port = match.groups()
                    addr = f"{ip}:{port}"
                    if addr not in seen:
                        seen.add(addr)
                        proxies.append(Proxy(ip=ip, port=int(port), source=name))

            print(f"  {C.G}✓ {name.upper():>6}: {len(proxies):>5} proxies{C.X}")

    except Exception as e:
        print(f"  {C.R}✗ {name.upper()}: {e}{C.X}")

    return proxies


async def step1_fetch(rejected_cache: RejectedCache) -> List[Proxy]:
    section(1, "Téléchargement async + filtrage cache rejet")

    seen: Set[str] = set()
    all_proxies: List[Proxy] = []

    connector = aiohttp.TCPConnector(limit=30, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, name, url, seen) for name, url, _ in PROXY_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_proxies.extend(result)

    total_fetched = len(all_proxies)
    print(f"\n  {C.BD}Total brut: {total_fetched} proxies uniques{C.X}")

    # ── Filtrage via le cache de rejet ──
    filtered, excluded = rejected_cache.filter_proxies(all_proxies)

    if excluded > 0:
        stats = rejected_cache.get_stats()
        print(f"\n  {C.Y}🚫 Exclus par le cache de rejet: {excluded} proxies{C.X}")
        for reason, count in sorted(stats.items()):
            if reason not in ("total", "long_ban"):
                print(f"     {C.DM}  {reason}: {count}{C.X}")
        if stats.get("long_ban", 0):
            print(f"     {C.R}  dont {stats['long_ban']} en ban longue durée{C.X}")

    print(f"  {C.G}✓ Restant après filtrage: {len(filtered)} proxies à tester{C.X}")

    return filtered


# ══════════════════════════════════════════════
#  ÉTAPE 2 : PROXYSCRAPE DOUBLE CHECK
# ══════════════════════════════════════════════

def check_batch_sync(
    batch: List[Proxy],
    batch_num: int,
    total_batches: int,
    start_idx: int,
    pass_label: str,
    api_caller: Optional[ProxiedAPICaller] = None,
) -> Tuple[int, int, List[Proxy], List[Proxy]]:
    """
    Version synchrone avec support proxy-through-proxy.
    Retourne: (alive_count, dead_count, alive_proxies, dead_proxies)
    """
    alive_count, dead_count = 0, 0
    alive_proxies = []
    dead_proxies = []

    # Construire le payload
    files = []
    for i, proxy in enumerate(batch):
        idx = start_idx + i
        value = f"{proxy.ip}:{proxy.port}-{idx}"
        files.append(("ip_addr[]", (None, value)))

    data = None
    method = "direct"

    try:
        if api_caller:
            data, method = api_caller.call_api(files, f"{pass_label}-B{batch_num}")
        else:
            import requests
            resp = requests.post(
                PROXYSCRAPE_API,
                files=files,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Origin": "https://proxyscrape.com",
                    "Referer": "https://proxyscrape.com/",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
                                  "Gecko/20100101 Firefox/128.0",
                },
                timeout=120,
            )
            if resp.status_code == 200:
                data = resp.json()

        if data and isinstance(data, list):
            proxy_map = {(p.ip, p.port): p for p in batch}
            seen_keys = set()

            for entry in data:
                ip = entry.get("ip", "")
                port_val = entry.get("port")

                if port_val is not None:
                    try:
                        port = int(port_val)
                    except (ValueError, TypeError):
                        continue
                else:
                    continue

                key = (ip, port)
                seen_keys.add(key)

                if key in proxy_map:
                    p = proxy_map[key]
                    working = entry.get("working", False)

                    if working is True:
                        p.alive = True
                        p.country = (
                            entry.get("country")
                            or entry.get("country_code")
                            or ""
                        )
                        p.proxy_type = (
                            entry.get("type")
                            or entry.get("protocol")
                            or p.source
                        )
                        alive_count += 1
                        alive_proxies.append(p)
                    else:
                        p.alive = False
                        dead_count += 1
                        dead_proxies.append(p)

            # Proxies non mentionnés dans la réponse = dead
            for key, p in proxy_map.items():
                if key not in seen_keys:
                    dead_count += 1
                    dead_proxies.append(p)

            via = f" [{C.B}via {method}{C.X}]" if method != "direct" else ""
            status = f"{C.G}{alive_count:>3}✓{C.X} {C.R}{dead_count:>3}✗{C.X}{via}"

        else:
            status = f"{C.Y}Pas de données{C.X}"
            # Tous sont considérés comme non testés (pas dead)

    except Exception as e:
        status = f"{C.R}{str(e)[:40]}{C.X}"

    print(f"  [{pass_label}] Batch {batch_num:>2}/{total_batches} │ {status}")

    return alive_count, dead_count, alive_proxies, dead_proxies


async def proxyscrape_batch_async(
    proxies: List[Proxy],
    pass_label: str,
    api_caller: Optional[ProxiedAPICaller] = None,
) -> Tuple[List[Proxy], List[Proxy]]:
    """
    Execute les checks en parallèle.
    Retourne: (alive_list, dead_list)
    """
    total = len(proxies)
    batches = [proxies[i : i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
    total_batches = len(batches)

    total_alive, total_dead = 0, 0
    all_alive: List[Proxy] = []
    all_dead: List[Proxy] = []

    loop = asyncio.get_event_loop()

    for group_start in range(0, total_batches, CONCURRENT_BATCHES):
        group_end = min(group_start + CONCURRENT_BATCHES, total_batches)

        with ThreadPoolExecutor(max_workers=CONCURRENT_BATCHES) as executor:
            tasks = []
            for i in range(group_start, group_end):
                batch = batches[i]
                start_idx = i * BATCH_SIZE
                task = loop.run_in_executor(
                    executor,
                    check_batch_sync,
                    batch,
                    i + 1,
                    total_batches,
                    start_idx,
                    pass_label,
                    api_caller,
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, tuple):
                    alive_c, dead_c, alive_list, dead_list = result
                    total_alive += alive_c
                    total_dead += dead_c
                    all_alive.extend(alive_list)
                    all_dead.extend(dead_list)
                elif isinstance(result, Exception):
                    print(f"  {C.R}Erreur batch: {result}{C.X}")

        if group_end < total_batches:
            await asyncio.sleep(API_DELAY)

    print(
        f"\n  {C.BD}[{pass_label}] Total: "
        f"{C.G}{total_alive} alive{C.X} / {C.R}{total_dead} dead{C.X}"
    )

    return all_alive, all_dead


async def step2_double_check(
    proxies: List[Proxy],
    rejected_cache: RejectedCache,
    api_caller: Optional[ProxiedAPICaller] = None,
) -> Tuple[List[Proxy], int, int]:
    """
    Retourne: (confirmed_proxies, pass1_count, pass2_count)
    """
    section(2, f"ProxyScrape Double Check ({len(proxies)} proxies)")
    print(f"  {C.DM}API: {PROXYSCRAPE_API}{C.X}")
    print(f"  {C.DM}Batch size: {BATCH_SIZE}, Concurrent: {CONCURRENT_BATCHES}{C.X}")

    if api_caller and api_caller.store.count > 0:
        print(f"  {C.B}🔀 Mode proxy-through-proxy activé "
              f"(pool: {api_caller.store.elite_count} elite){C.X}")

    # ── PASS 1 ──
    print(f"\n  {C.M}{C.BD}═══ PASS 1: Élimination rapide ═══{C.X}\n")
    pass1_alive, pass1_dead = await proxyscrape_batch_async(
        proxies, "P1", api_caller
    )

    # Enregistrer les morts du PASS 1
    if pass1_dead:
        rejected_cache.reject_batch(pass1_dead, "dead_pass1")
        print(f"  {C.DM}📋 {len(pass1_dead)} proxies dead ajoutés au cache de rejet{C.X}")

    if not pass1_alive:
        print(f"\n  {C.R}Aucun survivant PASS 1{C.X}")
        await rejected_cache.save_async()
        return [], 0, 0

    pass1_count = len(pass1_alive)

    # Marquer pass1
    pass1_set = {(p.ip, p.port) for p in pass1_alive}
    for p in proxies:
        if (p.ip, p.port) in pass1_set:
            p.pass1_alive = True

    print(f"\n  {C.G}Survivants PASS 1: {pass1_count}{C.X}")
    for p in pass1_alive[:5]:
        print(
            f"    {C.G}✓{C.X} {p.address:<22} "
            f"{p.country or '??':>4} {p.proxy_type or p.source}"
        )
    if len(pass1_alive) > 5:
        print(f"    {C.DM}... et {len(pass1_alive) - 5} autres{C.X}")

    # Reset alive pour pass 2
    for p in pass1_alive:
        p.alive = False

    # ── PASS 2 ──
    print(f"\n  {C.M}{C.BD}═══ PASS 2: Confirmation ({pass1_count} survivants) ═══{C.X}")
    print(f"  {C.DM}Pause 3s avant PASS 2...{C.X}")
    await asyncio.sleep(3)
    print()

    pass2_alive, pass2_dead = await proxyscrape_batch_async(
        pass1_alive, "P2", api_caller
    )

    # Enregistrer les morts du PASS 2 (ils étaient vivants au P1 mais morts au P2)
    if pass2_dead:
        rejected_cache.reject_batch(pass2_dead, "dead_pass2")
        print(f"  {C.DM}📋 {len(pass2_dead)} proxies instables ajoutés au cache{C.X}")

    # Marquer pass2
    for p in pass2_alive:
        p.pass2_alive = True

    pass2_count = len(pass2_alive)
    eliminated = pass1_count - pass2_count

    print(
        f"\n  {C.BD}Pipeline: {len(proxies)} → {pass1_count} → "
        f"{C.G}{pass2_count} confirmés{C.X}"
    )
    if eliminated > 0:
        print(f"  {C.Y}({eliminated} éliminés entre P1 et P2){C.X}")

    await rejected_cache.save_async()

    return pass2_alive, pass1_count, pass2_count


# ══════════════════════════════════════════════
#  ÉTAPE 3 : ANONYMITY CHECK
# ══════════════════════════════════════════════

@lru_cache(maxsize=1)
def get_real_ip() -> str:
    import requests
    services = [
        ("https://api.ipify.org?format=json", lambda r: r.json()["ip"]),
        ("https://ifconfig.me/ip",            lambda r: r.text.strip()),
        ("http://httpbin.org/ip",             lambda r: r.json()["origin"].split(",")[0].strip()),
    ]
    for url, parser in services:
        try:
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200:
                return parser(resp)
        except Exception:
            continue
    return ""


def test_proxy_anonymity(proxy: Proxy, real_ip: str) -> Proxy:
    import requests

    scheme = proxy.source
    proxy_dict = {
        "http":  f"{scheme}://{proxy.address}",
        "https": f"{scheme}://{proxy.address}",
    }

    try:
        start = time.perf_counter()
        resp = requests.get(
            HTTPBIN_URL,
            proxies=proxy_dict,
            timeout=PROXY_TIMEOUT,
            headers=HTTPBIN_HEADERS,
        )
        elapsed = (time.perf_counter() - start) * 1000
        proxy.response_time_ms = round(elapsed, 1)

        if resp.status_code != 200:
            proxy.anonymity = AnonymityLevel.UNKNOWN
            return proxy

        data = resp.json()
        headers_resp = data.get("headers", {})
        origin = data.get("origin", "")
        proxy.httpbin_origin = origin

        headers_lower = {k.lower(): v for k, v in headers_resp.items()}

        ip_leaked = real_ip and real_ip in origin
        proxy_detected = False
        leaked = []

        for hl in PROXY_HEADERS_LOWER:
            if hl in headers_lower:
                value = headers_lower[hl]
                leaked.append(f"{PROXY_HEADERS_DISPLAY.get(hl, hl)}: {value}")
                if real_ip and real_ip in str(value):
                    ip_leaked = True
                else:
                    proxy_detected = True

        proxy.leaked_headers = tuple(leaked)

        if ip_leaked:
            proxy.anonymity = AnonymityLevel.TRANSPARENT
        elif proxy_detected:
            proxy.anonymity = AnonymityLevel.ANONYMOUS
        else:
            proxy.anonymity = AnonymityLevel.ELITE

    except Exception:
        proxy.alive = False
        proxy.anonymity = AnonymityLevel.UNKNOWN

    return proxy


async def step3_anonymity(
    proxies: List[Proxy],
    rejected_cache: RejectedCache,
) -> List[Proxy]:
    section(3, f"Test d'anonymat ({len(proxies)} proxies, {MAX_WORKERS_ANON} workers)")

    print(f"  {C.CY}🔍 Détection de votre IP...{C.X}")
    real_ip = get_real_ip()

    if not real_ip:
        print(f"  {C.R}✗ Impossible de détecter votre IP!{C.X}")
        return []

    print(f"  {C.Y}Votre IP: {real_ip}{C.X}\n")

    loop = asyncio.get_event_loop()
    results: List[Proxy] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_ANON) as executor:
        tasks = [
            loop.run_in_executor(executor, test_proxy_anonymity, p, real_ip)
            for p in proxies
        ]

        completed = 0
        total = len(tasks)

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            if result.anonymity == AnonymityLevel.ELITE:
                icon = f"{C.G}★ ELITE{C.X}"
            elif result.anonymity == AnonymityLevel.ANONYMOUS:
                icon = f"{C.Y}● ANON {C.X}"
            elif result.anonymity == AnonymityLevel.TRANSPARENT:
                icon = f"{C.R}✗ TRANS{C.X}"
            else:
                icon = f"{C.DM}? DEAD {C.X}"

            speed = (
                f"{result.response_time_ms:.0f}ms"
                if result.response_time_ms
                else "fail"
            )
            print(f"  {icon} {result.address:<22} {speed:>7} [{completed}/{total}]")

            results.append(result)

    # ── Enregistrer les transparents et dead dans le cache de rejet ──
    transparent_proxies = [
        p for p in results if p.anonymity == AnonymityLevel.TRANSPARENT
    ]
    dead_proxies = [
        p for p in results if p.anonymity == AnonymityLevel.UNKNOWN
    ]

    if transparent_proxies:
        rejected_cache.reject_batch(transparent_proxies, "transparent")
        print(
            f"\n  {C.R}📋 {len(transparent_proxies)} proxies transparents "
            f"→ cache de rejet{C.X}"
        )

    if dead_proxies:
        rejected_cache.reject_batch(dead_proxies, "dead_anonymity")
        print(
            f"  {C.DM}📋 {len(dead_proxies)} proxies dead (anonymat) "
            f"→ cache de rejet{C.X}"
        )

    await rejected_cache.save_async()

    # Stats
    by_level = defaultdict(list)
    for p in results:
        by_level[p.anonymity].append(p)

    print(f"\n  {'─' * 50}")
    print(f"  {C.G}★ Elite      : {len(by_level[AnonymityLevel.ELITE])}{C.X}")
    print(f"  {C.Y}● Anonymous  : {len(by_level[AnonymityLevel.ANONYMOUS])}{C.X}")
    print(f"  {C.R}✗ Transparent: {len(by_level[AnonymityLevel.TRANSPARENT])}{C.X}")
    print(f"  {C.DM}? Dead/Unknown: {len(by_level[AnonymityLevel.UNKNOWN])}{C.X}")

    final = by_level[AnonymityLevel.ELITE] + by_level[AnonymityLevel.ANONYMOUS]
    final.sort(
        key=lambda p: (
            0 if p.anonymity == AnonymityLevel.ELITE else 1,
            p.response_time_ms or 99999,
        )
    )

    return final


# ══════════════════════════════════════════════
#  RÉSUMÉ
# ══════════════════════════════════════════════

def print_summary(
    store: ProxyStore,
    rejected_cache: RejectedCache,
    new_proxies: List[Proxy],
    iteration: int,
    total_fetched: int,
    excluded_by_cache: int,
    pass1_count: int,
    pass2_count: int,
):
    now = datetime.now().strftime("%H:%M:%S")

    print(f"\n{C.BD}{C.CY}{'━' * 70}")
    print(f"  RÉSUMÉ │ Itération #{iteration} à {now}")
    print(f"{'━' * 70}{C.X}")

    print(f"\n  {C.BD}Pipeline cette itération:{C.X}")
    print(f"  {C.DM}  Téléchargés       : {total_fetched}{C.X}")
    if excluded_by_cache > 0:
        print(f"  {C.R}  Exclus (cache)    : -{excluded_by_cache}{C.X}")
        print(
            f"  {C.DM}  Envoyés au test   : "
            f"{total_fetched - excluded_by_cache}{C.X}"
        )
    print(f"  {C.Y}  Après PASS 1      : {pass1_count}{C.X}")
    print(f"  {C.CY}  Après PASS 2      : {pass2_count}{C.X}")
    print(f"  {C.G}  Après anonymat    : {len(new_proxies)}{C.X}")

    if new_proxies:
        print(f"\n  {C.BD}Top 10 proxies vérifiés:{C.X}")
        for p in new_proxies[:10]:
            anon = (
                f"{C.G}★ ELITE{C.X}"
                if p.anonymity == AnonymityLevel.ELITE
                else f"{C.Y}● ANON{C.X}"
            )
            speed = (
                f"{p.response_time_ms:.0f}ms"
                if p.response_time_ms
                else "N/A"
            )
            print(f"    {p.address:<22} {anon} {speed:>8} {p.country or '??'}")

    # Stats du cache de rejet
    rej_stats = rejected_cache.get_stats()
    if rej_stats.get("total", 0) > 0:
        print(f"\n  {C.BD}📋 Cache de rejet:{C.X}")
        print(f"     Total blacklistés : {rej_stats['total']}")
        for reason in ("dead_pass1", "dead_pass2", "transparent", "dead_anonymity"):
            if rej_stats.get(reason, 0) > 0:
                print(f"     {reason:<18}: {rej_stats[reason]}")
        if rej_stats.get("long_ban", 0):
            print(f"     {C.R}Long ban         : {rej_stats['long_ban']}{C.X}")

    print(f"\n  {'═' * 50}")
    print(f"  {C.BD}{C.G}📊 TOTAL ACCUMULÉ: {store.count} proxies vérifiés{C.X}")
    print(f"     {C.G}★ {store.elite_count} Elite{C.X}")
    print(f"     {C.Y}● {store.anon_count} Anonymous{C.X}")

    print(f"\n  {C.BD}Fichiers:{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_FILE}{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_ELITE}{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_JSON}{C.X}")
    print(f"    {C.B}📄 {REJECTED_CACHE_FILE}{C.X}")


# ══════════════════════════════════════════════
#  ITÉRATION PRINCIPALE
# ══════════════════════════════════════════════

async def run_iteration(
    store: ProxyStore,
    rejected_cache: RejectedCache,
    api_caller: ProxiedAPICaller,
    iteration: int,
) -> List[Proxy]:
    now = datetime.now().strftime("%H:%M:%S")

    print(f"\n\n{C.BD}{C.M}{'▓' * 70}")
    print(
        f"  ITÉRATION #{iteration} │ {now} │ "
        f"Accumulé: {store.count} │ Rejetés: {len(rejected_cache.entries)}"
    )
    print(f"{'▓' * 70}{C.X}")

    # Étape 1 (avec filtrage cache)
    all_proxies = await step1_fetch(rejected_cache)
    if not all_proxies:
        return []

    # Calculer combien ont été exclus pour le résumé
    # (on recalcule vite fait)
    total_fetched_approx = len(all_proxies)  # Après filtrage
    # Pour avoir le vrai total, on stocke avant filtrage
    # Note: le vrai total est loggé dans step1_fetch

    # Étape 2
    confirmed, pass1_count, pass2_count = await step2_double_check(
        all_proxies, rejected_cache, api_caller
    )

    if not confirmed:
        rej_stats = rejected_cache.get_stats()
        print_summary(
            store, rejected_cache, [], iteration,
            total_fetched_approx, 0, pass1_count, 0,
        )
        return []

    # Installer PySocks si nécessaire
    has_socks = any(p.source in ("socks4", "socks5") for p in confirmed)
    if has_socks:
        try:
            import socks
        except ImportError:
            print(f"\n  {C.Y}⚠ Installation de PySocks...{C.X}")
            os.system(f"{sys.executable} -m pip install PySocks -q")

    # Étape 3 (avec enregistrement transparents/dead)
    final = await step3_anonymity(confirmed, rejected_cache)

    # Mise à jour store
    for p in final:
        store.add(p)

    await store.save_async()
    await rejected_cache.save_async()

    print_summary(
        store,
        rejected_cache,
        final,
        iteration,
        total_fetched_approx,
        0,
        pass1_count,
        pass2_count,
    )

    return final


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════

async def main_async():
    banner()

    print(f"  {C.DM}Dépendances:{C.X}")
    print(f"  {C.G}✓ aiohttp{C.X}")
    print(f"  {C.G}✓ aiofiles{C.X}")
    print(f"  {C.G}✓ {JSON_ENGINE} (JSON engine){C.X}")

    try:
        import requests
        print(f"  {C.G}✓ requests{C.X}")
    except ImportError:
        print(f"  {C.R}✗ pip install requests{C.X}")
        sys.exit(1)

    print(f"\n  {C.BD}Nouvelles fonctionnalités v5.0:{C.X}")
    print(f"  {C.CY}✓ Cache rejet persistant "
          f"(expiry: {REJECTED_EXPIRY_HOURS}h / long ban: {REJECTED_LONG_EXPIRY_HOURS}h){C.X}")
    print(f"  {C.CY}✓ API via proxy vérifié "
          f"({'activé' if USE_PROXY_FOR_API else 'désactivé'}){C.X}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    store = ProxyStore()
    rejected_cache = RejectedCache()
    api_caller = ProxiedAPICaller(store)

    iteration = 0

    print(f"\n  {C.BD}{C.CY}🔄 Mode boucle: {LOOP_INTERVAL}s (Ctrl+C pour arrêter){C.X}")

    try:
        while True:
            iteration += 1
            start_time = time.perf_counter()

            await run_iteration(store, rejected_cache, api_caller, iteration)

            elapsed = time.perf_counter() - start_time
            wait = max(0, LOOP_INTERVAL - elapsed)

            if wait > 0:
                print(f"\n  {C.DM}⏳ Prochaine itération dans {int(wait)}s...{C.X}")
                await asyncio.sleep(wait)
            else:
                print(f"\n  {C.Y}⚡ Itération: {elapsed:.0f}s, relance immédiate{C.X}")

    except KeyboardInterrupt:
        print(f"\n\n  {C.Y}{C.BD}⚡ Arrêt demandé.{C.X}")

        # Sauvegarde finale
        await rejected_cache.save_async()
        await store.save_async()

        print(f"\n  {C.BD}Résultat final:{C.X}")
        print(f"  {C.G}  {store.count} proxies vérifiés{C.X}")
        print(
            f"  {C.G}  ★ {store.elite_count} Elite │ "
            f"● {store.anon_count} Anonymous{C.X}"
        )
        print(
            f"  {C.B}  📋 {len(rejected_cache.entries)} proxies "
            f"dans le cache de rejet{C.X}"
        )
        print()


def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main_async())


if __name__ == "__main__":
    main()
