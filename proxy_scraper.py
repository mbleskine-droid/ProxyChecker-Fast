#!/usr/bin/env python3
"""
Proxy Scraper, Checker & Anonymity Verifier v4.1 - FIXED
=========================================================
"""

from __future__ import annotations

import asyncio
import sys
import os
import time
import re
from datetime import datetime
from dataclasses import dataclass
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
    ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http"),
    ("socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
)

PROXYSCRAPE_API = "https://api.proxyscrape.com/v4/online_check"
HTTPBIN_URL = "http://httpbin.org/get"

BATCH_SIZE = 1000
CONCURRENT_BATCHES = 1
MAX_WORKERS_ANON = 50
PROXY_TIMEOUT = 6
LOOP_INTERVAL = 120
API_DELAY = 1.0

OUTPUT_DIR = "output"
PERSISTENT_FILE = os.path.join(OUTPUT_DIR, "VERIFIED_PROXIES.txt")
PERSISTENT_ELITE = os.path.join(OUTPUT_DIR, "VERIFIED_ELITE.txt")
PERSISTENT_JSON = os.path.join(OUTPUT_DIR, "VERIFIED_DETAILED.json")

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
    UNKNOWN = 0
    TRANSPARENT = 1
    ANONYMOUS = 2
    ELITE = 3


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
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; M = "\033[95m"; CY = "\033[96m"
    W = "\033[97m"; BD = "\033[1m"; DM = "\033[2m"; X = "\033[0m"


def banner():
    print(f"""{C.CY}{C.BD}
    ╔════════════════════════════════════════════════════════════════╗
    ║   🔒  PROXY SCRAPER v4.1 FIXED (Windows Compatible) 🔒       ║
    ║                                                                ║
    ║   ⚡ Async I/O · Connection Pooling · Parallel Batches        ║
    ║   ⚡ {JSON_ENGINE:>6} engine · Fixed API parsing                      ║
    ╚════════════════════════════════════════════════════════════════╝
    {C.X}""")


def section(step: int, title: str):
    print(f"\n{C.BD}{C.CY}{'━'*70}\n  ÉTAPE {step} │ {title}\n{'━'*70}{C.X}")


# ══════════════════════════════════════════════
#  PERSISTENT STORAGE
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
                print(f"  {C.DM}Chargé {len(self.verified)} proxies depuis le cache{C.X}")
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

    async def save_async(self):
        if not self._dirty:
            return

        os.makedirs(OUTPUT_DIR, exist_ok=True)

        entries = sorted(
            self.verified.values(),
            key=lambda e: (0 if e["anonymity"] == "elite" else 1, e.get("response_time_ms") or 99999)
        )

        async with aiofiles.open(PERSISTENT_JSON, "w", encoding="utf-8") as f:
            await f.write(json_dumps(entries))

        async with aiofiles.open(PERSISTENT_FILE, "w", encoding="utf-8") as f:
            await f.write('\n'.join(e['proxy'] for e in entries) + '\n')

        async with aiofiles.open(PERSISTENT_ELITE, "w", encoding="utf-8") as f:
            elite_list = [e['proxy'] for e in entries if e["anonymity"] == "elite"]
            await f.write('\n'.join(elite_list) + '\n' if elite_list else '')

        self._dirty = False
        print(f"  {C.G}💾 Sauvegardé: {len(entries)} proxies{C.X}")

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
#  ÉTAPE 1 : FETCH ASYNC
# ══════════════════════════════════════════════

PROXY_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$')


async def fetch_source(session: aiohttp.ClientSession, name: str, url: str, seen: Set[str]) -> List[Proxy]:
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


async def step1_fetch() -> List[Proxy]:
    section(1, "Téléchargement async (3 sources parallèles)")

    seen: Set[str] = set()
    all_proxies: List[Proxy] = []

    connector = aiohttp.TCPConnector(limit=30, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, name, url, seen) for name, url, _ in PROXY_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_proxies.extend(result)

    print(f"\n  {C.BD}Total: {len(all_proxies)} proxies uniques{C.X}")
    return all_proxies


# ══════════════════════════════════════════════
#  ÉTAPE 2 : PROXYSCRAPE - VERSION SYNCHRONE CORRIGÉE
# ══════════════════════════════════════════════

def check_batch_sync(batch: List[Proxy], batch_num: int, total_batches: int, start_idx: int, pass_label: str) -> Tuple[int, int, List[Proxy]]:
    """Version synchrone avec requests - plus fiable pour cette API"""
    import requests

    alive_count, dead_count = 0, 0
    alive_proxies = []

    # Construire le payload
    files = []
    for i, proxy in enumerate(batch):
        idx = start_idx + i
        value = f"{proxy.ip}:{proxy.port}-{idx}"
        files.append(("ip_addr[]", (None, value)))

    try:
        resp = requests.post(
            PROXYSCRAPE_API,
            files=files,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
                "Origin": "https://proxyscrape.com",
                "Referer": "https://proxyscrape.com/",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            },
            timeout=120,
        )

        if resp.status_code == 200:
            try:
                data = resp.json()

                if isinstance(data, list):
                    proxy_map = {(p.ip, p.port): p for p in batch}

                    for entry in data:
                        ip = entry.get("ip", "")
                        port_val = entry.get("port")
                        
                        # Gérer port comme int ou string
                        if port_val is not None:
                            try:
                                port = int(port_val)
                            except (ValueError, TypeError):
                                continue
                        else:
                            continue

                        key = (ip, port)

                        if key in proxy_map:
                            p = proxy_map[key]
                            working = entry.get("working", False)
                            
                            if working is True:
                                p.alive = True
                                p.country = entry.get("country") or entry.get("country_code") or ""
                                p.proxy_type = entry.get("type") or entry.get("protocol") or p.source
                                alive_count += 1
                                alive_proxies.append(p)
                            else:
                                p.alive = False
                                dead_count += 1

                    status = f"{C.G}{alive_count:>3}✓{C.X} {C.R}{dead_count:>3}✗{C.X}"
                else:
                    # Réponse inattendue
                    status = f"{C.Y}Format inattendu: {type(data).__name__}{C.X}"
                    
            except ValueError as e:
                # JSON invalide
                preview = resp.text[:100] if resp.text else "empty"
                status = f"{C.R}JSON error: {preview}...{C.X}"
        else:
            status = f"{C.R}HTTP {resp.status_code}{C.X}"

    except requests.exceptions.Timeout:
        status = f"{C.R}TIMEOUT{C.X}"
    except Exception as e:
        status = f"{C.R}{str(e)[:30]}{C.X}"

    print(f"  [{pass_label}] Batch {batch_num:>2}/{total_batches} │ {status}")

    return alive_count, dead_count, alive_proxies


async def proxyscrape_batch_async(proxies: List[Proxy], pass_label: str) -> List[Proxy]:
    """Execute les checks en parallèle via thread pool"""
    total = len(proxies)
    batches = [proxies[i:i+BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
    total_batches = len(batches)

    total_alive, total_dead = 0, 0
    all_alive: List[Proxy] = []

    loop = asyncio.get_event_loop()

    # Traiter par groupes de CONCURRENT_BATCHES
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
                    batch, i + 1, total_batches, start_idx, pass_label
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, tuple):
                    alive_c, dead_c, alive_list = result
                    total_alive += alive_c
                    total_dead += dead_c
                    all_alive.extend(alive_list)
                elif isinstance(result, Exception):
                    print(f"  {C.R}Erreur batch: {result}{C.X}")

        # Délai entre groupes pour éviter rate limiting
        if group_end < total_batches:
            await asyncio.sleep(API_DELAY)

    print(f"\n  {C.BD}[{pass_label}] Total: {C.G}{total_alive} alive{C.X} / {C.R}{total_dead} dead{C.X}")

    return all_alive


async def step2_double_check(proxies: List[Proxy]) -> List[Proxy]:
    section(2, f"ProxyScrape Double Check ({len(proxies)} proxies)")
    print(f"  {C.DM}API: {PROXYSCRAPE_API}{C.X}")
    print(f"  {C.DM}Batch size: {BATCH_SIZE}, Concurrent: {CONCURRENT_BATCHES}{C.X}")

    # PASS 1
    print(f"\n  {C.M}{C.BD}═══ PASS 1: Élimination rapide ═══{C.X}\n")
    pass1 = await proxyscrape_batch_async(proxies, "P1")

    if not pass1:
        print(f"\n  {C.R}Aucun survivant PASS 1{C.X}")
        return []

    # Marquer pass1
    pass1_set = {(p.ip, p.port) for p in pass1}
    for p in proxies:
        if (p.ip, p.port) in pass1_set:
            p.pass1_alive = True

    # Afficher quelques survivants
    print(f"\n  {C.G}Survivants PASS 1: {len(pass1)}{C.X}")
    for p in pass1[:5]:
        print(f"    {C.G}✓{C.X} {p.address:<22} {p.country or '??':>4} {p.proxy_type or p.source}")
    if len(pass1) > 5:
        print(f"    {C.DM}... et {len(pass1) - 5} autres{C.X}")

    # Reset alive pour pass 2
    for p in pass1:
        p.alive = False

    # PASS 2
    print(f"\n  {C.M}{C.BD}═══ PASS 2: Confirmation ({len(pass1)} survivants) ═══{C.X}")
    print(f"  {C.DM}Pause 3s avant PASS 2...{C.X}")
    await asyncio.sleep(3)
    print()

    pass2 = await proxyscrape_batch_async(pass1, "P2")

    # Marquer pass2
    for p in pass2:
        p.pass2_alive = True

    eliminated = len(pass1) - len(pass2)
    print(f"\n  {C.BD}Pipeline: {len(proxies)} → {len(pass1)} → {C.G}{len(pass2)} confirmés{C.X}")
    if eliminated > 0:
        print(f"  {C.Y}({eliminated} éliminés entre P1 et P2){C.X}")

    return pass2


# ══════════════════════════════════════════════
#  ÉTAPE 3 : ANONYMITY CHECK
# ══════════════════════════════════════════════

@lru_cache(maxsize=1)
def get_real_ip() -> str:
    import requests
    services = [
        ("https://api.ipify.org?format=json", lambda r: r.json()["ip"]),
        ("https://ifconfig.me/ip", lambda r: r.text.strip()),
        ("http://httpbin.org/ip", lambda r: r.json()["origin"].split(",")[0].strip()),
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
        "http": f"{scheme}://{proxy.address}",
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


async def step3_anonymity(proxies: List[Proxy]) -> List[Proxy]:
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

            speed = f"{result.response_time_ms:.0f}ms" if result.response_time_ms else "fail"
            print(f"  {icon} {result.address:<22} {speed:>7} [{completed}/{total}]")

            results.append(result)

    # Stats
    by_level = defaultdict(list)
    for p in results:
        by_level[p.anonymity].append(p)

    print(f"\n  {'─'*50}")
    print(f"  {C.G}★ Elite      : {len(by_level[AnonymityLevel.ELITE])}{C.X}")
    print(f"  {C.Y}● Anonymous  : {len(by_level[AnonymityLevel.ANONYMOUS])}{C.X}")
    print(f"  {C.R}✗ Transparent: {len(by_level[AnonymityLevel.TRANSPARENT])}{C.X}")
    print(f"  {C.DM}? Dead/Unknown: {len(by_level[AnonymityLevel.UNKNOWN])}{C.X}")

    final = by_level[AnonymityLevel.ELITE] + by_level[AnonymityLevel.ANONYMOUS]
    final.sort(key=lambda p: (
        0 if p.anonymity == AnonymityLevel.ELITE else 1,
        p.response_time_ms or 99999
    ))

    return final


# ══════════════════════════════════════════════
#  RÉSUMÉ
# ══════════════════════════════════════════════

def print_summary(store: ProxyStore, new_proxies: List[Proxy], iteration: int,
                  total_fetched: int, pass1_count: int, pass2_count: int):
    now = datetime.now().strftime("%H:%M:%S")

    print(f"\n{C.BD}{C.CY}{'━'*70}")
    print(f"  RÉSUMÉ │ Itération #{iteration} à {now}")
    print(f"{'━'*70}{C.X}")

    print(f"\n  {C.BD}Pipeline cette itération:{C.X}")
    print(f"  {C.DM}  Téléchargés   : {total_fetched}{C.X}")
    print(f"  {C.Y}  Après PASS 1  : {pass1_count}{C.X}")
    print(f"  {C.CY}  Après PASS 2  : {pass2_count}{C.X}")
    print(f"  {C.G}  Après anonymat: {len(new_proxies)}{C.X}")

    if new_proxies:
        print(f"\n  {C.BD}Top 10 proxies vérifiés:{C.X}")
        for p in new_proxies[:10]:
            anon = f"{C.G}★ ELITE{C.X}" if p.anonymity == AnonymityLevel.ELITE else f"{C.Y}● ANON{C.X}"
            speed = f"{p.response_time_ms:.0f}ms" if p.response_time_ms else "N/A"
            print(f"    {p.address:<22} {anon} {speed:>8} {p.country or '??'}")

    print(f"\n  {'═'*50}")
    print(f"  {C.BD}{C.G}📊 TOTAL ACCUMULÉ: {store.count} proxies{C.X}")
    print(f"     {C.G}★ {store.elite_count} Elite{C.X}")
    print(f"     {C.Y}● {store.anon_count} Anonymous{C.X}")

    print(f"\n  {C.BD}Fichiers:{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_FILE}{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_ELITE}{C.X}")
    print(f"    {C.G}📄 {PERSISTENT_JSON}{C.X}")


# ══════════════════════════════════════════════
#  ITÉRATION PRINCIPALE
# ══════════════════════════════════════════════

async def run_iteration(store: ProxyStore, iteration: int) -> List[Proxy]:
    now = datetime.now().strftime("%H:%M:%S")

    print(f"\n\n{C.BD}{C.M}{'▓'*70}")
    print(f"  ITÉRATION #{iteration} │ {now} │ Accumulé: {store.count}")
    print(f"{'▓'*70}{C.X}")

    # Étape 1
    all_proxies = await step1_fetch()
    if not all_proxies:
        return []

    total_fetched = len(all_proxies)

    # Étape 2
    confirmed = await step2_double_check(all_proxies)
    pass1_count = sum(1 for p in all_proxies if p.pass1_alive)
    pass2_count = len(confirmed)

    if not confirmed:
        print_summary(store, [], iteration, total_fetched, pass1_count, 0)
        return []

    # Installer PySocks si nécessaire
    has_socks = any(p.source in ("socks4", "socks5") for p in confirmed)
    if has_socks:
        try:
            import socks
        except ImportError:
            print(f"\n  {C.Y}⚠ Installation de PySocks...{C.X}")
            os.system(f"{sys.executable} -m pip install PySocks -q")

    # Étape 3
    final = await step3_anonymity(confirmed)

    # Mise à jour store
    for p in final:
        store.add(p)

    await store.save_async()

    print_summary(store, final, iteration, total_fetched, pass1_count, pass2_count)

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

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    store = ProxyStore()

    iteration = 0

    print(f"\n  {C.BD}{C.CY}🔄 Mode boucle: {LOOP_INTERVAL}s (Ctrl+C pour arrêter){C.X}")

    try:
        while True:
            iteration += 1
            start_time = time.perf_counter()

            await run_iteration(store, iteration)

            elapsed = time.perf_counter() - start_time
            wait = max(0, LOOP_INTERVAL - elapsed)

            if wait > 0:
                print(f"\n  {C.DM}⏳ Prochaine itération dans {int(wait)}s...{C.X}")
                await asyncio.sleep(wait)
            else:
                print(f"\n  {C.Y}⚡ Itération: {elapsed:.0f}s, relance immédiate{C.X}")

    except KeyboardInterrupt:
        print(f"\n\n  {C.Y}{C.BD}⚡ Arrêt demandé.{C.X}")
        print(f"\n  {C.BD}Résultat final:{C.X}")
        print(f"  {C.G}  {store.count} proxies vérifiés{C.X}")
        print(f"  {C.G}  ★ {store.elite_count} Elite │ ● {store.anon_count} Anonymous{C.X}")
        print()


def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main_async())


if __name__ == "__main__":
    main()
