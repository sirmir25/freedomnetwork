"""DNS over HTTPS resolver — bypasses ISP DNS blocking entirely."""
from __future__ import annotations

import asyncio
import json
import socket
import time
import urllib.request
from typing import Optional

from config import DNS_CACHE_TTL, DOH_RESOLVERS

_cache: dict[str, tuple[str, float]] = {}


def _query_sync(hostname: str, url: str) -> Optional[str]:
    req = urllib.request.Request(
        f"{url}?name={hostname}&type=A",
        headers={"Accept": "application/dns-json", "User-Agent": "curl/7.88.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            for answer in json.loads(resp.read()).get("Answer", []):
                if answer.get("type") == 1:  # A record
                    return answer["data"]
    except Exception:
        return None
    return None


async def resolve(hostname: str) -> Optional[str]:
    now = time.monotonic()
    cached = _cache.get(hostname)
    if cached and now < cached[1]:
        return cached[0]

    loop = asyncio.get_event_loop()

    for url in DOH_RESOLVERS:
        ip = await loop.run_in_executor(None, _query_sync, hostname, url)
        if ip:
            _cache[hostname] = (ip, now + DNS_CACHE_TTL)
            return ip

    # System DNS fallback (last resort — may be poisoned by ISP)
    try:
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            ip = infos[0][4][0]
            _cache[hostname] = (ip, now + DNS_CACHE_TTL)
            return ip
    except Exception:
        pass

    return None
