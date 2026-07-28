"""CONNECT tunnel for onboarding, locked to a fixed set of hosts.

The client needs to reach my.telegram.org to create its own api_id/api_hash,
and on the networks this product targets that host is blocked. Mode 0x10 lets
an authorized client tunnel to it through the relay.

The whole risk here is turning the relay into an open proxy, so the controls
are layered and none of them is operator-configurable:

  1. exact-match host whitelist, compiled in, no suffix matching and no env
     override (an env-settable whitelist is a footgun that eventually becomes
     ANY);
  2. the port is always 443, never taken from the client, which rules out
     CONNECT-to-:25 mail relaying and internal port scanning;
  3. resolved addresses must be global unicast, and we connect to the
     validated IP literal rather than re-resolving the name, closing the
     DNS-rebinding window between check and connect;
  4. per-token concurrency, open-rate and daily byte limits, sized so the
     tunnel is useless as general-purpose transport (onboarding needs a few
     megabytes at most).
"""

import ipaddress
import time

TUNNEL_HOSTS = frozenset({
    "my.telegram.org",     # required: api_id / api_hash issuance
    "telegram.org",        # redirect target, css/fonts
    "www.telegram.org",
    "core.telegram.org",   # documentation links from those pages
})
# Deliberately excluded: web.telegram.org (a full client - would make this a
# general Telegram proxy outside the metered path), t.me, api.telegram.org.

TUNNEL_PORT = 443

MAX_CONCURRENT_PER_TOKEN = 4
OPENS_PER_MINUTE = 10
OPEN_BURST = 20
DAILY_BYTES_DEFAULT = 50 * 1024 * 1024
GLOBAL_MAX_TUNNELS = 200

RESOLVE_TTL_OK = 300.0
RESOLVE_TTL_FAIL = 30.0
RESOLVE_CACHE_MAX = 64


class Limits(object):
    """Token buckets and counters, all in memory."""

    def __init__(self, daily_bytes=DAILY_BYTES_DEFAULT):
        self.daily_bytes = daily_bytes
        self.open_tokens = {}     # token_id -> [tokens, last_refill]
        self.concurrent = {}      # token_id -> int
        self.day_bytes = {}       # (token_id, day) -> int
        self.total = 0

    def allow_open(self, token_id, mono=None):
        mono = mono if mono is not None else time.monotonic()
        if self.total >= GLOBAL_MAX_TUNNELS:
            return False, "global"
        if self.concurrent.get(token_id, 0) >= MAX_CONCURRENT_PER_TOKEN:
            return False, "concurrent"
        ent = self.open_tokens.get(token_id)
        if ent is None:
            ent = self.open_tokens[token_id] = [float(OPEN_BURST), mono]
        else:
            elapsed = mono - ent[1]
            ent[0] = min(float(OPEN_BURST), ent[0] + elapsed * (OPENS_PER_MINUTE / 60.0))
            ent[1] = mono
        if ent[0] < 1.0:
            return False, "rate"
        day = time.strftime("%Y-%m-%d", time.gmtime())
        if self.day_bytes.get((token_id, day), 0) >= self.daily_bytes:
            return False, "daily_bytes"
        ent[0] -= 1.0
        return True, None

    def opened(self, token_id):
        self.concurrent[token_id] = self.concurrent.get(token_id, 0) + 1
        self.total += 1

    def closed(self, token_id, nbytes=0):
        self.concurrent[token_id] = max(0, self.concurrent.get(token_id, 0) - 1)
        self.total = max(0, self.total - 1)
        if nbytes:
            day = time.strftime("%Y-%m-%d", time.gmtime())
            key = (token_id, day)
            self.day_bytes[key] = self.day_bytes.get(key, 0) + nbytes

    def sweep(self):
        today = time.strftime("%Y-%m-%d", time.gmtime())
        for key in [k for k in self.day_bytes if k[1] != today]:
            del self.day_bytes[key]


def host_allowed(host):
    if not host:
        return False
    try:
        h = host.decode("ascii") if isinstance(host, (bytes, bytearray)) else host
    except UnicodeDecodeError:
        return False
    return h.strip().lower().rstrip(".") in TUNNEL_HOSTS


def is_public(addr_text):
    """Reject anything that is not a globally routable unicast address."""
    try:
        a = ipaddress.ip_address(addr_text)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified)


class Resolver(object):
    """Small TTL cache in front of getaddrinfo, returning only public IPs."""

    def __init__(self):
        self.cache = {}   # host -> (expires_at, [ip, ...])

    def cached(self, host, mono=None):
        mono = mono if mono is not None else time.monotonic()
        ent = self.cache.get(host)
        if ent and ent[0] > mono:
            return ent[1]
        return None

    def store(self, host, ips, mono=None):
        mono = mono if mono is not None else time.monotonic()
        ttl = RESOLVE_TTL_OK if ips else RESOLVE_TTL_FAIL
        if len(self.cache) >= RESOLVE_CACHE_MAX:
            self.cache.clear()
        self.cache[host] = (mono + ttl, ips)
        return ips

    @staticmethod
    def filter_public(addrinfos, local_addrs=()):
        out = []
        for info in addrinfos:
            ip = info[4][0]
            if not is_public(ip):
                continue
            if ip in local_addrs:
                continue
            if ip not in out:
                out.append(ip)
        return out
