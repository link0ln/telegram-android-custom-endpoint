"""In-memory authorization state: token table, device presence, live
connections and pending meter counters.

Why the whole token table is held in RAM, always, with no lazy loading and no
negative cache: if an unknown token fell through to a database query it would
be measurably slower than a known one, and that timing difference is exactly
the active-probing oracle the masking design exists to prevent. A dict lookup
takes the same time whether or not the key is present, so 'unknown token' and
'random garbage' follow an identical code path to the cover site.

Device accounting counts *presence*, not connections. A running Telegram app
holds ~2-4 sockets when idle and 10-20+ when active, and churns them
constantly, so counting connections would make any device limit flap on every
reconnect.
"""

import time

# A device keeps its slot for this long after its last socket closes, so that
# a reconnect storm does not cost the user their device slot.
DEFAULT_GRACE = 180.0
# One rejection log/counter per device per this many seconds, instead of one
# per parallel reconnect.
REJECT_MEMO = 60.0

POLICY_STRICT = "strict"
POLICY_LRU = "lru"


class TokenRec(object):
    __slots__ = ("id", "prefix", "plan", "expires_at", "device_limit",
                 "conn_limit", "byte_quota", "quota_period", "tunnel_enabled",
                 "status", "used_bytes")

    def __init__(self, row, used_bytes=0):
        self.id = row["id"]
        self.prefix = row["token_prefix"]
        self.plan = row["plan"]
        self.expires_at = row["expires_at"]
        self.device_limit = row["device_limit"]
        self.conn_limit = row["conn_limit"]
        self.byte_quota = row["byte_quota"]
        self.quota_period = row["quota_period"]
        self.tunnel_enabled = bool(row["tunnel_enabled"])
        self.status = row["status"]
        self.used_bytes = used_bytes

    def expired(self, now=None):
        if self.expires_at == 0:
            return False
        return (now or time.time()) >= self.expires_at

    def ttl_days(self, now=None):
        if self.expires_at == 0:
            return 0xFFFF
        left = self.expires_at - (now or time.time())
        return max(0, int(left // 86400))

    def over_quota(self):
        return self.byte_quota > 0 and self.used_bytes >= self.byte_quota


class DeviceState(object):
    __slots__ = ("live", "last_active", "first_seen")

    def __init__(self, now):
        self.live = 0
        self.last_active = now
        self.first_seen = now

    def present(self, now, grace):
        return self.live > 0 or (now - self.last_active) < grace


class ConnState(object):
    __slots__ = ("conn_id", "token_id", "prefix", "device", "mode", "ip",
                 "up", "down", "pend_up", "pend_down", "reason", "started",
                 "killer")

    def __init__(self, conn_id, token_id, prefix, device, mode, ip, started):
        # set by the transport layer so a revocation can drop a live socket
        self.killer = None
        self.conn_id = conn_id
        self.token_id = token_id
        self.prefix = prefix
        self.device = device
        self.mode = mode
        self.ip = ip
        self.up = 0
        self.down = 0
        self.pend_up = 0
        self.pend_down = 0
        self.reason = "eof"
        self.started = started

    # These two are the only thing the byte pump calls; keep them trivial.
    def add_up(self, n):
        self.up += n
        self.pend_up += n

    def add_down(self, n):
        self.down += n
        self.pend_down += n


class AuthState(object):
    def __init__(self, grace=DEFAULT_GRACE, policy=POLICY_STRICT):
        self.auth = {}          # sha256(token) -> TokenRec
        self.by_id = {}         # token_id -> TokenRec
        self.devices = {}       # (token_id, device) -> DeviceState
        self.live = {}          # token_id -> set[ConnState]
        self.meter = {}         # token_id -> counter dict
        self.reject_memo = {}   # (token_id, device) -> monotonic
        self.bad_auth = {}      # ip -> [count, window_start]
        self.grace = grace
        self.policy = policy
        self.gen = 0

    # ---- snapshot loading -------------------------------------------------

    def replace(self, rows, usage_by_id=None, gen=0):
        """Swap in a fresh snapshot. Returns the token ids whose connections
        must now be killed (revoked, suspended, expired, over quota)."""
        usage_by_id = usage_by_id or {}
        auth, by_id = {}, {}
        for row in rows:
            rec = TokenRec(row, usage_by_id.get(row["id"], 0))
            auth[bytes(row["token_hash"])] = rec
            by_id[rec.id] = rec
        self.auth, self.by_id, self.gen = auth, by_id, gen

        now = time.time()
        doomed = []
        for tid, conns in self.live.items():
            if not conns:
                continue
            rec = by_id.get(tid)
            if rec is None or rec.status != "active" or rec.expired(now) or rec.over_quota():
                doomed.append(tid)
        # Devices of tokens that vanished entirely are dead weight.
        for key in [k for k in self.devices if k[0] not in by_id]:
            del self.devices[key]
        return doomed

    def get(self, token_hash):
        return self.auth.get(token_hash)

    # ---- admission --------------------------------------------------------

    def present_devices(self, token_id, now):
        return [k[1] for k, d in self.devices.items()
                if k[0] == token_id and d.present(now, self.grace)]

    def admit(self, rec, device, mode, now=None, mono=None):
        """None to admit, or (status_code, ttl_days, payload) to reject.

        Only ever called for a token we already know, so returning a
        distinguishable answer here leaks nothing to a prober.
        """
        import wire
        now = now or time.time()
        mono = mono if mono is not None else time.monotonic()

        if rec.status == "revoked" or rec.status == "suspended":
            return (wire.ST_SUSPENDED, 0, {"code": rec.status})
        if rec.expired(now):
            return (wire.ST_EXPIRED, 0,
                    {"code": "expired", "expires_at": rec.expires_at})
        if rec.over_quota():
            return (wire.ST_QUOTA, rec.ttl_days(now),
                    {"code": "quota", "used": rec.used_bytes,
                     "limit": rec.byte_quota, "period": rec.quota_period})
        if mode == wire.MODE_TUNNEL and not rec.tunnel_enabled:
            return (wire.ST_FORBIDDEN_HOST, rec.ttl_days(now),
                    {"code": "tunnel_disabled"})

        conns = self.live.get(rec.id)
        if conns is not None and len(conns) >= rec.conn_limit:
            return (wire.ST_BUSY, rec.ttl_days(now),
                    {"code": "busy", "retry_after": 30})

        key = (rec.id, device)
        dev = self.devices.get(key)
        if dev is not None and dev.present(mono, self.grace):
            dev.last_active = mono
            return None                      # the common case: 19 of 20 sockets

        present = self.present_devices(rec.id, mono)
        if len(present) < rec.device_limit:
            if dev is None:
                self.devices[key] = DeviceState(mono)
            else:
                dev.last_active = mono
            return None

        if self.policy == POLICY_LRU:
            victim = min((k for k in self.devices if k[0] == rec.id and k[1] in present),
                         key=lambda k: self.devices[k].last_active, default=None)
            if victim is not None:
                del self.devices[victim]
                self.devices[key] = DeviceState(mono)
                return None

        return (wire.ST_DEVICE_LIMIT, rec.ttl_days(now),
                {"code": "device_limit", "limit": rec.device_limit,
                 "devices": [{"id": d.hex()[:8],
                              "idle": int(mono - self.devices[(rec.id, d)].last_active)}
                             for d in present]})

    def status_payload(self, rec, device=None, now=None):
        now = now or time.time()
        mono = time.monotonic()
        return {
            "code": "ok",
            "plan": rec.plan,
            "expires_at": rec.expires_at,
            "device_limit": rec.device_limit,
            "devices_present": len(self.present_devices(rec.id, mono)),
            "quota": rec.byte_quota,
            "used": rec.used_bytes,
        }

    # ---- connection registry ---------------------------------------------

    def attach(self, rec, device, ip, mode, conn_id, mono=None):
        mono = mono if mono is not None else time.monotonic()
        cs = ConnState(conn_id, rec.id, rec.prefix, device, mode, ip, mono)
        self.live.setdefault(rec.id, set()).add(cs)
        key = (rec.id, device)
        dev = self.devices.get(key)
        if dev is None:
            dev = self.devices[key] = DeviceState(mono)
        dev.live += 1
        dev.last_active = mono
        self._bump(rec.id, "conns", 1)
        if mode == 0x10:
            self._bump(rec.id, "tunnel_conns", 1)
        self.meter.setdefault(rec.id, {})["device_id"] = device
        return cs

    def detach(self, cs, mono=None):
        mono = mono if mono is not None else time.monotonic()
        conns = self.live.get(cs.token_id)
        if conns is not None:
            conns.discard(cs)
        dev = self.devices.get((cs.token_id, cs.device))
        if dev is not None:
            dev.live = max(0, dev.live - 1)
            dev.last_active = mono
        self.drain_conn(cs)

    def drain_conn(self, cs):
        """Move a connection's pending bytes into the token's meter bucket.
        Called both on teardown and periodically for long-lived connections,
        so a multi-gigabyte download is metered continuously."""
        if cs.pend_up or cs.pend_down:
            self._bump(cs.token_id, "bytes_up", cs.pend_up)
            self._bump(cs.token_id, "bytes_down", cs.pend_down)
            if cs.mode == 0x10:
                self._bump(cs.token_id, "tunnel_bytes", cs.pend_up + cs.pend_down)
            rec = self.by_id.get(cs.token_id)
            if rec is not None:
                rec.used_bytes += cs.pend_up + cs.pend_down
            cs.pend_up = 0
            cs.pend_down = 0

    def drain_all(self):
        for conns in self.live.values():
            for cs in list(conns):
                self.drain_conn(cs)

    def _bump(self, token_id, field, n):
        m = self.meter.setdefault(token_id, {})
        m[field] = m.get(field, 0) + n

    def take_meter(self):
        """Rows for store.flush_usage(); resets the accumulator."""
        self.drain_all()
        rows = []
        for tid, m in self.meter.items():
            row = {"token_id": tid}
            row.update(m)
            rows.append(row)
        self.meter = {}
        return rows

    # ---- rejections and probes -------------------------------------------

    def note_reject(self, rec, device, mono=None):
        """True if this rejection should be logged/counted; False if it is one
        of the 19 duplicate reconnects that follow the first."""
        mono = mono if mono is not None else time.monotonic()
        key = (rec.id, device)
        last = self.reject_memo.get(key, 0)
        if mono - last < REJECT_MEMO:
            return False
        self.reject_memo[key] = mono
        self._bump(rec.id, "rejects", 1)
        return True

    def note_bad_auth(self, ip, mono=None, limit=30, window=60.0):
        """True while we should still log unknown-token attempts from this ip.
        Purely log hygiene: 128-bit tokens do not need brute-force defence."""
        mono = mono if mono is not None else time.monotonic()
        ent = self.bad_auth.get(ip)
        if ent is None or mono - ent[1] > window:
            self.bad_auth[ip] = [1, mono]
            return True
        ent[0] += 1
        return ent[0] <= limit

    # ---- housekeeping -----------------------------------------------------

    def sweep(self, now=None, mono=None):
        """Drop stale device slots and rejection memos; return token ids whose
        subscription lapsed mid-session."""
        now = now or time.time()
        mono = mono if mono is not None else time.monotonic()
        for key in [k for k, d in self.devices.items()
                    if d.live == 0 and (mono - d.last_active) > self.grace * 4]:
            del self.devices[key]
        for key in [k for k, t in self.reject_memo.items() if mono - t > REJECT_MEMO * 4]:
            del self.reject_memo[key]
        for ip in [i for i, e in self.bad_auth.items() if mono - e[1] > 300]:
            del self.bad_auth[ip]
        doomed = []
        for tid, conns in self.live.items():
            if not conns:
                continue
            rec = self.by_id.get(tid)
            if rec is None or rec.expired(now) or rec.over_quota() or rec.status != "active":
                doomed.append(tid)
        return doomed

    def conns_of(self, token_id):
        return list(self.live.get(token_id) or ())

    def total_conns(self):
        return sum(len(s) for s in self.live.values())
