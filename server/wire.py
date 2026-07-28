"""Wire format for the relay protocol. Pure functions, no I/O, no state.

Two protocol versions share one 5-byte prologue so that the server can keep
reading exactly 5 bytes before it knows anything about the client:

    byte 0..2   b"TGR"
    byte 3      version: 0x31 (ASCII '1') = v1 legacy, 0x02 = v2
    byte 4      v1: dcId 1..5      v2: mode

v1 (`TGR1` + dcId) is what the pre-subscription client sends: no token, no
reply. It is a strict subset of v2's prologue, so both parse the same way.

v2 continues with a fixed body, read ONLY after the prologue matched. Reading
more bytes unconditionally would stall on short probes and make the relay
distinguishable from an ordinary HTTPS server:

    0..15    token       16 raw bytes
    16..31   device_id   16 raw bytes, stable per app install
    32..33   ext_len     uint16 BE, <= 512
    34..     ext         TLV blob: type u8, len u8, value[len]

The server answers a v2 client with a status frame, and ONLY ever answers a
client whose token it already knows. An unknown token is spliced to the cover
site with no server-originated bytes, so an active prober cannot tell this
server apart from the site it fronts.

    0..3     b"TGS2"
    4        status code
    5        flags (0)
    6..7     ttl_days uint16 BE      <- native reads 10 bytes, never parses JSON
    8..9     payload_len uint16 BE
    10..     payload: UTF-8 JSON, may be empty
"""

import base64
import hashlib
import json
import secrets

# ---- prologue -------------------------------------------------------------

MAGIC3 = b"TGR"
VER_V1 = 0x31          # ASCII '1', so the v1 header "TGR1" stays byte-identical
VER_V2 = 0x02
PROLOGUE_LEN = 5

# ---- v2 modes (prologue byte 4) -------------------------------------------

MODE_DC_MIN = 0x01
MODE_DC_MAX = 0x05
MODE_TUNNEL = 0x10     # CONNECT to a whitelisted host (onboarding)
MODE_PING = 0x11       # report subscription status and close

# ---- v2 body --------------------------------------------------------------

TOKEN_LEN = 16
DEVICE_LEN = 16
V2_BODY_LEN = TOKEN_LEN + DEVICE_LEN + 2   # 34
MAX_EXT_LEN = 512

TLV_CONNECT_HOST = 0x01
TLV_CLIENT_VERSION = 0x03

# ---- status frame ---------------------------------------------------------

STATUS_MAGIC = b"TGS2"
STATUS_HDR_LEN = 10
MAX_STATUS_PAYLOAD = 1024

ST_OK = 0x00
ST_EXPIRED = 0x01
ST_DEVICE_LIMIT = 0x02
ST_SUSPENDED = 0x03
ST_QUOTA = 0x04
ST_BUSY = 0x05
ST_CLIENT_TOO_OLD = 0x06
ST_FORBIDDEN_HOST = 0x07
ST_UPSTREAM = 0x08

STATUS_NAMES = {
    ST_OK: "ok",
    ST_EXPIRED: "expired",
    ST_DEVICE_LIMIT: "device_limit",
    ST_SUSPENDED: "suspended",
    ST_QUOTA: "quota",
    ST_BUSY: "busy",
    ST_CLIENT_TOO_OLD: "client_too_old",
    ST_FORBIDDEN_HOST: "forbidden_host",
    ST_UPSTREAM: "upstream",
}


# ---- tokens ---------------------------------------------------------------

_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# The base32 alphabet contains no 0, 1 or 8, so mapping those to the glyphs
# they get confused with is unambiguous and always safe.
_CONFUSABLE = {"0": "O", "1": "I", "8": "B"}


def new_token():
    """A fresh 16-byte (128-bit) token."""
    return secrets.token_bytes(TOKEN_LEN)


def token_to_str(raw):
    """Human form: 26 base32 chars, hyphenated 13-13."""
    if len(raw) != TOKEN_LEN:
        raise ValueError("token must be %d bytes" % TOKEN_LEN)
    s = base64.b32encode(raw).decode("ascii").rstrip("=")
    return s[:13] + "-" + s[13:]


def token_from_str(text):
    """Parse a human-typed token. Tolerates spaces, hyphens, case and the
    0/O 1/I 8/B confusions. Raises ValueError on anything else."""
    if text is None:
        raise ValueError("empty token")
    cleaned = []
    for ch in text.strip().upper():
        if ch.isalnum():
            cleaned.append(_CONFUSABLE.get(ch, ch))
    s = "".join(cleaned)
    if len(s) != 26:
        raise ValueError("token must be 26 base32 characters, got %d" % len(s))
    for ch in s:
        if ch not in _B32_ALPHABET:
            raise ValueError("invalid character %r in token" % ch)
    raw = base64.b32decode(s + "======")
    if len(raw) != TOKEN_LEN:
        raise ValueError("decoded token is %d bytes" % len(raw))
    return raw


def token_hash(raw):
    """What the database stores. The secret itself is never persisted."""
    return hashlib.sha256(raw).digest()


# ---- setup code: one string the customer types into the app ---------------
#
#   host[:port][@ip]|TOKEN|CK
#
# e.g.  relay.example.com|A7K...|BMI3
#       relay.example.com:8443@203.0.113.10|A7K...|X2QF
#
# The optional :port lets a staging relay live beside a production one on the
# same certificate and hostname, and the optional @ip is an escape hatch for
# networks where DNS is poisoned. CK is a 4-character checksum, so a mistyped
# code fails immediately with "check the code" rather than failing to connect -
# which on this product is indistinguishable from "the relay is blocked here".

DEFAULT_PORT = 443


def setup_checksum(hostpart, token_str):
    digest = hashlib.sha256(("%s|%s" % (hostpart, token_str)).encode("utf-8")).digest()
    return base64.b32encode(digest).decode("ascii")[:4]


def build_setup_code(host, raw_token, ip=None, port=None):
    hostpart = host
    if port and int(port) != DEFAULT_PORT:
        hostpart = "%s:%d" % (hostpart, int(port))
    if ip:
        hostpart = "%s@%s" % (hostpart, ip)
    tok = token_to_str(raw_token)
    return "%s|%s|%s" % (hostpart, tok, setup_checksum(hostpart, tok))


def parse_setup_code(text):
    """(host, port, ip_or_None, raw_token). Raises ValueError with a message
    meant to be shown to a human."""
    parts = [p.strip() for p in (text or "").strip().split("|")]
    if len(parts) != 3:
        raise ValueError("setup code must look like host|TOKEN|CHECK")
    hostpart, tok, ck = parts
    if setup_checksum(hostpart, tok.upper()).upper() != ck.upper():
        raise ValueError("checksum mismatch - the code was mistyped")
    rest, _, ip = hostpart.partition("@")
    host, _, port = rest.partition(":")
    if not host:
        raise ValueError("missing host")
    return host, int(port) if port else DEFAULT_PORT, (ip or None), token_from_str(tok)


def token_prefix(raw):
    """Non-secret 6-char handle for logs and CLI lookups (30 bits)."""
    return base64.b32encode(raw).decode("ascii")[:6]


# ---- parsing --------------------------------------------------------------

def classify_prologue(head):
    """(version, byte4) for one of ours, or (None, None) for anything else.

    Callers treat (None, None) as 'not our client' and splice to the cover
    site, replaying these bytes verbatim.
    """
    if len(head) < PROLOGUE_LEN:
        return None, None
    if head[0:3] != MAGIC3:
        return None, None
    ver = head[3]
    if ver not in (VER_V1, VER_V2):
        return None, None
    return ver, head[4]


def parse_v2_body(body):
    """(token, device_id, ext_len). Raises ValueError if ext_len is absurd."""
    if len(body) != V2_BODY_LEN:
        raise ValueError("v2 body must be %d bytes" % V2_BODY_LEN)
    token = bytes(body[0:TOKEN_LEN])
    device = bytes(body[TOKEN_LEN:TOKEN_LEN + DEVICE_LEN])
    ext_len = int.from_bytes(body[TOKEN_LEN + DEVICE_LEN:], "big")
    if ext_len > MAX_EXT_LEN:
        raise ValueError("ext_len %d over limit" % ext_len)
    return token, device, ext_len


def parse_tlv(blob):
    """{type: value}. Truncated trailing entries are ignored rather than
    fatal, so a future client can add fields without breaking old servers."""
    out = {}
    i = 0
    n = len(blob)
    while i + 2 <= n:
        t = blob[i]
        ln = blob[i + 1]
        if i + 2 + ln > n:
            break
        out[t] = bytes(blob[i + 2:i + 2 + ln])
        i += 2 + ln
    return out


def build_tlv(items):
    """items: {type: bytes}."""
    out = bytearray()
    for t, v in sorted(items.items()):
        if len(v) > 255:
            raise ValueError("TLV 0x%02x too long" % t)
        out.append(t)
        out.append(len(v))
        out += v
    return bytes(out)


def build_v1_header(dc_id):
    return MAGIC3 + bytes([VER_V1, dc_id])


def build_v2_header(mode, token, device, ext=None):
    """The full client hello. Sent as one write so it lands in one TLS record."""
    if len(token) != TOKEN_LEN or len(device) != DEVICE_LEN:
        raise ValueError("bad token/device length")
    blob = build_tlv(ext or {})
    if len(blob) > MAX_EXT_LEN:
        raise ValueError("ext blob too long")
    return (MAGIC3 + bytes([VER_V2, mode]) + token + device
            + len(blob).to_bytes(2, "big") + blob)


def build_status(code, ttl_days=0, payload=None):
    """payload: dict -> JSON, or None for an empty body."""
    body = b""
    if payload:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_STATUS_PAYLOAD:
            raise ValueError("status payload too long")
    ttl = max(0, min(0xFFFF, int(ttl_days)))
    return (STATUS_MAGIC + bytes([code, 0]) + ttl.to_bytes(2, "big")
            + len(body).to_bytes(2, "big") + body)


def parse_status_header(buf):
    """(code, ttl_days, payload_len) from the first 10 bytes."""
    if len(buf) < STATUS_HDR_LEN or buf[0:4] != STATUS_MAGIC:
        raise ValueError("not a status frame")
    code = buf[4]
    ttl = int.from_bytes(buf[6:8], "big")
    plen = int.from_bytes(buf[8:10], "big")
    if plen > MAX_STATUS_PAYLOAD:
        raise ValueError("status payload_len %d over limit" % plen)
    return code, ttl, plen


def parse_status(buf):
    """(code, ttl_days, payload_dict) from a complete frame."""
    code, ttl, plen = parse_status_header(buf)
    body = buf[STATUS_HDR_LEN:STATUS_HDR_LEN + plen]
    if len(body) < plen:
        raise ValueError("status frame truncated")
    payload = {}
    if plen:
        payload = json.loads(body.decode("utf-8"))
    return code, ttl, payload
