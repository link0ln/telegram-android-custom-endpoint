"""Admin panel tests.

The panel is reachable over the same port the relay masks on, so the tests
that matter most are the negative ones: every request that does not carry the
secret path must reach the cover site byte for byte, exactly as it did before
the panel existed. If those ever need relaxing, the panel has become a way to
tell this domain apart from an ordinary web server.
"""

import os
import re
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import adminui              # noqa: E402
import store                # noqa: E402
import wire                 # noqa: E402

from test_e2e import COVER_BANNER, Harness, tls_connect   # noqa: E402


def ping_status(sock):
    """Read a MODE_PING answer. Unlike a data connection's bare ack, this one
    carries a JSON payload, so the header's length has to be drained too."""
    buf = b""
    while len(buf) < 10:
        chunk = sock.recv(10 - len(buf))
        if not chunk:
            break
        buf += chunk
    code, ttl, plen = wire.parse_status_header(buf)
    while plen > 0:
        chunk = sock.recv(plen)
        if not chunk:
            break
        plen -= len(chunk)
    return code


def http(sock, method, path, body=None, host="relay.test"):
    """One request, one response, connection closed by the server."""
    head = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, host)
    if body is not None:
        head += ("Content-Type: application/x-www-form-urlencoded\r\n"
                 "Content-Length: %d\r\n" % len(body))
    head += "\r\n"
    sock.sendall(head.encode("latin-1") + (body or "").encode("latin-1"))
    out = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        out += chunk
    return out


def status_of(raw):
    return raw.split(b"\r\n", 1)[0].decode("latin-1")


def location_of(raw):
    m = re.search(rb"\r\nLocation: ([^\r\n]+)", raw)
    return m.group(1).decode("latin-1") if m else None


class AdminTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        # Harness writes straight into os.environ, so anything set here would
        # leak into whichever suite runs next. Only what this suite needs.
        cls.h = Harness(cls.tmp, ADMIN_UI="1", RELAY_PUBLIC_HOST="relay.test",
                        RELAY_PUBLIC_PORT="8443")
        cls.port = cls.h.start()
        conn = store.connect(os.path.join(cls.tmp, "relay.db"))
        try:
            cls.secret = adminui.get_path(conn)
        finally:
            conn.close()
        cls.base = "/" + cls.secret

    @classmethod
    def tearDownClass(cls):
        cls.h.stop()

    # ---------------------------------------------------------- masking ----

    def test_wrong_path_is_the_cover_site_byte_for_byte(self):
        before = len(self.h.cover_seen)
        req = "GET /admin HTTP/1.1\r\nHost: relay.test\r\n\r\n"
        s = tls_connect(self.port)
        s.sendall(req.encode("latin-1"))
        out = b""
        while len(out) < len(COVER_BANNER):
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
        s.close()
        self.assertEqual(out, COVER_BANNER)
        self.assertEqual(bytes(self.h.cover_seen[before:]), req.encode("latin-1"),
                         "the cover site must receive an unmodified copy")

    def test_near_miss_path_is_masked(self):
        """One character off is as wrong as no path at all."""
        wrong = self.secret[:-1] + ("A" if self.secret[-1] != "A" else "B")
        s = tls_connect(self.port)
        out = http(s, "GET", "/" + wrong + "/")
        s.close()
        self.assertEqual(out, COVER_BANNER)

    def test_prefix_without_separator_is_masked(self):
        s = tls_connect(self.port)
        out = http(s, "GET", self.base + "extra")
        s.close()
        self.assertEqual(out, COVER_BANNER)

    def test_non_http_garbage_still_masked(self):
        s = tls_connect(self.port)
        s.sendall(b"\x00\x01\x02\x03\x04junk")
        out = s.recv(4096)
        s.close()
        self.assertEqual(out, COVER_BANNER)

    # ------------------------------------------------------------ panel ----

    def test_index_renders(self):
        s = tls_connect(self.port)
        out = http(s, "GET", self.base + "/")
        s.close()
        self.assertIn("200 OK", status_of(out))
        self.assertIn(b"Subscriptions", out)
        self.assertIn(b"Referrer-Policy: no-referrer", out)
        self.assertIn(b"Cache-Control: no-store", out)

    def test_page_loads_no_external_resource(self):
        """A single outbound request would leak the secret path in Referer."""
        s = tls_connect(self.port)
        out = http(s, "GET", self.base + "/")
        s.close()
        body = out.partition(b"\r\n\r\n")[2].decode("utf-8", "replace")
        for pattern in ("http://", "https://", "<script", "<img", "<link"):
            self.assertNotIn(pattern, body.lower(),
                             "panel must be self-contained: found %r" % pattern)

    def test_issue_then_the_code_works(self):
        s = tls_connect(self.port)
        body = urllib.parse.urlencode({"label": "web test", "days": "7",
                                       "devices": "2", "host": "relay.test",
                                       "port": "8443", "period": "none"})
        out = http(s, "POST", self.base + "/issue", body)
        s.close()
        self.assertIn("303", status_of(out))
        loc = location_of(out)
        self.assertIsNotNone(loc)

        s = tls_connect(self.port)
        page = http(s, "GET", loc)
        s.close()
        m = re.search(rb'<div class="code">([^<]+)</div>', page)
        self.assertIsNotNone(m, "the setup code must be shown once")
        code = m.group(1).decode("ascii").strip()

        host, port, ip, raw = wire.parse_setup_code(code)   # raises if malformed
        self.assertEqual((host, port, ip), ("relay.test", 8443, None))

        # and the relay must actually accept it
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(wire.MODE_PING, raw, b"\x11" * 16))
        self.assertEqual(ping_status(s), wire.ST_OK)
        s.close()

        # shown once: the same link must not produce it again
        s = tls_connect(self.port)
        again = http(s, "GET", loc)
        s.close()
        self.assertNotIn(code.encode("ascii"), again)

    def test_revoke_needs_confirmation_then_bites(self):
        conn = store.connect(os.path.join(self.tmp, "relay.db"))
        try:
            raw = wire.new_token()
            tid = store.create_token(conn, wire.token_hash(raw),
                                     wire.token_prefix(raw), 0, label="doomed")
            store.bump_gen(conn)
        finally:
            conn.close()
        self.h.call(__import__("mtrelay").reload_cache(force=True))

        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(wire.MODE_PING, raw, b"\x22" * 16))
        self.assertEqual(ping_status(s), wire.ST_OK)
        s.close()

        # wrong confirmation changes nothing
        s = tls_connect(self.port)
        http(s, "POST", self.base + "/revoke",
             urllib.parse.urlencode({"id": str(tid), "confirm": "nope"}))
        s.close()
        conn = store.connect(os.path.join(self.tmp, "relay.db"))
        try:
            self.assertEqual(store.find(conn, "#%d" % tid)["status"], "active")
        finally:
            conn.close()

        s = tls_connect(self.port)
        http(s, "POST", self.base + "/revoke",
             urllib.parse.urlencode({"id": str(tid), "confirm": "#%d" % tid}))
        s.close()

        conn = store.connect(os.path.join(self.tmp, "relay.db"))
        try:
            row = store.find(conn, "#%d" % tid)
            self.assertEqual(row["status"], "revoked")
            self.assertTrue(row["revoked_at"], "prune() keys on revoked_at")
        finally:
            conn.close()

        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(wire.MODE_PING, raw, b"\x22" * 16))
        self.assertEqual(ping_status(s), wire.ST_SUSPENDED)
        s.close()

    def test_rotating_the_path_closes_the_old_link(self):
        old = self.base
        conn = store.connect(os.path.join(self.tmp, "relay.db"))
        try:
            new = adminui.rotate_path(conn)
        finally:
            conn.close()
        self.addCleanup(self._restore_path, self.secret)

        # the relay caches the path at startup; a rotation is picked up the
        # same way relayctl delivers one - by signalling a reload
        self.h.call(self._reload_admin(new))

        s = tls_connect(self.port)
        out = http(s, "GET", old + "/")
        s.close()
        self.assertEqual(out, COVER_BANNER, "a rotated-away link must mask")

        s = tls_connect(self.port)
        out = http(s, "GET", "/" + new + "/")
        s.close()
        self.assertIn("200 OK", status_of(out))

    async def _reload_admin(self, new):
        __import__("mtrelay").ST.admin._secret = new

    def _restore_path(self, secret):
        conn = store.connect(os.path.join(self.tmp, "relay.db"))
        try:
            with conn:
                conn.execute("UPDATE schema_meta SET value=? WHERE key=?",
                             (secret, adminui.META_KEY))
        finally:
            conn.close()
        self.h.call(self._reload_admin(secret))


if __name__ == "__main__":
    unittest.main()
