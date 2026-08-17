"""Subscription admin, served from inside the relay on an unguessable path.

Why it lives here and not behind a normal web server: this process already
answers anything it does not recognise by replaying it to the cover site, byte
for byte. Hanging the panel off that same decision means a wrong URL is not a
404 and not a login form - it is the cover site, identical to what a domain
with no panel at all would return. There is nothing for a scanner to find.

The path is the only credential. That is a deliberate operator choice, so the
things that cost nothing are done anyway:

  * 32 characters from os.urandom, compared with hmac.compare_digest;
  * every response sends Referrer-Policy: no-referrer, and the page loads no
    external resource whatsoever, so the path cannot leak through an outbound
    request the browser makes on our behalf;
  * Cache-Control: no-store, so it does not linger in a shared cache;
  * a Content-Security-Policy that forbids everything except the page's own
    inline stylesheet and same-origin form posts;
  * every mutation goes to the audit log with actor "web";
  * `relayctl adminurl --rotate` invalidates a leaked link in one command.

Issued tokens are shown exactly once, as they are on the CLI - the database
keeps only a SHA-256, so a panel cannot show them again even if asked.
"""

import base64
import calendar
import hmac
import html
import json
import os
import time
import urllib.parse

import store
import wire

MAX_HEADER = 16384
MAX_BODY = 65536
HTTP_METHODS = (b"GET /", b"POST ", b"HEAD /")

META_KEY = "admin_path"
PATH_BYTES = 20            # -> 32 base32 characters

# Setup codes handed back after issue/rotate. The database cannot show a token
# twice, so the value lives here for one read: the POST redirects to a GET
# carrying only this opaque id, which keeps the token out of the URL, out of
# browser history, and out of a page that a refresh would re-submit.
_ONESHOT = {}
_ONESHOT_TTL = 300


# ------------------------------------------------------------ secret path ---

def _gen_path():
    return base64.b32encode(os.urandom(PATH_BYTES)).decode("ascii").rstrip("=")


def get_path(conn, create=True):
    row = conn.execute("SELECT value FROM schema_meta WHERE key=?",
                       (META_KEY,)).fetchone()
    if row and row["value"]:
        return row["value"]
    if not create:
        return None
    return rotate_path(conn)


def rotate_path(conn):
    value = _gen_path()
    with conn:
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (META_KEY, value))
    return value


def public_url(host, port, path):
    base = host if port == 443 else "%s:%d" % (host, port)
    return "https://%s/%s/" % (base, path)


# -------------------------------------------------------------- http bits ---

def looks_like_http(prologue):
    """Could these 5 bytes begin a request we should look at?

    Deliberately narrow. Everything else goes to the cover site without us
    having read one byte more than the relay reads from any other peer.
    """
    return prologue[:5] in HTTP_METHODS


def _parse_request(raw):
    """(method, path, query, headers) or None if the head is malformed."""
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return None
    try:
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) < 2:
            return None
        method, target = parts[0], parts[1]
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.decode("latin-1").partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
    except Exception:
        return None
    path, _, query = target.partition("?")
    return method, urllib.parse.unquote(path), query, headers


def _match_secret(path, secret):
    """Constant-time prefix check. Returns the remainder, or None."""
    want = "/" + secret
    if len(path) < len(want):
        return None
    if not hmac.compare_digest(path[:len(want)], want):
        return None
    rest = path[len(want):]
    if rest and not rest.startswith("/"):
        return None
    return rest or "/"


def _response(status, body, ctype="text/html; charset=utf-8", extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    lines = [
        "HTTP/1.1 %s" % status,
        "Content-Type: %s" % ctype,
        "Content-Length: %d" % len(body),
        "Connection: close",
        "Cache-Control: no-store, max-age=0",
        "Referrer-Policy: no-referrer",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ]
    for k, v in (extra or {}).items():
        lines.append("%s: %s" % (k, v))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def _redirect(location):
    return _response("303 See Other", b"", extra={"Location": location})


# ------------------------------------------------------------- rendering ---

CSS = """
:root { color-scheme: light dark;
  --bg:#fff; --fg:#111; --dim:#666; --line:#dcdcdc; --card:#f7f7f7;
  --accent:#0a58ca; --bad:#b3261e; --good:#186a3b; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#15181c; --fg:#e6e6e6; --dim:#9aa0a6; --line:#333a42; --card:#1d2126;
  --accent:#7aa7ff; --bad:#ef9a93; --good:#7ddba4; } }
* { box-sizing:border-box }
body { margin:0; padding:16px; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
main { max-width:900px; margin:0 auto }
h1 { font-size:19px; margin:0 0 4px }
h2 { font-size:16px; margin:28px 0 8px; padding-bottom:6px;
  border-bottom:1px solid var(--line) }
a { color:var(--accent) }
.sub { color:var(--dim); font-size:13px; margin:0 0 20px }
table { width:100%; border-collapse:collapse; font-size:14px }
th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
  vertical-align:top }
th { color:var(--dim); font-weight:600; font-size:12px; text-transform:uppercase;
  letter-spacing:.04em }
td.num { text-align:right; font-variant-numeric:tabular-nums }
.wrap { overflow-x:auto; -webkit-overflow-scrolling:touch }
code,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace }
.pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px;
  border:1px solid var(--line) }
.ok { color:var(--good) } .no { color:var(--bad) }
form.inline { display:inline }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:14px; margin:12px 0 }
label { display:block; font-size:12px; color:var(--dim); margin:10px 0 3px }
input,select { width:100%; padding:9px 10px; font:inherit; color:var(--fg);
  background:var(--bg); border:1px solid var(--line); border-radius:8px }
button { padding:9px 14px; font:inherit; border-radius:8px; cursor:pointer;
  border:1px solid var(--line); background:var(--card); color:var(--fg) }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff }
button.danger { color:var(--bad) }
.row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end }
.row > div { flex:1 1 150px }
.code { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:12px; word-break:break-all; font-family:ui-monospace,Menlo,Consolas,
  monospace; font-size:15px; -webkit-user-select:all; user-select:all }
.warn { border-left:3px solid var(--bad); padding-left:10px; color:var(--dim);
  font-size:13px }
"""


def _page(title, body, base):
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>%s</title><style>%s</style></head><body><main>
<h1>%s</h1><p class="sub"><a href="%s">subscriptions</a></p>
%s</main></body></html>""" % (html.escape(title), CSS, html.escape(title), base, body)


def _esc(v):
    return html.escape("" if v is None else str(v))


def _ts(v):
    if not v:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(v)) + "Z"


def _bytes(n):
    n = float(n or 0)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return "%dB" % n if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024


def _state_of(row):
    if row["status"] != "active":
        return row["status"], "no"
    exp = row["expires_at"] or 0
    if exp and exp <= time.time():
        return "expired", "no"
    if exp:
        days = int((exp - time.time()) // 86400)
        if days <= 3:
            return "%dd left" % days, "no"
        return "%dd left" % days, "ok"
    return "no expiry", "ok"


# --------------------------------------------------------------- handlers ---

def _index(conn, deps, base, shown):
    out = []

    if shown:
        out.append('<div class="card"><h2 style="margin-top:0">New setup code</h2>'
                   '<p class="sub">Shown once. The server keeps only a hash.</p>'
                   '<div class="code">%s</div>'
                   '<p class="warn">Copy it now - reopening this page will not '
                   'show it again.</p></div>' % _esc(shown))

    rows = store.list_tokens(conn, include_all=True)
    live = deps.live_conns()
    out.append('<h2>Subscriptions</h2><div class="wrap"><table>'
               "<tr><th>id</th><th>prefix</th><th>label</th><th>state</th>"
               "<th>expires</th><th class='num'>dev</th><th class='num'>live</th></tr>")
    for r in rows:
        state, cls = _state_of(r)
        out.append(
            "<tr><td><a href='%s/sub/%d'>#%d</a></td><td class='mono'>%s</td>"
            "<td>%s</td><td class='%s'>%s</td><td>%s</td>"
            "<td class='num'>%d</td><td class='num'>%d</td></tr>"
            % (base, r["id"], r["id"], _esc(r["token_prefix"]), _esc(r["label"]),
               cls, _esc(state), _ts(r["expires_at"]), r["device_limit"],
               live.get(r["id"], 0)))
    out.append("</table></div>")

    out.append("""
<h2>Issue a subscription</h2>
<form method="post" action="%s/issue" class="card">
  <div class="row">
    <div><label>label</label><input name="label" placeholder="who this is for"></div>
    <div><label>days (0 = no expiry)</label><input name="days" value="30" inputmode="numeric"></div>
    <div><label>devices</label><input name="devices" value="2" inputmode="numeric"></div>
  </div>
  <div class="row">
    <div><label>host</label><input name="host" value="%s"></div>
    <div><label>port</label><input name="port" value="%d" inputmode="numeric"></div>
    <div><label>pinned ip (optional)</label><input name="ip" placeholder="skip a DNS lookup"></div>
  </div>
  <div class="row">
    <div><label>quota (e.g. 50G, blank = none)</label><input name="quota"></div>
    <div><label>quota period</label><select name="period">
      <option value="none">none</option><option value="day">day</option>
      <option value="month">month</option></select></div>
    <div><label>note</label><input name="note"></div>
  </div>
  <p><button class="primary" type="submit">Issue</button></p>
</form>
<h2>Maintenance</h2>
<div class="card">
  <form method="post" action="%s/reload" class="inline">
    <button type="submit">Reload cache now</button></form>
  <form method="post" action="%s/prune" class="inline">
    <button type="submit">Prune revoked &gt; 30d</button></form>
</div>""" % (base, _esc(deps.public_host), deps.public_port, base, base))

    return _page("Relay admin", "".join(out), base)


def _detail(conn, deps, base, tid):
    row = store.find(conn, "#%d" % tid)
    state, cls = _state_of(row)
    live = deps.live_conns().get(row["id"], 0)
    out = []

    out.append('<h2>#%d %s <span class="pill %s">%s</span></h2>'
               % (row["id"], _esc(row["token_prefix"]), cls, _esc(state)))
    out.append('<div class="wrap"><table>')
    for k, v in (("label", row["label"]), ("plan", row["plan"]),
                 ("created", _ts(row["created_at"])),
                 ("expires", _ts(row["expires_at"])),
                 ("status", row["status"]),
                 ("device limit", row["device_limit"]),
                 ("conn limit", row["conn_limit"]),
                 ("quota", "%s / %s" % (_bytes(row["byte_quota"]) if row["byte_quota"]
                                        else "none", row["quota_period"])),
                 ("tunnel", "yes" if row["tunnel_enabled"] else "no"),
                 ("live connections", live), ("note", row["note"])):
        out.append("<tr><th>%s</th><td>%s</td></tr>" % (_esc(k), _esc(v)))
    out.append("</table></div>")

    out.append("""
<h2>Change</h2>
<div class="card">
  <form method="post" action="%s/extend">
    <input type="hidden" name="id" value="%d">
    <div class="row"><div><label>extend by days</label>
      <input name="days" value="30" inputmode="numeric"></div>
      <div style="flex:0 0 auto"><button class="primary" type="submit">Extend</button></div>
    </div>
  </form>
  <form method="post" action="%s/setexp">
    <input type="hidden" name="id" value="%d">
    <div class="row"><div><label>or set expiry (YYYY-MM-DD, UTC)</label>
      <input name="until" placeholder="2027-01-31"></div>
      <div style="flex:0 0 auto"><button type="submit">Set</button></div>
    </div>
  </form>
  <form method="post" action="%s/set">
    <input type="hidden" name="id" value="%d">
    <div class="row">
      <div><label>label</label><input name="label" value="%s"></div>
      <div><label>devices</label><input name="devices" value="%d" inputmode="numeric"></div>
      <div><label>conns</label><input name="conns" value="%d" inputmode="numeric"></div>
    </div>
    <div class="row">
      <div><label>quota (blank = unchanged, 0 = none)</label><input name="quota"></div>
      <div><label>period</label><select name="period">%s</select></div>
      <div><label>tunnel</label><select name="tunnel">%s</select></div>
    </div>
    <p><button type="submit">Save</button></p>
  </form>
</div>

<h2>Access</h2>
<div class="card">
  <form method="post" action="%s/suspend" class="inline">
    <input type="hidden" name="id" value="%d">
    <button type="submit">Suspend</button></form>
  <form method="post" action="%s/resume" class="inline">
    <input type="hidden" name="id" value="%d">
    <button type="submit">Resume</button></form>
  <form method="post" action="%s/kick" class="inline">
    <input type="hidden" name="id" value="%d">
    <button type="submit">Drop live connections</button></form>
  <form method="post" action="%s/rotate" class="inline">
    <input type="hidden" name="id" value="%d">
    <button type="submit">Rotate token</button></form>
  <p class="warn">Rotating issues a new code and invalidates the old one
    immediately. Revoking is permanent - the subscription keeps answering
    "revoked" for 30 days so the client can be told why, then prune removes it.</p>
  <form method="post" action="%s/revoke">
    <input type="hidden" name="id" value="%d">
    <div class="row"><div><label>type the id (#%d) to confirm</label>
      <input name="confirm" placeholder="#%d"></div>
      <div style="flex:0 0 auto"><button class="danger" type="submit">Revoke</button></div>
    </div>
  </form>
</div>""" % (base, tid, base, tid, base, tid, _esc(row["label"]),
             row["device_limit"], row["conn_limit"],
             "".join("<option value='%s'%s>%s</option>"
                     % (p, " selected" if row["quota_period"] == p else "", p)
                     for p in ("none", "day", "month")),
             "".join("<option value='%s'%s>%s</option>"
                     % (v, " selected" if row["tunnel_enabled"] == int(v) else "", n)
                     for v, n in (("1", "yes"), ("0", "no"))),
             base, tid, base, tid, base, tid, base, tid, base, tid, tid, tid))

    devs = store.list_devices(conn, row["id"])
    out.append("<h2>Devices</h2>")
    if not devs:
        out.append('<p class="sub">None seen yet.</p>')
    else:
        out.append('<div class="wrap"><table><tr><th>device</th><th>first seen</th>'
                   "<th>last seen</th><th class='num'>bytes</th><th></th></tr>")
        for d in devs:
            did = d["device_id"].hex()      # stored as a BLOB, shown as hex
            out.append(
                "<tr><td class='mono'>%s</td><td>%s</td><td>%s</td>"
                "<td class='num'>%s</td><td>"
                "<form method='post' action='%s/forget-device' class='inline'>"
                "<input type='hidden' name='id' value='%d'>"
                "<input type='hidden' name='device' value='%s'>"
                "<button type='submit'>Forget</button></form></td></tr>"
                % (_esc(did), _ts(d["first_seen"]), _ts(d["last_seen"]),
                   _bytes((d["bytes_up"] or 0) + (d["bytes_down"] or 0)),
                   base, tid, _esc(did)))
        out.append("</table></div>")

    rows = store.usage(conn, row["id"], days=30)
    out.append("<h2>Usage, 30 days</h2>")
    if not rows:
        out.append('<p class="sub">Nothing recorded.</p>')
    else:
        out.append('<div class="wrap"><table><tr><th>day</th><th class="num">up</th>'
                   '<th class="num">down</th><th class="num">conns</th>'
                   '<th class="num">rejects</th></tr>')
        for u in rows:
            out.append("<tr><td>%s</td><td class='num'>%s</td><td class='num'>%s</td>"
                       "<td class='num'>%d</td><td class='num'>%d</td></tr>"
                       % (_esc(u["day"]), _bytes(u["bytes_up"]), _bytes(u["bytes_down"]),
                          u["conns"] or 0, u["rejects"] or 0))
        out.append("</table></div>")

    return _page("#%d %s" % (row["id"], row["token_prefix"]), "".join(out), base)


def _audit_page(conn, base, limit=100):
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]
    out = ['<h2>Audit</h2><div class="wrap"><table>'
           "<tr><th>when</th><th>actor</th><th>action</th><th>token</th><th>detail</th></tr>"]
    for r in rows:
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                   "<td class='mono'>%s</td></tr>"
                   % (_ts(r["ts"]), _esc(r["actor"]), _esc(r["action"]),
                      ("#%d" % r["token_id"]) if r["token_id"] else "",
                      _esc((r["detail"] or "")[:160])))
    out.append("</table></div>")
    return _page("Audit", "".join(out), base)


# ----------------------------------------------------------------- actions --

def _int(form, name, default=0):
    try:
        return int((form.get(name) or [""])[0].strip())
    except (ValueError, TypeError):
        return default


def _str(form, name, default=""):
    return (form.get(name) or [default])[0].strip()


def _parse_size(text):
    t = (text or "").strip().upper()
    if not t:
        return None
    mult = 1
    if t[-1] in "KMGT":
        mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[t[-1]]
        t = t[:-1]
    try:
        return int(float(t) * mult)
    except ValueError:
        return None


def _oneshot_put(value):
    now = time.time()
    for k in [k for k, (_, exp) in _ONESHOT.items() if exp < now]:
        _ONESHOT.pop(k, None)
    key = base64.urlsafe_b64encode(os.urandom(9)).decode("ascii").rstrip("=")
    _ONESHOT[key] = (value, now + _ONESHOT_TTL)
    return key


def _oneshot_take(key):
    item = _ONESHOT.pop(key, None)
    if not item:
        return None
    value, exp = item
    return value if exp >= time.time() else None


def _do_action(conn, deps, base, action, form):
    """Returns a Location to redirect to."""
    home = base + "/"

    if action == "issue":
        days = _int(form, "days", 30)
        raw = wire.new_token()
        expires = 0 if days == 0 else int(time.time()) + days * 86400
        tid = store.create_token(
            conn, wire.token_hash(raw), wire.token_prefix(raw), expires,
            label=_str(form, "label"), plan="basic",
            device_limit=max(1, _int(form, "devices", 2)),
            conn_limit=64, byte_quota=_parse_size(_str(form, "quota")) or 0,
            quota_period=_str(form, "period", "none") or "none",
            tunnel_enabled=1, note=_str(form, "note"))
        store.audit(conn, "web", "issue", tid,
                    json.dumps({"days": days, "label": _str(form, "label")}))
        host = _str(form, "host") or deps.public_host
        port = _int(form, "port", deps.public_port) or 443
        code = wire.build_setup_code(host, raw, _str(form, "ip") or None, port)
        deps.reload()
        return home + "?shown=" + _oneshot_put(code)

    tid = _int(form, "id")
    row = store.find(conn, "#%d" % tid)
    here = "%s/sub/%d" % (base, tid)

    if action == "extend":
        days = _int(form, "days", 0)
        if days:
            base_ts = max(int(time.time()), row["expires_at"] or 0)
            store.update_token(conn, tid, expires_at=base_ts + days * 86400)
            store.audit(conn, "web", "extend", tid, json.dumps({"days": days}))

    elif action == "setexp":
        until = _str(form, "until")
        try:
            # UTC, matching relayctl and every date this project prints. Local
            # time here would silently shift every expiry by the server's offset.
            ts = calendar.timegm(time.strptime(until, "%Y-%m-%d"))
            store.update_token(conn, tid, expires_at=ts)
            store.audit(conn, "web", "setexp", tid, json.dumps({"until": until}))
        except ValueError:
            pass

    elif action == "set":
        fields = {"label": _str(form, "label"),
                  "device_limit": max(1, _int(form, "devices", row["device_limit"])),
                  "conn_limit": max(1, _int(form, "conns", row["conn_limit"])),
                  "quota_period": _str(form, "period", row["quota_period"]),
                  "tunnel_enabled": 1 if _str(form, "tunnel", "1") == "1" else 0}
        quota = _parse_size(_str(form, "quota"))
        if quota is not None:
            fields["byte_quota"] = quota
        store.update_token(conn, tid, **fields)
        store.audit(conn, "web", "set", tid, json.dumps(fields))

    elif action in ("suspend", "resume"):
        store.update_token(conn, tid,
                           status="suspended" if action == "suspend" else "active")
        store.audit(conn, "web", action, tid, "")

    elif action == "revoke":
        if _str(form, "confirm").lstrip("#") != str(tid):
            return here + "?err=confirm"
        # revoked_at is what prune() keys on; without it the row would answer
        # "revoked" forever and never age out.
        store.update_token(conn, tid, status="revoked",
                           revoked_at=int(time.time()))
        store.audit(conn, "web", "revoke", tid, "")

    elif action == "rotate":
        raw = wire.new_token()
        store.update_token(conn, tid, token_hash=wire.token_hash(raw),
                           token_prefix=wire.token_prefix(raw))
        store.audit(conn, "web", "rotate", tid, "")
        code = wire.build_setup_code(deps.public_host, raw, None, deps.public_port)
        deps.reload()
        return home + "?shown=" + _oneshot_put(code)

    elif action == "forget-device":
        dev = _str(form, "device")
        try:
            store.forget_device(conn, tid, bytes.fromhex(dev))
            store.audit(conn, "web", "forget-device", tid,
                        json.dumps({"device": dev[:8]}))
        except ValueError:
            pass

    elif action == "kick":
        n = deps.kill(tid, "admin")
        store.audit(conn, "web", "kick", tid, json.dumps({"conns": n}))
        return here

    deps.reload()
    return here


def _do_global(conn, deps, base, action):
    if action == "prune":
        n = store.prune(conn, older_than_days=30)
        store.audit(conn, "web", "prune", None, json.dumps({"removed": n}))
    deps.reload()
    return base + "/"


# ------------------------------------------------------------ entry point ---

async def try_serve(reader, writer, peeked, deadline, deps, read_into):
    """Handle an admin request, or return False so the caller masks it.

    Everything consumed lands in `peeked`, so bailing out still leaves the
    cover path able to replay a byte-exact copy of what the peer sent.
    """
    while b"\r\n\r\n" not in bytes(peeked):
        if len(peeked) >= MAX_HEADER:
            return False
        if not await read_into(reader, 1, peeked, deadline):
            return False

    raw = bytes(peeked)
    parsed = _parse_request(raw)
    if parsed is None:
        return False
    method, path, query, headers = parsed

    secret = deps.secret()
    if not secret:
        return False
    rest = _match_secret(path, secret)
    if rest is None:
        return False

    # From here the caller has proved it knows the path, so a distinguishable
    # answer costs nothing.
    if method == "POST":
        origin = headers.get("origin")
        if origin:
            want = urllib.parse.urlsplit(origin).netloc.lower()
            if want and want != (headers.get("host") or "").lower():
                writer.write(_response("403 Forbidden", b"cross-origin"))
                await writer.drain()
                return True
        length = min(int(headers.get("content-length") or 0), MAX_BODY)
        body = raw.partition(b"\r\n\r\n")[2]
        while len(body) < length:
            before = len(peeked)
            if not await read_into(reader, length - len(body), peeked, deadline):
                break
            body += bytes(peeked[before:])
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    else:
        form = {}

    out = await deps.run_db(_dispatch, deps, method, rest, query, form)
    writer.write(out)
    await writer.drain()
    return True


def _dispatch(conn, deps, method, rest, query, form):
    """Runs on a worker thread with its own sqlite connection."""
    base = "/" + deps.secret()
    try:
        if method == "POST":
            act = rest.strip("/")
            if act in ("prune", "reload"):
                return _redirect(_do_global(conn, deps, base, act))
            return _redirect(_do_action(conn, deps, base, act, form))

        if rest.startswith("/sub/"):
            return _response("200 OK", _detail(conn, deps, base, int(rest[5:].strip("/"))))
        if rest.rstrip("/") == "/audit":
            return _response("200 OK", _audit_page(conn, base))

        shown = None
        q = urllib.parse.parse_qs(query)
        if q.get("shown"):
            shown = _oneshot_take(q["shown"][0])
        return _response("200 OK", _index(conn, deps, base, shown))
    except ValueError as exc:
        return _response("404 Not Found", _page("Not found", "<p>%s</p>" % _esc(exc),
                                                base))
    except Exception as exc:                       # keep the panel from 500-ing silently
        return _response("500 Server Error",
                         _page("Error", "<p class='no'>%s</p>" % _esc(repr(exc)[:300]),
                               base))
