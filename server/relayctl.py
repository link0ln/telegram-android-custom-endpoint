#!/usr/bin/env python3
"""relayctl - issue and manage subscriptions.

    python3 relayctl.py --db /data/relay.db issue --days 30 --label "alice"

A token is printed exactly once, at issue time, and never stored: the database
keeps only sha256(token) plus a 6-character non-secret prefix. If a customer
loses their code, rotate it - it cannot be recovered.

Most commands take <tok>, which accepts a full token, a unique prefix, or #id.
"""

import argparse
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import store
import wire

DEFAULT_DB = os.environ.get("RELAY_DB", "/data/relay.db")
DEFAULT_PIDFILE = os.environ.get("RELAY_PIDFILE", "/run/mtrelay.pid")


def actor():
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "unknown"


def human_ts(ts):
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + "Z"


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return "%.1f%s" % (n, unit) if unit != "B" else "%dB" % n
        n /= 1024


def parse_size(text):
    if text is None:
        return None
    t = str(text).strip().upper()
    mult = 1
    if t and t[-1] in "KMGT":
        mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[t[-1]]
        t = t[:-1]
    return int(float(t) * mult)


def notify_relay(conn, pidfile=DEFAULT_PIDFILE):
    """Bump the generation counter and poke the relay so a change takes effect
    in about a second instead of at the next scheduled reload."""
    gen = store.bump_gen(conn)
    try:
        with open(pidfile) as fh:
            pid = int(fh.read().strip())
        os.kill(pid, signal.SIGHUP)
        return gen, True
    except Exception:
        return gen, False


def cmd_initdb(args, conn):
    print("schema ready at %s (version %s)" % (args.db, store.SCHEMA_VERSION))


def cmd_issue(args, conn):
    raw = wire.new_token()
    expires = 0 if args.days == 0 else int(time.time()) + args.days * 86400
    tid = store.create_token(
        conn, wire.token_hash(raw), wire.token_prefix(raw), expires,
        label=args.label, plan=args.plan, device_limit=args.devices,
        conn_limit=args.conns, byte_quota=parse_size(args.quota) or 0,
        quota_period=args.period, tunnel_enabled=0 if args.no_tunnel else 1,
        note=args.note)
    store.audit(conn, actor(), "issue", tid,
                json.dumps({"days": args.days, "label": args.label}))
    notify_relay(conn, args.pidfile)
    code = wire.build_setup_code(args.host, raw, args.ip, args.port) if args.host else None
    print("token issued  id=#%d  prefix=%s  expires=%s"
          % (tid, wire.token_prefix(raw), human_ts(expires)))
    print("")
    print("  token:      %s" % wire.token_to_str(raw))
    if code:
        print("  setup code: %s" % code)
    print("")
    print("  ^ shown once and never stored - copy it now.")


def cmd_extend(args, conn):
    row = store.find(conn, args.token)
    base = max(int(time.time()), row["expires_at"] or 0)
    new = base + args.days * 86400
    store.update_token(conn, row["id"], expires_at=new)
    store.audit(conn, actor(), "extend", row["id"], json.dumps({"days": args.days}))
    notify_relay(conn, args.pidfile)
    print("#%d %s -> expires %s" % (row["id"], row["token_prefix"], human_ts(new)))


def cmd_setexp(args, conn):
    row = store.find(conn, args.token)
    ts = int(time.mktime(time.strptime(args.until, "%Y-%m-%d")))
    store.update_token(conn, row["id"], expires_at=ts)
    store.audit(conn, actor(), "setexp", row["id"], args.until)
    notify_relay(conn, args.pidfile)
    print("#%d %s -> expires %s" % (row["id"], row["token_prefix"], human_ts(ts)))


def cmd_rotate(args, conn):
    row = store.find(conn, args.token)
    raw = wire.new_token()
    store.update_token(conn, row["id"], token_hash=wire.token_hash(raw),
                       token_prefix=wire.token_prefix(raw))
    store.audit(conn, actor(), "rotate", row["id"], row["token_prefix"])
    notify_relay(conn, args.pidfile)
    print("#%d rotated: %s -> %s" % (row["id"], row["token_prefix"], wire.token_prefix(raw)))
    print("")
    print("  token:      %s" % wire.token_to_str(raw))
    if args.host:
        print("  setup code: %s" % wire.build_setup_code(args.host, raw, args.ip, args.port))
    print("")
    print("  the previous code stops working immediately.")


def _set_status(args, conn, status, action):
    row = store.find(conn, args.token)
    fields = {"status": status}
    if status == "revoked":
        fields["revoked_at"] = int(time.time())
    if getattr(args, "reason", None):
        fields["note"] = args.reason
    store.update_token(conn, row["id"], **fields)
    store.audit(conn, actor(), action, row["id"], getattr(args, "reason", "") or "")
    gen, poked = notify_relay(conn, args.pidfile)
    print("#%d %s -> %s%s" % (row["id"], row["token_prefix"], status,
                              "" if poked else "  (relay not signalled; takes effect at next reload)"))


def cmd_revoke(args, conn):
    _set_status(args, conn, "revoked", "revoke")
    print("note: the row is kept so the customer still gets a 'revoked' answer.")
    print("      'prune' deletes it later, after which the token is silently masked.")


def cmd_suspend(args, conn):
    _set_status(args, conn, "suspended", "suspend")


def cmd_resume(args, conn):
    _set_status(args, conn, "active", "resume")


def cmd_set(args, conn):
    row = store.find(conn, args.token)
    fields = {}
    if args.devices is not None:
        fields["device_limit"] = args.devices
    if args.conns is not None:
        fields["conn_limit"] = args.conns
    if args.quota is not None:
        fields["byte_quota"] = parse_size(args.quota)
    if args.period is not None:
        fields["quota_period"] = args.period
    if args.plan is not None:
        fields["plan"] = args.plan
    if args.label is not None:
        fields["label"] = args.label
    if args.note is not None:
        fields["note"] = args.note
    if args.tunnel is not None:
        fields["tunnel_enabled"] = 1 if args.tunnel == "on" else 0
    if not fields:
        print("nothing to change")
        return
    store.update_token(conn, row["id"], **fields)
    store.audit(conn, actor(), "set", row["id"], json.dumps(fields))
    notify_relay(conn, args.pidfile)
    print("#%d %s updated: %s" % (row["id"], row["token_prefix"],
                                  ", ".join("%s=%s" % kv for kv in fields.items())))


def cmd_list(args, conn):
    rows = store.list_tokens(conn, include_all=args.all, expiring_days=args.expiring)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if not rows:
        print("no tokens")
        return
    print("%-5s %-8s %-18s %-8s %-6s %-9s %s"
          % ("id", "prefix", "expires", "status", "dev", "plan", "label"))
    for r in rows:
        print("%-5s %-8s %-18s %-8s %-6s %-9s %s"
              % ("#%d" % r["id"], r["token_prefix"], human_ts(r["expires_at"]),
                 r["status"], r["device_limit"], r["plan"], r["label"]))


def cmd_show(args, conn):
    row = store.find(conn, args.token)
    devs = store.list_devices(conn, row["id"])
    use = store.usage(conn, row["id"], days=30)
    total = sum((u["bytes_up"] + u["bytes_down"]) for u in use)
    if args.json:
        print(json.dumps({"token": row, "devices": devs, "usage": use},
                         indent=2, default=str))
        return
    print("id            #%d" % row["id"])
    print("prefix        %s" % row["token_prefix"])
    print("label         %s" % row["label"])
    print("plan/status   %s / %s" % (row["plan"], row["status"]))
    print("created       %s" % human_ts(row["created_at"]))
    print("expires       %s" % human_ts(row["expires_at"]))
    print("devices       %d seen, limit %d" % (len(devs), row["device_limit"]))
    print("conn limit    %d" % row["conn_limit"])
    print("quota         %s / %s" % (human_bytes(row["byte_quota"]) if row["byte_quota"] else "unlimited",
                                     row["quota_period"]))
    print("tunnel        %s" % ("enabled" if row["tunnel_enabled"] else "disabled"))
    print("traffic 30d   %s" % human_bytes(total))
    if row["note"]:
        print("note          %s" % row["note"])
    for d in devs:
        print("  device %-16s last seen %s  %s"
              % (d["device_id"].hex()[:12], human_ts(d["last_seen"]),
                 human_bytes(d["bytes_up"] + d["bytes_down"])))


def cmd_usage(args, conn):
    row = store.find(conn, args.token)
    rows = store.usage(conn, row["id"], days=args.days)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return
    print("%-12s %10s %10s %6s %8s" % ("day", "up", "down", "conns", "rejects"))
    for r in rows:
        print("%-12s %10s %10s %6d %8d"
              % (r["day"], human_bytes(r["bytes_up"]), human_bytes(r["bytes_down"]),
                 r["conns"], r["rejects"]))


def cmd_devices(args, conn):
    row = store.find(conn, args.token)
    for d in store.list_devices(conn, row["id"]):
        print("%-16s first %s  last %s  conns %d  %s"
              % (d["device_id"].hex()[:16], human_ts(d["first_seen"]),
                 human_ts(d["last_seen"]), d["conns"],
                 human_bytes(d["bytes_up"] + d["bytes_down"])))


def cmd_forget_device(args, conn):
    row = store.find(conn, args.token)
    n = store.forget_device(conn, row["id"], bytes.fromhex(args.device))
    store.audit(conn, actor(), "forget-device", row["id"], args.device)
    notify_relay(conn, args.pidfile)
    print("removed %d device row(s)" % n)
    print("note: the in-memory presence slot frees itself after the grace window.")


def cmd_audit(args, conn):
    sql = "SELECT * FROM audit"
    params = []
    if args.token:
        row = store.find(conn, args.token)
        sql += " WHERE token_id=?"
        params.append(row["id"])
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(args.limit)
    for r in conn.execute(sql, params):
        print("%s %-10s %-14s %s %s"
              % (human_ts(r["ts"]), r["actor"], r["action"],
                 ("#%d" % r["token_id"]) if r["token_id"] else "-", r["detail"]))


def cmd_prune(args, conn):
    n = store.prune(conn, args.older_than)
    store.audit(conn, actor(), "prune", None, str(n))
    notify_relay(conn, args.pidfile)
    print("deleted %d revoked token(s)" % n)


def cmd_reload(args, conn):
    gen, poked = notify_relay(conn, args.pidfile)
    print("generation=%d, relay %s" % (gen, "signalled" if poked else "not running / no pidfile"))


def build_parser():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--pidfile", default=DEFAULT_PIDFILE)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("initdb").set_defaults(fn=cmd_initdb)

    q = sub.add_parser("issue", help="create a subscription")
    q.add_argument("--days", type=int, default=30, help="0 = never expires")
    q.add_argument("--label", default="")
    q.add_argument("--plan", default="basic")
    q.add_argument("--devices", type=int, default=2)
    q.add_argument("--conns", type=int, default=64)
    q.add_argument("--quota", default=None, help="e.g. 50G; omit for unlimited")
    q.add_argument("--period", default="none", choices=["none", "day", "month"])
    q.add_argument("--no-tunnel", action="store_true")
    q.add_argument("--note", default="")
    q.add_argument("--host", default=os.environ.get("RELAY_PUBLIC_HOST", ""),
                   help="relay hostname, to print a ready-to-type setup code")
    q.add_argument("--ip", default=None, help="pin an IP into the setup code")
    q.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PUBLIC_PORT", "443")),
                   help="public port, if not 443 (lets staging sit beside production)")
    q.set_defaults(fn=cmd_issue)

    q = sub.add_parser("extend"); q.add_argument("token"); q.add_argument("--days", type=int, required=True); q.set_defaults(fn=cmd_extend)
    q = sub.add_parser("setexp"); q.add_argument("token"); q.add_argument("--until", required=True, help="YYYY-MM-DD"); q.set_defaults(fn=cmd_setexp)
    q = sub.add_parser("rotate"); q.add_argument("token"); q.add_argument("--host", default=os.environ.get("RELAY_PUBLIC_HOST", "")); q.add_argument("--ip", default=None); q.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PUBLIC_PORT", "443"))); q.set_defaults(fn=cmd_rotate)
    q = sub.add_parser("revoke"); q.add_argument("token"); q.add_argument("--reason", default=""); q.set_defaults(fn=cmd_revoke)
    q = sub.add_parser("suspend"); q.add_argument("token"); q.add_argument("--reason", default=""); q.set_defaults(fn=cmd_suspend)
    q = sub.add_parser("resume"); q.add_argument("token"); q.set_defaults(fn=cmd_resume)

    q = sub.add_parser("set"); q.add_argument("token")
    q.add_argument("--devices", type=int); q.add_argument("--conns", type=int)
    q.add_argument("--quota"); q.add_argument("--period", choices=["none", "day", "month"])
    q.add_argument("--plan"); q.add_argument("--label"); q.add_argument("--note")
    q.add_argument("--tunnel", choices=["on", "off"]); q.set_defaults(fn=cmd_set)

    q = sub.add_parser("list"); q.add_argument("--all", action="store_true")
    q.add_argument("--expiring", type=int, default=None); q.add_argument("--json", action="store_true")
    q.set_defaults(fn=cmd_list)

    q = sub.add_parser("show"); q.add_argument("token"); q.add_argument("--json", action="store_true"); q.set_defaults(fn=cmd_show)
    q = sub.add_parser("usage"); q.add_argument("token"); q.add_argument("--days", type=int, default=30); q.add_argument("--json", action="store_true"); q.set_defaults(fn=cmd_usage)
    q = sub.add_parser("devices"); q.add_argument("token"); q.set_defaults(fn=cmd_devices)
    q = sub.add_parser("forget-device"); q.add_argument("token"); q.add_argument("device", help="hex device id"); q.set_defaults(fn=cmd_forget_device)
    q = sub.add_parser("audit"); q.add_argument("--token", default=None); q.add_argument("--limit", type=int, default=50); q.set_defaults(fn=cmd_audit)
    q = sub.add_parser("prune"); q.add_argument("--older-than", type=int, default=30); q.set_defaults(fn=cmd_prune)
    sub.add_parser("reload").set_defaults(fn=cmd_reload)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    conn = store.init_db(args.db)
    try:
        args.fn(args, conn)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
