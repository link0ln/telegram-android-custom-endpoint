#!/usr/bin/env python3
"""mtrelay - a TLS relay that fronts Telegram behind an ordinary HTTPS domain.

A patched Telegram client opens a genuine TLS connection here and announces
itself with a small header sent inside the TLS session. Recognised clients are
forwarded to the Telegram datacenter they ask for; everything else - a browser,
a port scanner, a censor's active probe - is spliced verbatim to a cover
website, so from the outside this host is indistinguishable from the site it
fronts.

Subscription enforcement lives here and nowhere else. The client is GPL and
public, so anyone can rebuild it without a licence check; what they cannot do
is make this process carry their traffic without a token it already knows.

Two properties are load-bearing and easy to break by accident:

  * The unconditional read is exactly 5 bytes. Reading more before the magic
    matches would stall on short probes and make this server behave unlike the
    site it pretends to be.
  * An unknown token takes the same code path, at the same speed, as random
    garbage: a dict lookup, then the cover site. Nothing is ever written back.
    Any database call or extra await on that path would create a timing oracle
    that lets a censor distinguish this host.

stdlib only, no pip dependencies. See .env.example for configuration.
"""

import asyncio
import os
import signal
import socket
import ssl
import time

try:                      # Unix only; absent on a Windows dev box
    import resource
except ImportError:
    resource = None

import authcache
import rlog
import store
import tunnel
import wire


# ---------------------------------------------------------------- config ----

class Cfg(object):
    pass


def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def load_cfg():
    c = Cfg()
    c.host = os.environ.get("RELAY_LISTEN_HOST", "0.0.0.0")
    c.port = _env_int("RELAY_LISTEN_PORT", 443)
    c.cert = os.environ.get("RELAY_CERT", "/certs/fullchain.pem")
    c.key = os.environ.get("RELAY_KEY", "/certs/privkey.pem")
    c.db = os.environ.get("RELAY_DB", "/data/relay.db")
    c.pidfile = os.environ.get("RELAY_PIDFILE", "/run/mtrelay.pid")
    c.mask_host = os.environ.get("MASK_HOST", "")
    c.mask_port = _env_int("MASK_PORT", 0)
    # v1 is the token-less legacy header. Self-hosters keep working by default;
    # a paid deployment sets ALLOW_V1=0.
    c.allow_v1 = os.environ.get("ALLOW_V1", "1") not in ("0", "false", "no")
    c.header_timeout = _env_int("HEADER_TIMEOUT", 20)
    c.body_timeout = _env_int("BODY_TIMEOUT", 5)
    c.tls_handshake_timeout = _env_int("TLS_HANDSHAKE_TIMEOUT", 10)
    c.upstream_timeout = _env_int("UPSTREAM_TIMEOUT", 8)
    c.auth_reload_sec = _env_int("AUTH_RELOAD_SEC", 15)
    c.meter_flush_sec = _env_int("METER_FLUSH_SEC", 30)
    c.sweep_sec = _env_int("SWEEP_SEC", 10)
    c.device_grace = _env_int("DEVICE_GRACE_SEC", 180)
    c.device_policy = os.environ.get("DEVICE_POLICY", authcache.POLICY_STRICT)
    c.max_conns = _env_int("MAX_CONNS", 8192)
    c.log_ip = os.environ.get("LOG_IP", rlog.MODE_PREFIX)
    c.renew_hint = os.environ.get("RENEW_HINT", "")
    c.dc = {
        1: os.environ.get("DC1", "149.154.175.50"),
        2: os.environ.get("DC2", "149.154.167.51"),
        3: os.environ.get("DC3", "149.154.175.100"),
        4: os.environ.get("DC4", "149.154.167.91"),
        5: os.environ.get("DC5", "149.154.171.5"),
    }
    c.dc_port = _env_int("DC_PORT", 443)
    return c


class Runtime(object):
    def __init__(self):
        self.cfg = None
        self.state = None
        self.limits = None
        self.resolver = None
        self.conn_seq = 0
        self.local_addrs = set()

    def next_id(self):
        self.conn_seq += 1
        return self.conn_seq


ST = Runtime()


# ------------------------------------------------------------- transport ----

async def _read_into(reader, n, peeked, deadline):
    """Read exactly n more bytes, appending everything consumed to `peeked`.

    Bytes land in `peeked` even on timeout or EOF, which is what lets the cover
    path replay a byte-exact copy of whatever the peer sent. readexactly() will
    not do: on IncompleteReadError it returns the bytes only via .partial, and
    on a wait_for timeout they are stranded in a private buffer - both leave
    the mask replay short, which is itself a fingerprint.
    """
    need = n
    while need > 0:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            chunk = await asyncio.wait_for(reader.read(need), remaining)
        except Exception:
            return False
        if not chunk:
            return False
        peeked += chunk
        need -= len(chunk)
    return True


async def splice(reader, writer, on_bytes):
    """Pump one direction. Returns (bytes_moved, error_or_None).

    Deliberately does not close `writer`: closing it here means whichever
    direction ends first tears down the socket the other direction is still
    writing into, truncating in-flight data. Closing is the caller's job, once,
    after both directions are done.
    """
    total = 0
    err = None
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            total += len(data)
            if on_bytes is not None:
                on_bytes(len(data))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        err = exc
    finally:
        try:
            if writer.can_write_eof():   # False on asyncio's TLS transports
                writer.write_eof()
        except Exception:
            pass
    return total, err


def _close(writer):
    try:
        writer.close()
    except Exception:
        pass


async def _aclose(writer):
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 5)
    except Exception:
        pass


async def _send_status(writer, code, ttl_days=0, payload=None, close=True):
    """Answer a client we already recognise. Unreachable for an unknown token,
    which is what keeps this from being a probing oracle."""
    try:
        writer.write(wire.build_status(code, ttl_days, payload))
        await writer.drain()
    except Exception:
        pass
    if close:
        await _aclose(writer)


async def _mask(client_reader, client_writer, peeked, conn_id, ip):
    """Behave like the cover site: replay every byte consumed, then splice."""
    cfg = ST.cfg
    if not (cfg.mask_host and cfg.mask_port):
        _close(client_writer)
        return
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(cfg.mask_host, cfg.mask_port),
            cfg.upstream_timeout)
    except Exception:
        _close(client_writer)
        return
    try:
        if peeked:
            up_w.write(bytes(peeked))
            await up_w.drain()
    except Exception:
        await _aclose(up_w)
        _close(client_writer)
        return
    rlog.log("mask", conn=conn_id, bytes=len(peeked), ip=rlog.redact(ip))
    await asyncio.gather(splice(client_reader, up_w, None),
                         splice(up_r, client_writer, None),
                         return_exceptions=True)
    await _aclose(up_w)
    await _aclose(client_writer)


async def _resolve_tunnel(host):
    """Whitelisted host -> one validated public IP, or None.

    We connect to the IP literal this returns rather than to the name, so a
    rebinding answer cannot slip a private address in between check and connect.
    """
    if not tunnel.host_allowed(host):
        return None
    name = (host.decode("ascii") if isinstance(host, (bytes, bytearray)) else host)
    name = name.strip().lower().rstrip(".")
    cached = ST.resolver.cached(name)
    if cached is not None:
        return cached[0] if cached else None
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, tunnel.TUNNEL_PORT, type=socket.SOCK_STREAM), 5)
    except Exception:
        ST.resolver.store(name, [])
        return None
    ips = tunnel.Resolver.filter_public(infos, ST.local_addrs)
    ST.resolver.store(name, ips)
    return ips[0] if ips else None


# ---------------------------------------------------------------- handler ---

async def handle(client_reader, client_writer):
    cfg = ST.cfg
    st = ST.state
    conn_id = ST.next_id()
    peer = client_writer.get_extra_info("peername") or ("", 0)
    ip = peer[0] if peer else ""
    peeked = bytearray()
    t0 = time.monotonic()
    deadline = t0 + cfg.header_timeout
    cs = None
    up_w = None

    try:
        # ---- prologue: exactly 5 bytes, read unconditionally ----
        if not await _read_into(client_reader, wire.PROLOGUE_LEN, peeked, deadline):
            return await _mask(client_reader, client_writer, peeked, conn_id, ip)

        ver, b4 = wire.classify_prologue(bytes(peeked[:wire.PROLOGUE_LEN]))
        if ver is None:
            return await _mask(client_reader, client_writer, peeked, conn_id, ip)

        rec = None
        device = None
        ext = {}
        if ver == wire.VER_V1:
            if not cfg.allow_v1:
                return await _mask(client_reader, client_writer, peeked, conn_id, ip)
            mode = b4 if wire.MODE_DC_MIN <= b4 <= wire.MODE_DC_MAX else 2
        else:
            body_deadline = min(deadline, time.monotonic() + cfg.body_timeout)
            base = len(peeked)
            if not await _read_into(client_reader, wire.V2_BODY_LEN, peeked, body_deadline):
                return await _mask(client_reader, client_writer, peeked, conn_id, ip)
            try:
                token, device, ext_len = wire.parse_v2_body(
                    bytes(peeked[base:base + wire.V2_BODY_LEN]))
            except ValueError:
                return await _mask(client_reader, client_writer, peeked, conn_id, ip)
            if ext_len and not await _read_into(client_reader, ext_len, peeked, body_deadline):
                return await _mask(client_reader, client_writer, peeked, conn_id, ip)
            ext = wire.parse_tlv(bytes(peeked[base + wire.V2_BODY_LEN:]))

            rec = st.get(wire.token_hash(token))
            if rec is None:
                # An unknown token is treated exactly like random garbage.
                if st.note_bad_auth(ip):
                    rlog.log("unknown", conn=conn_id, ip=rlog.redact(ip))
                return await _mask(client_reader, client_writer, peeked, conn_id, ip)

            # ---- the client is known from here on; a status frame can no
            # ---- longer tell an outsider anything they did not already have
            mode = b4
            verdict = st.admit(rec, device, mode)
            if verdict is not None:
                code, ttl, payload = verdict
                if cfg.renew_hint and code in (wire.ST_EXPIRED, wire.ST_QUOTA):
                    payload = dict(payload, renew=cfg.renew_hint)
                if st.note_reject(rec, device):
                    rlog.log("reject", conn=conn_id, tok=rec.prefix,
                             dev=device.hex()[:8],
                             code=wire.STATUS_NAMES.get(code), ip=rlog.redact(ip))
                await _send_status(client_writer, code, ttl, payload)
                return

            if mode == wire.MODE_PING:
                await _send_status(client_writer, wire.ST_OK, rec.ttl_days(),
                                   st.status_payload(rec, device))
                return

        # ---- choose the upstream ----
        if wire.MODE_DC_MIN <= mode <= wire.MODE_DC_MAX:
            target = (cfg.dc.get(mode, cfg.dc[2]), cfg.dc_port)
        elif ver == wire.VER_V2 and mode == wire.MODE_TUNNEL:
            ok, why = ST.limits.allow_open(rec.id)
            if not ok:
                await _send_status(client_writer, wire.ST_BUSY, rec.ttl_days(),
                                   {"code": "busy", "reason": why, "retry_after": 60})
                return
            resolved = await _resolve_tunnel(ext.get(wire.TLV_CONNECT_HOST, b""))
            if resolved is None:
                await _send_status(client_writer, wire.ST_FORBIDDEN_HOST,
                                   rec.ttl_days(), {"code": "forbidden_host"})
                return
            target = (resolved, tunnel.TUNNEL_PORT)
        else:
            return await _mask(client_reader, client_writer, peeked, conn_id, ip)

        if st.total_conns() >= cfg.max_conns:
            # Capacity pressure must never change the cover path's behaviour,
            # or a censor could DoS us into revealing ourselves. Unknown
            # traffic is masked above regardless of this check.
            if rec is not None:
                await _send_status(client_writer, wire.ST_BUSY, rec.ttl_days(),
                                   {"code": "busy", "retry_after": 30})
            else:
                _close(client_writer)
            return

        if rec is not None:
            cs = st.attach(rec, device, ip, mode, conn_id)

        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(*target), cfg.upstream_timeout)
        except Exception as exc:
            rlog.log("upstream_fail", conn=conn_id, target="%s:%d" % target,
                     err=str(exc)[:120])
            if cs is not None:
                st.detach(cs)
                cs = None
            if rec is not None:
                await _send_status(client_writer, wire.ST_UPSTREAM, rec.ttl_days(),
                                   {"code": "upstream", "retry_after": 5})
            else:
                _close(client_writer)
            return

        if cs is not None:
            def _kill(_cw=client_writer, _uw=up_w):
                _close(_cw)
                _close(_uw)
            cs.killer = _kill

        if ver == wire.VER_V2:
            if mode == wire.MODE_TUNNEL:
                ST.limits.opened(rec.id)
            # Every v2 connection is acknowledged with one 10-byte frame before
            # any payload, and only once the upstream is actually up. The client
            # withholds the socket from tgnet until it arrives: acknowledging
            # earlier would let MTProto pour into a connection we are about to
            # drop. On the tunnel path the client's local proxy turns this into
            # "HTTP/1.1 200 Connection established" for its WebView.
            # OK frames carry no payload, which keeps the client's reader a
            # fixed 10-byte read with no partial-body state to track.
            await _send_status(client_writer, wire.ST_OK, rec.ttl_days(),
                               None, close=False)

        rlog.log("open", conn=conn_id, tok=(rec.prefix if rec else None),
                 dev=(device.hex()[:8] if device else None), mode=mode,
                 target="%s:%d" % target, ip=rlog.redact(ip))

        on_up = cs.add_up if cs is not None else None
        on_down = cs.add_down if cs is not None else None
        await asyncio.gather(splice(client_reader, up_w, on_up),
                             splice(up_r, client_writer, on_down),
                             return_exceptions=True)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        rlog.log("error", conn=conn_id, err=repr(exc)[:200])
    finally:
        if cs is not None:
            if cs.mode == wire.MODE_TUNNEL:
                ST.limits.closed(cs.token_id, cs.up + cs.down)
            ST.state.detach(cs)
            rlog.log("close", conn=conn_id, tok=cs.prefix,
                     dev=cs.device.hex()[:8] if cs.device else None,
                     mode=cs.mode, up=cs.up, down=cs.down,
                     dur=round(time.monotonic() - t0, 1), reason=cs.reason,
                     ip=rlog.redact(ip))
        if up_w is not None:
            await _aclose(up_w)
        await _aclose(client_writer)


# ------------------------------------------------------- background tasks ---

def _load_snapshot(db):
    conn = store.connect(db)
    try:
        gen = store.get_gen(conn)
        rows = store.snapshot(conn)
        by_day = store.period_usage(conn, "day")
        by_month = store.period_usage(conn, "month")
        usage = {}
        for r in rows:
            if r["quota_period"] == "day":
                usage[r["id"]] = by_day.get(r["id"], 0)
            elif r["quota_period"] == "month":
                usage[r["id"]] = by_month.get(r["id"], 0)
        return gen, rows, usage
    finally:
        conn.close()


def _kill_tokens(token_ids, reason):
    n = 0
    for tid in token_ids:
        for cs in ST.state.conns_of(tid):
            cs.reason = reason
            if cs.killer is not None:
                cs.killer()
                n += 1
    if n:
        rlog.log("kill", tokens=len(token_ids), conns=n, reason=reason)
    return n


async def reload_cache(force=False):
    gen, rows, usage = await asyncio.to_thread(_load_snapshot, ST.cfg.db)
    if not force and gen == ST.state.gen:
        return False
    doomed = ST.state.replace(rows, usage, gen)
    rlog.log("reload", gen=gen, tokens=len(rows), doomed=len(doomed))
    # A status frame is never injected mid-stream - that would corrupt MTProto
    # framing. The socket is dropped instead; the client reconnects within a
    # second and gets its explanation at handshake time, where it belongs.
    _kill_tokens(doomed, "revoked")
    return True


async def flush_meter():
    rows = ST.state.take_meter()
    if not rows:
        return 0

    def work():
        conn = store.connect(ST.cfg.db)
        try:
            return store.flush_usage(conn, rows)
        finally:
            conn.close()

    return await asyncio.to_thread(work)


async def task_reload():
    while True:
        await asyncio.sleep(ST.cfg.auth_reload_sec)
        try:
            await reload_cache()
        except Exception as exc:
            rlog.log("reload_error", err=repr(exc)[:200])


async def task_flush():
    while True:
        await asyncio.sleep(ST.cfg.meter_flush_sec)
        try:
            await flush_meter()
        except Exception as exc:
            rlog.log("flush_error", err=repr(exc)[:200])


async def task_sweep():
    while True:
        await asyncio.sleep(ST.cfg.sweep_sec)
        try:
            ST.limits.sweep()
            _kill_tokens(ST.state.sweep(), "expired")
        except Exception as exc:
            rlog.log("sweep_error", err=repr(exc)[:200])


# ------------------------------------------------------------------ main ----

def _raise_fd_limit():
    if resource is None:
        return -1
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        return soft
    except Exception:
        return -1


async def serve(cfg=None, ready=None):
    """Set everything up and serve until SIGTERM. `ready` is for tests."""
    ST.cfg = cfg = cfg or load_cfg()
    rlog.configure(cfg.log_ip)
    ST.state = authcache.AuthState(grace=cfg.device_grace, policy=cfg.device_policy)
    ST.limits = tunnel.Limits()
    ST.resolver = tunnel.Resolver()

    store.init_db(cfg.db).close()
    await reload_cache(force=True)

    fds = _raise_fd_limit()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg.cert, cfg.key)

    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()

    def on_hup():
        rlog.log("sighup")
        try:
            # picks up a renewed certificate without restarting the container
            ctx.load_cert_chain(cfg.cert, cfg.key)
        except Exception as exc:
            rlog.log("cert_reload_error", err=repr(exc)[:200])
        asyncio.ensure_future(reload_cache(force=True))
        asyncio.ensure_future(flush_meter())

    for sig, cb in ((getattr(signal, "SIGHUP", None), on_hup),
                    (signal.SIGTERM, stopping.set),
                    (signal.SIGINT, stopping.set)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, cb)
        except (NotImplementedError, RuntimeError):
            pass

    server = await asyncio.start_server(
        handle, cfg.host, cfg.port, ssl=ctx,
        ssl_handshake_timeout=cfg.tls_handshake_timeout, backlog=512)

    # relayctl SIGHUPs this pid so a revocation lands in about a second
    # instead of waiting out the reload interval
    try:
        with open(cfg.pidfile, "w") as fh:
            fh.write(str(os.getpid()))
    except Exception as exc:
        rlog.log("pidfile_error", path=cfg.pidfile, err=str(exc)[:120])

    tasks = [asyncio.ensure_future(t()) for t in (task_reload, task_flush, task_sweep)]
    bound = server.sockets[0].getsockname() if server.sockets else (cfg.host, cfg.port)
    rlog.log("listening", host=bound[0], port=bound[1], cert=cfg.cert, db=cfg.db,
             tokens=len(ST.state.auth), allow_v1=cfg.allow_v1, fds=fds,
             mask=("%s:%d" % (cfg.mask_host, cfg.mask_port)) if cfg.mask_host else None)

    if ready is not None:
        ready.set_result(bound[1])

    try:
        await stopping.wait()
    finally:
        rlog.log("shutdown")
        server.close()
        for t in tasks:
            t.cancel()
        try:
            await flush_meter()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
