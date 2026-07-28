"""Structured stdout logging with a deliberate IP policy.

On the privacy of client addresses: hashing an IPv4 address looks safe but is
not. The whole IPv4 space is 2**32 values, so an HMAC over it can be inverted
by brute force in minutes on a GPU, which means a seized log file is fully
reversible. For a censorship-circumvention relay the logs are the single
largest deanonymisation risk if the machine is taken, so the default is to
keep only a coarse network prefix (/24 for v4, /48 for v6) - enough to triage
abuse, not enough to identify a person. LOG_IP=full is opt-in and documented
as such.
"""

import ipaddress
import json
import sys
import time

MODE_OFF = "off"
MODE_PREFIX = "prefix"
MODE_FULL = "full"

_mode = MODE_PREFIX


def configure(mode):
    global _mode
    _mode = mode if mode in (MODE_OFF, MODE_PREFIX, MODE_FULL) else MODE_PREFIX


def redact(ip):
    if not ip or _mode == MODE_OFF:
        return None
    if _mode == MODE_FULL:
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    return str(ipaddress.ip_network(ip + "/48", strict=False))


def log(ev, **fields):
    rec = {"ts": round(time.time(), 3), "ev": ev}
    for k, v in fields.items():
        if v is not None:
            rec[k] = v
    sys.stdout.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")
    sys.stdout.flush()
