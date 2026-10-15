"""Thin wrapper over net-snmp CLI tools (apt install snmp). v1/v2c only."""
import math
import os
import re
import subprocess

_ENV = dict(os.environ, MIBS="")
_LINE = re.compile(r'^\.?([\d.]+) = ([A-Za-z0-9-]+): ?(.*)$')


class SnmpError(Exception):
    pass


def clean(v):
    v = str(v).strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def num(v):
    m = re.search(r'-?\d+(?:\.\d+)?', str(v))
    return float(m.group()) if m else None


def _parse(out):
    rows = []
    for line in out.splitlines():
        m = _LINE.match(line.strip())
        if m:
            rows.append((m.group(1), m.group(2), clean(m.group(3))))
    return rows


def _run(tool, dev, args, timeout, walk=False):
    cmd = [tool, "-v", str(dev.get("version") or "2c"), "-c", dev.get("community") or "public",
           "-t", "3", "-r", "1", "-On", "-Oe", "-OU", "-Ot"]
    if walk:
        cmd.append("-Cc")
        if tool == "snmpbulkwalk":
            cmd.append("-Cr20")
    cmd += [f"{dev['host']}:{int(dev.get('port') or 161)}"] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_ENV)
    except FileNotFoundError:
        raise SnmpError("net-snmp tools missing (run: apt install snmp)")
    except subprocess.TimeoutExpired:
        raise SnmpError("SNMP timeout")
    rows = _parse(p.stdout)
    if not rows and p.returncode != 0:
        raise SnmpError((p.stderr or p.stdout).strip().splitlines()[-1][:200] if (p.stderr or p.stdout).strip()
                        else "SNMP error")
    return rows


def get(dev, oids, timeout=20):
    """-> {oid: (type, value)}; missing instances are simply absent."""
    rows = _run("snmpget", dev, ["." + o.strip(".") for o in oids], timeout)
    return {o: (t, v) for o, t, v in rows}


def walk(dev, oid, timeout=60):
    tool = "snmpwalk" if str(dev.get("version") or "2c") == "1" else "snmpbulkwalk"
    return _run(tool, dev, ["." + oid.strip(".")], timeout, walk=True)


# ---------- helpers
def norm_mac(s):
    h = re.sub(r'[^0-9A-Fa-f]', '', s or '')
    if len(h) != 12:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def mac_dec(mac):
    return ".".join(str(int(x, 16)) for x in mac.split(":"))


def val_mac(typ, v):
    m = norm_mac(v)
    if m:
        return m
    if typ == "STRING" and len(v) == 6:
        try:
            return ":".join(f"{ord(c):02X}" for c in v) if all(ord(c) < 256 for c in v) else None
        except Exception:
            return None
    return None


def to_dbm(raw, div, unit):
    try:
        x = float(raw) / (float(div) or 1)
    except Exception:
        return None
    if unit == "uw":
        if x <= 0:
            return None
        x = 10 * math.log10(x / 1000.0)
    return round(x, 2) if -60 <= x <= 10 else None


def rx_quality(dbm):
    """EPON-ish thresholds."""
    if dbm is None:
        return None
    if dbm > -8:
        return "high"
    if dbm >= -24:
        return "good"
    if dbm >= -27:
        return "weak"
    return "bad"


def parse_dbm_str(v):
    """V-SOL style text: '0.02 mW (-18.12 dBm)' or '6.56 dbm'."""
    m = re.findall(r'(-?\d+(?:\.\d+)?)\s*dbm', str(v), re.I)
    if not m:
        return None
    x = float(m[-1])
    return round(x, 2) if -60 <= x <= 10 else None
