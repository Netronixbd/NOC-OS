"""Multi-vendor EPON OLT lookup: customer router MAC -> OLT port/ONU -> optical data (+ dashboard snapshot)."""
import re
import time
from concurrent.futures import ThreadPoolExecutor

import snmp

FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort  (index: <fdbId/vlan>.<mac>)
BASEPORT_IF = "1.3.6.1.2.1.17.1.4.1.2"     # dot1dBasePortIfIndex
IF_DESCR, IF_OPER, IF_NAME, IF_ALIAS = ("1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.8",
                                        "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1.18")

FIELDS = [("status", "ONU status"), ("rx", "ONU Rx power (dBm)"), ("tx", "ONU Tx power (dBm)"),
          ("olt_rx", "OLT Rx power of this ONU (dBm)"), ("distance", "Distance (m)"), ("mac", "ONU MAC"),
          ("model", "ONU model"), ("vendor", "ONU vendor"), ("name", "ONU name / description"),
          ("temp", "Temperature"), ("voltage", "Voltage"), ("uptime", "Online time / last event"),
          ("uni_speed", "ONU LAN port speed (Mbps)"), ("uni_status", "ONU LAN port status")]
KIND = {"rx": "power", "tx": "power", "olt_rx": "power", "distance": "num", "temp": "num",
        "voltage": "num", "uni_speed": "num", "status": "status", "mac": "mac"}
UNITS = {"distance": "m", "temp": "°C", "voltage": "V", "uni_speed": "Mbps"}
ONLINE_WORDS = ("online", "up", "active", "working", "registered")
NUMTYPES = ("INTEGER", "Integer32", "Gauge32", "Unsigned32", "Counter32", "Counter64")
SKIP_NAME = re.compile(r'(?i)^(gi|ge|xe|te|ten|gigabit|fast|ethernet|port-?channel|trunk|vlan|uplink|eth|ae|bridge|lo|null)')
ONU_IF = re.compile(r'^(?P<pre>.*?)(?P<pon>\d+(?:/\d+)+):(?P<onu>\d+)$')
PON_IF = re.compile(r'^(?P<pre>[A-Za-z][A-Za-z\- ]*?)\s*(?P<pon>\d+(?:/\d+)+)$')


def parse_status_map(s):
    d = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def parse_port(name):
    m = re.search(r'(\d+)/(\d+):(\d+)', name or "")
    if m:
        return dict(slot=int(m[1]), pon=int(m[2]), onu=int(m[3]))
    m = re.search(r'(\d+)/(\d+)/(\d+)', name or "")
    if m:
        return dict(slot=int(m[1]), pon=int(m[2]), onu=int(m[3]))
    return None


# ------------------------------------------------------------------ L2: MAC -> port (+VLAN)
def fdb_port(dev, mac):
    """-> (bridge port, vlan/fdb id or None)."""
    dec = snmp.mac_dec(mac)
    variants = [dev] + [dict(dev, community=f"{dev['community']}@{v}") for v in dev.get("vlans", [])]
    for d in variants:
        for _, (_, v) in snmp.get(d, [f"{FDB_PORT}.{dec}"]).items():
            n = snmp.num(v)
            if n and n > 0:
                return int(n), None
    for o, _, v in snmp.walk(dev, QFDB_PORT, timeout=40):
        if o.endswith("." + dec):
            n = snmp.num(v)
            if n and n > 0:
                rest = o[len(QFDB_PORT) + 1:-(len(dec) + 1)]
                return int(n), (int(rest) if rest.isdigit() else None)
    return None, None


def port_ifindex(dev, port):
    for _, (_, v) in snmp.get(dev, [f"{BASEPORT_IF}.{port}"]).items():
        n = snmp.num(v)
        if n:
            return int(n)
    return port


def if_info(dev, ix):
    r = snmp.get(dev, [f"{IF_NAME}.{ix}", f"{IF_DESCR}.{ix}", f"{IF_OPER}.{ix}", f"{IF_ALIAS}.{ix}"])
    g = lambda base: (r.get(f"{base}.{ix}") or (None, ""))[1]
    oper = snmp.num(g(IF_OPER))
    return dict(name=g(IF_NAME) or g(IF_DESCR), alias=g(IF_ALIAS),
                link={1: "up", 2: "down"}.get(int(oper)) if oper else None)


def suffix_for(tpl, ix, pp):
    ctx = dict(ifindex=ix, slot=(pp or {}).get("slot", 0), pon=(pp or {}).get("pon", 0), onu=(pp or {}).get("onu", 0))
    return (tpl or "{ifindex}").format(**ctx)


_ifn_cache = {}


def _ifname_map(dev):
    k = (dev["host"], dev.get("port", 161))
    c = _ifn_cache.get(k)
    if c and time.time() - c[0] < 600:
        return c[1]
    m = {}
    for o, _, v in snmp.walk(dev, IF_NAME, timeout=120):
        m[v.lower()] = o.rsplit(".", 1)[1]
    _ifn_cache[k] = (time.time(), m)
    return m


def pon_ifindex(dev, slot, pon):
    m = _ifname_map(dev)
    for pre in ("epon", "pon", "gpon", "xpon"):
        for sep in ("", " "):
            ix = m.get(f"{pre}{sep}{slot}/{pon}")
            if ix:
                return ix
    for name, ix in m.items():
        if ":" not in name and "pon" in name and name.endswith(f"{slot}/{pon}"):
            return ix
    return None


# ------------------------------------------------------------------ per-ONU values
def _conv(f, c, typ, v, smap):
    div = float(c.get("div") or 1)
    kind = KIND.get(f, "str")
    conf = c.get("conf") or ""
    if kind == "power":
        if (c.get("unit") or "dbm") == "dbm_str":
            dbm = snmp.parse_dbm_str(v)
        else:
            n = snmp.num(v)
            dbm = snmp.to_dbm(n, div, c.get("unit") or "dbm") if n is not None else None
        return dict(value=dbm, unit="dBm", conf=conf, quality=snmp.rx_quality(dbm) if f in ("rx", "olt_rx") else None)
    if kind == "num":
        n = snmp.num(v)
        if n is None:
            return None
        x = round(n / div, 2)
        return dict(value=int(x) if x == int(x) else x, unit=UNITS.get(f, ""), conf=conf)
    if kind == "status":
        n = snmp.num(v)
        txt = smap.get(str(int(n)) if n is not None else v, v)
        return dict(value=txt, conf=conf, online=txt.lower() in ONLINE_WORDS)
    if kind == "mac":
        return dict(value=snmp.val_mac(typ, v) or v, conf=conf)
    return dict(value=v, conf=conf)


def onu_details(dev, prof, ix, pp):
    suffix = suffix_for(prof.get("index_template"), ix, pp)
    cfg = {f: c for f, c in (prof.get("oids") or {}).items() if (c or {}).get("oid")}
    smap = prof.get("status_map") or {}
    req = {f"{c['oid'].strip('.')}.{suffix}": f for f, c in cfg.items() if c.get("index") != "pon_mac"}
    vals = snmp.get(dev, list(req)) if req else {}
    out, raw = {}, []
    for oid, f in req.items():
        if oid in vals:
            e = _conv(f, cfg[f], vals[oid][0], vals[oid][1], smap)
            if e is not None:
                out[f] = e
                raw.append(dict(field=f, oid=oid, raw=vals[oid][1], conf=e.get("conf")))
    # tables indexed by <PON ifIndex>.<ONU MAC> (e.g. BDCOM distance)
    need = {f: c for f, c in cfg.items() if c.get("index") in ("pon_mac", "auto") and f not in out}
    mac = (out.get("mac") or {}).get("value")
    if need and mac and pp:
        pi = pon_ifindex(dev, pp["slot"], pp["pon"])
        if pi:
            sfx2 = f"{pi}.{snmp.mac_dec(mac)}"
            req2 = {f"{c['oid'].strip('.')}.{sfx2}": f for f, c in need.items()}
            vals2 = snmp.get(dev, list(req2))
            for oid, f in req2.items():
                if oid in vals2:
                    e = _conv(f, need[f], vals2[oid][0], vals2[oid][1], smap)
                    if e is not None:
                        out[f] = e
                        raw.append(dict(field=f, oid=oid, raw=vals2[oid][1], conf=e.get("conf")))
    return dict(fields=out, suffix=suffix, raw=raw)


def locate_one(dev, prof, mac, onu_mac=None):
    ix = info = pp = None
    vlan = None
    if mac:
        port, vlan = fdb_port(dev, mac)
        if port:
            ix = port_ifindex(dev, port)
            info = if_info(dev, ix)
            pp = parse_port(info["name"])
            if not pp and SKIP_NAME.match(info["name"] or ""):
                ix = info = None          # learned on uplink / non-ONU port
    mac_cfg = ((prof.get("oids") or {}).get("mac") or {}).get("oid")
    if ix is None and onu_mac and mac_cfg:
        target = snmp.norm_mac(onu_mac)
        for o, t, v in snmp.walk(dev, mac_cfg, timeout=60):
            if snmp.val_mac(t, v) == target:
                suf = o[len(mac_cfg.strip(".")) + 1:]
                if (prof.get("index_template") or "{ifindex}") == "{ifindex}" and suf.isdigit():
                    ix = int(suf)
                    info = if_info(dev, ix)
                    pp = parse_port(info["name"])
                break
    if ix is None:
        return None
    det = onu_details(dev, prof, ix, pp)
    return dict(found=True, olt=dev["name"], vendor=dev.get("vendor"), host=dev.get("host"), profile=prof.get("name"),
                ifindex=ix, ifname=info["name"], alias=info["alias"], link=info["link"], vlan=vlan,
                pon=f"{pp['slot']}/{pp['pon']}" if pp else None, onu=pp["onu"] if pp else None,
                fields=det["fields"], suffix=det["suffix"], raw=det["raw"],
                configured=bool(prof.get("oids")) and any((c or {}).get("oid") for c in prof["oids"].values()))


def locate(olts, mac, onu_mac=None):
    if not olts:
        return None

    def work(o):
        try:
            r = locate_one(o, o["profile"], mac, onu_mac)
            return r, None
        except Exception as e:
            return None, str(e)
    with ThreadPoolExecutor(max_workers=min(6, len(olts))) as ex:
        res = list(ex.map(work, olts))
    checked = [dict(olt=o["name"], vendor=o.get("vendor"), host=o.get("host"),
                    state="found" if r else ("error" if e else "not_found"), detail=e or "")
               for o, (r, e) in zip(olts, res)]
    errs = [f"{c['olt']}: {c['detail']}" for c in checked if c["detail"]]
    for r, _ in res:
        if r:
            r["errors"], r["checked"] = errs, checked
            return r
    return dict(found=False, errors=errs, searched=len(olts), checked=checked)


def sys_info(dev):
    r = snmp.get(dev, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"])
    g = lambda k: (r.get(k) or (None, ""))[1]
    return dict(name=g("1.3.6.1.2.1.1.5.0"), descr=g("1.3.6.1.2.1.1.1.0")[:120], uptime=g("1.3.6.1.2.1.1.3.0"))


# ------------------------------------------------------------------ dashboard snapshot (standard IF-MIB only)
def _pon_sort(p):
    return [int(x) for x in re.findall(r"\d+", p["pon"])]


def snapshot(dev):
    """ONU online counts per PON from ifOperStatus of the logical ONU interfaces (EPON0/1:24) and PON port state."""
    names = {o.rsplit(".", 1)[1]: v for o, _, v in snmp.walk(dev, IF_NAME, timeout=90)}
    oper = {o.rsplit(".", 1)[1]: int(snmp.num(v) or 0) for o, _, v in snmp.walk(dev, IF_OPER, timeout=90)}
    s = snmp.get(dev, ["1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"])
    ticks = snmp.num((s.get("1.3.6.1.2.1.1.3.0") or (0, ""))[1])
    pons, total, online = {}, 0, 0
    for ix, name in names.items():
        m = ONU_IF.match(name)
        if m:
            p = pons.setdefault(m["pon"], dict(pon=m["pon"], up=None, total=0, online=0))
            p["total"] += 1
            on = oper.get(ix) == 1
            p["online"] += on
            total += 1
            online += on
            continue
        m = PON_IF.match(name)
        if m and "pon" in m["pre"].lower():
            p = pons.setdefault(m["pon"], dict(pon=m["pon"], up=None, total=0, online=0))
            p["up"] = oper.get(ix) == 1
    for p in pons.values():
        if p["up"] is None:
            p["up"] = p["online"] > 0
    return dict(ok=True, sysname=(s.get("1.3.6.1.2.1.1.5.0") or (0, ""))[1], uptime=int(ticks / 100) if ticks else None,
                onu_total=total, onu_online=online, onu_supported=total > 0,
                pons=sorted(pons.values(), key=_pon_sort), if_count=len(names))


# ------------------------------------------------------------------ Discover tools
def guess(typ, v):
    if snmp.val_mac(typ, v) and typ in ("Hex-STRING", "STRING"):
        return "MAC address?"
    if typ == "STRING" and "dbm" in v.lower():
        return "power as text (use 'dBm from text')"
    n = snmp.num(v) if typ in NUMTYPES else None
    if n is None:
        return "text" if typ == "STRING" else ""
    if -6000 <= n <= -500:
        return f"power? ÷100 = {n/100:.2f} dBm"
    if -600 < n <= -50:
        return f"power? ÷10 = {n/10:.1f} dBm"
    if -60 < n < -5:
        return f"power? = {n:.0f} dBm"
    if 50 <= n <= 40000:
        return "distance(m) / power in µW×? / other"
    if 0 <= n <= 10:
        return "status / enum?"
    return ""


def discover(dev, start_oid, suffix):
    rows = snmp.walk(dev, start_oid, timeout=150)
    res = []
    for o, t, v in rows:
        if o.endswith("." + suffix):
            res.append(dict(column=o[:-len(suffix) - 1], type=t, value=v, guess=guess(t, v)))
    return res, len(rows)


def resolve_suffix(dev, prof, mac):
    port, _ = fdb_port(dev, mac)
    if not port:
        return None, None
    ix = port_ifindex(dev, port)
    info = if_info(dev, ix)
    pp = parse_port(info["name"])
    return suffix_for(prof.get("index_template"), ix, pp), info["name"]


def _fl(x):
    try:
        return float(str(x).lower().replace("dbm", "").replace("m", "").strip())
    except Exception:
        return None


def match_known(rows, known):
    """Mark discover rows whose value equals a value the admin read from the OLT CLI."""
    kn = {k: _fl(known.get(k)) for k in ("rx", "tx", "olt_rx", "distance", "temp", "voltage", "uni_speed")}
    kmac = snmp.norm_mac(known.get("mac", "")) if known.get("mac") else None
    best = {}

    def add(r, field, div, unit="dbm"):
        r.setdefault("matches", []).append(dict(field=field, div=div, unit=unit))
        best.setdefault(field, dict(field=field, col=r["column"], div=div, unit=unit, value=r["value"]))

    for r in rows:
        t, v = r["type"], r["value"]
        n = snmp.num(v) if t in NUMTYPES else None
        dtext = snmp.parse_dbm_str(v) if t == "STRING" else None
        for f in ("rx", "tx", "olt_rx"):
            if dtext is not None and kn[f] is not None and abs(dtext - kn[f]) <= 0.06:
                add(r, f, 1, "dbm_str")
        if n is not None:
            for f in ("rx", "tx", "olt_rx"):
                x = kn[f]
                if x is None or (x * n < 0) or n == 0:
                    continue
                hit = False
                for div in (1, 10, 100, 1000):
                    if abs(n / div - x) <= (0.51 if div == 1 else 0.051):
                        add(r, f, div, "dbm")
                        hit = True
                        break
                if not hit and x >= -40:
                    uw = 1000 * 10 ** (x / 10)
                    for div in (1, 10, 100):
                        if n > 0 and abs(n / div - uw) <= max(0.03 * uw, 0.5):
                            add(r, f, div, "uw")
                            break
            if kn["distance"] is not None and n > 0:
                for div in (1, 10):
                    if abs(n / div - kn["distance"]) <= 2:
                        add(r, "distance", div)
                        break
            if kn["temp"] is not None:
                for div in (1, 10, 100, 256):
                    if abs(n / div - kn["temp"]) <= (0.6 if div == 1 else 0.06):
                        add(r, "temp", div)
                        break
            if kn["voltage"] is not None:
                for div in (1, 10, 100, 1000, 10000):
                    if abs(n / div - kn["voltage"]) <= 0.02:
                        add(r, "voltage", div)
                        break
            if kn["uni_speed"] is not None and n == kn["uni_speed"]:
                add(r, "uni_speed", 1)
        if kmac and snmp.val_mac(t, v) == kmac:
            add(r, "mac", 1)
        if n is None and t in ("STRING", "Hex-STRING"):
            for f in ("model", "vendor"):
                k = (known.get(f) or "").strip().lower()
                if k and k in v.lower():
                    add(r, f, 1)
    return list(best.values())


# ------------------------------------------------------------------ weak-ONU scan
def scan(dev, prof):
    cfg = prof.get("oids") or {}
    rx = cfg.get("rx") or {}
    if not rx.get("oid"):
        raise ValueError("Set the 'ONU Rx power' OID in the profile first (Tools → Discover).")
    base = rx["oid"].strip(".")
    names = {o.rsplit(".", 1)[1]: v for o, _, v in snmp.walk(dev, IF_NAME, timeout=120)}
    oper = {o.rsplit(".", 1)[1]: int(snmp.num(v) or 0) for o, _, v in snmp.walk(dev, IF_OPER, timeout=120)}
    st, smap = {}, prof.get("status_map") or {}
    sc = cfg.get("status") or {}
    if sc.get("oid"):
        sb = sc["oid"].strip(".")
        for o, _, v in snmp.walk(dev, sb, timeout=120):
            n = snmp.num(v)
            key = str(int(n)) if n is not None else v
            txt = smap.get(key, v)
            norm = txt.strip().lower()
            if key in smap:
                is_online = norm in ONLINE_WORDS
            elif n is not None and int(n) == 1:
                is_online = True
            elif n is not None and int(n) == 2:
                is_online = False
            else:
                is_online = any(word in norm for word in ONLINE_WORDS)
            st[o[len(sb) + 1:]] = (txt, is_online)
    rows = []
    for o, _, v in snmp.walk(dev, base, timeout=150):
        suf = o[len(base) + 1:]
        name = names.get(suf, suf)
        m = ONU_IF.match(name)
        n = snmp.num(v)
        if (rx.get("unit") or "dbm") == "dbm_str":
            dbm = snmp.parse_dbm_str(v)
        else:
            unit = (rx.get("unit") or "dbm").lower()
            # A literal zero is not a plausible received optical power in dBm.
            # Treat it as missing data instead of displaying a false "Too strong" result.
            if n is not None and unit in ("dbm", "dbm_x100", "dbm_x10") and n == 0:
                dbm = None
            else:
                div = rx.get("div") or 1
                if unit == "dbm_x100": div = float(div) * 100
                elif unit == "dbm_x10": div = float(div) * 10
                dbm = snmp.to_dbm(n, div, "dbm" if unit.startswith("dbm") else unit) if n is not None else None
        s = st.get(suf)
        # Do not infer a customer ONU is offline from an unrelated/missing IF-MIB index.
        online = s[1] if s else ({1: True, 2: False}.get(oper.get(suf)) if suf in oper else None)
        rows.append(dict(name=name, pon=m["pon"] if m else "?", rx=dbm, quality=snmp.rx_quality(dbm),
                         status=s[0] if s else ({True: "up", False: "down"}.get(online)), online=online))
    rows.sort(key=lambda r: (r["rx"] is None, r["rx"] if r["rx"] is not None else 0))
    pons = {}
    for r in rows:
        p = pons.setdefault(r["pon"], dict(pon=r["pon"], total=0, weak=0, bad=0, nodata=0, offline=0))
        p["total"] += 1
        p["bad"] += r["quality"] == "bad"
        p["weak"] += r["quality"] == "weak"
        p["nodata"] += r["rx"] is None
        p["offline"] += r["online"] is False
    return dict(rows=rows[:500], total=len(rows), pons=sorted(pons.values(), key=_pon_sort))
