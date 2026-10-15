import ipaddress
import re
import ssl
import time

from librouteros import connect
from librouteros.query import Key

import snmp


def _connect(r):
    kw = dict(host=r["host"], username=r["username"], password=r["password"], port=int(r["port"]), timeout=6)
    if r.get("use_ssl"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kw["ssl_wrapper"] = ctx.wrap_socket
    return connect(**kw)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _q(api, path, props, key, value):
    return list(api.path(*path).select(*[Key(p) for p in props]).where(Key(key) == value))


def _flag(v):
    return str(v).lower() in ("true", "yes", "1")


def parse_uptime(s):
    if not s:
        return None
    mult = dict(w=604800, d=86400, h=3600, m=60, s=1)
    return sum(int(n) * mult[u] for n, u in re.findall(r"(\d+)([wdhms])", str(s))) or 0


def test(r):
    api = _connect(r)
    try:
        return list(api.path("system", "identity"))[0]["name"]
    finally:
        api.close()


def fetch_secrets(r):
    api = _connect(r)
    try:
        return list(api.path("ppp", "secret"))
    finally:
        api.close()


def status(user_id, routers):
    """Light status for the public customer page."""
    answered = False
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            answered = True
            act = _q(api, ("ppp", "active"), ["name", "address", "uptime"], "name", user_id)
            if act:
                return {"state": "online", "ip": act[0].get("address", ""), "uptime": act[0].get("uptime", "")}
            sec = _q(api, ("ppp", "secret"), ["name", "disabled"], "name", user_id)
            if sec:
                return {"state": "disabled" if _flag(sec[0].get("disabled")) else "offline"}
        except Exception:
            pass
        finally:
            try:
                api.close()
            except Exception:
                pass
    return {"state": "notfound" if answered else "unknown"}


def find_by_mac(mac, routers):
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            a = _q(api, ("ppp", "active"), ["name"], "caller-id", mac)
            if a:
                return a[0]["name"]
        except Exception:
            pass
        finally:
            api.close()
    return None


SEC = ["name", "service", "profile", "disabled", "comment", "last-logged-out", "last-caller-id",
       "last-disconnect-reason", "caller-id", "remote-address", "local-address"]
ACT = ["name", "address", "caller-id", "uptime", "service", "encoding", "session-id"]


def _pool_by_ip(api, ip):
    """Name of the /ip pool whose ranges contain the IP (works for RADIUS users too)."""
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
        for p in api.path("ip", "pool"):
            for rg in str(p.get("ranges", "")).split(","):
                rg = rg.strip()
                if not rg:
                    continue
                if "-" in rg:
                    lo, hi = rg.split("-", 1)
                    if ipaddress.ip_address(lo.strip()) <= a <= ipaddress.ip_address(hi.strip()):
                        return p.get("name")
                elif "/" in rg:
                    if a in ipaddress.ip_network(rg, strict=False):
                        return p.get("name")
                elif a == ipaddress.ip_address(rg):
                    return p.get("name")
    except Exception:
        return None
    return None


def _pair(s):
    try:
        a, b = str(s).split("/")[:2]
        return int(a), int(b)
    except Exception:
        return None, None


def diagnose(uid, routers):
    """Everything useful for troubleshooting one PPPoE user, via RouterOS API."""
    errs = []
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception as e:
            errs.append(f"{r.get('name')}: {e}")
            continue
        try:
            sec = _safe(lambda: _q(api, ("ppp", "secret"), SEC, "name", uid), [])
            act = _safe(lambda: _q(api, ("ppp", "active"), ACT, "name", uid), [])
            if not sec and not act:
                continue
            s, a = (sec[0] if sec else {}), (act[0] if act else None)
            ifname = f"<pppoe-{uid}>"
            prof = _safe(lambda: _q(api, ("ppp", "profile"), ["name", "rate-limit", "local-address", "remote-address",
                                                              "parent-queue"], "name", s["profile"]), []) \
                if s.get("profile") else []
            pool_ip = _pool_by_ip(api, (a or {}).get("address")) if a else None
            iface = _safe(lambda: _q(api, ("interface",), ["name", "running", "rx-byte", "tx-byte", "rx-error",
                                                           "tx-error", "rx-drop", "tx-drop", "link-downs"],
                                     "name", ifname), []) if a else []
            queue = _safe(lambda: _q(api, ("queue", "simple"), ["name", "max-limit", "rate", "bytes", "dropped"],
                                     "name", ifname), []) if a else []
            traffic = _safe(lambda: list(api.rawCmd("/interface/monitor-traffic", f"=interface={ifname}",
                                                    "=once=")), []) if a else []
            lists = _safe(lambda: _q(api, ("ip", "firewall", "address-list"), ["list", "address"], "address",
                                     a["address"]), []) if a and a.get("address") else []
            logs = _safe(lambda: [l for l in list(api.path("log"))[-600:] if uid in (l.get("message") or "")], [])
            mac = (a or {}).get("caller-id") or s.get("last-caller-id")
            q = queue[0] if queue else {}
            up_r, down_r = _pair(q.get("rate"))
            t = traffic[0] if traffic else {}
            i = iface[0] if iface else {}
            state = "online" if a else ("disabled" if _flag(s.get("disabled")) else "offline")
            return dict(
                found=True, router=r.get("name"), state=state, ip=(a or {}).get("address") or s.get("remote-address"),
                uptime=(a or {}).get("uptime"), uptime_sec=parse_uptime((a or {}).get("uptime")),
                mac=mac, mac_source="active session" if a and a.get("caller-id") else "last known",
                profile=s.get("profile") or ("RADIUS" if a and not s else None),
                rate_limit=(prof[0].get("rate-limit") if prof else None),
                profile_pool=(prof[0].get("remote-address") if prof else None) or s.get("remote-address"),
                profile_local=(prof[0].get("local-address") if prof else None) or s.get("local-address"),
                parent_queue=(prof[0].get("parent-queue") if prof else None), pool_by_ip=pool_ip,
                radius=bool(a and not s),
                session=dict(down_bytes=int(i.get("tx-byte") or 0), up_bytes=int(i.get("rx-byte") or 0)) if i else None,
                service=(a or s).get("service"), comment=s.get("comment"), disabled=_flag(s.get("disabled")),
                last_logged_out=s.get("last-logged-out"), last_disconnect_reason=s.get("last-disconnect-reason"),
                queue=dict(max_limit=q.get("max-limit"), rate_up=up_r, rate_down=down_r, dropped=q.get("dropped"),
                           bytes=q.get("bytes")) if q else None,
                iface=dict(running=_flag(i.get("running")), rx_error=i.get("rx-error"), tx_error=i.get("tx-error"),
                           rx_drop=i.get("rx-drop"), tx_drop=i.get("tx-drop"), link_downs=i.get("link-downs"),
                           rx_byte=i.get("rx-byte"), tx_byte=i.get("tx-byte")) if i else None,
                traffic=dict(down_bps=int(t["tx-bits-per-second"]), up_bps=int(t["rx-bits-per-second"]))
                if t.get("tx-bits-per-second") is not None else None,
                lists=[x.get("list") for x in lists],
                logs=[dict(time=l.get("time"), message=l.get("message")) for l in logs[-15:]],
            )
        finally:
            try:
                api.close()
            except Exception:
                pass
    return dict(found=False, errors=errs)


def _ms(s):
    m = re.fullmatch(r"(?:(\d+)ms)?(?:(\d+)us)?", str(s or ""))
    if not m or not (m[1] or m[2]):
        return None
    return int(m[1] or 0) + int(m[2] or 0) / 1000


def ping(uid, routers, count=20, interval="100ms"):
    """Ping the customer's PPPoE address from the router. Returns per-packet RTTs + stats."""
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            a = _q(api, ("ppp", "active"), ["address"], "name", uid)
            if not a:
                continue
            ip = a[0]["address"]
            rows = list(api.rawCmd("/ping", f"=address={ip}", f"=count={count}", f"=interval={interval}"))
            times = [None] * count
            for k, row in enumerate(rows[:count]):
                try:
                    seq = int(row.get("seq", k))
                except Exception:
                    seq = k
                if 0 <= seq < count:
                    times[seq] = _ms(row.get("time"))
            got = [t for t in times if t is not None]
            jit = [abs(got[k] - got[k - 1]) for k in range(1, len(got))]
            return dict(ok=True, ip=ip, sent=count, received=len(got), loss=round(100 * (count - len(got)) / count),
                        min=min(got) if got else None, avg=round(sum(got) / len(got), 2) if got else None,
                        max=max(got) if got else None, jitter=round(sum(jit) / len(jit), 2) if jit else None,
                        times=times, interval=interval)
        except Exception as e:
            return dict(ok=False, error=str(e))
        finally:
            api.close()
    return dict(ok=False, error="User is not online on any router")


def session_live(uid, routers):
    """Fast counters for the live graph (rate is computed from deltas by the browser)."""
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            a = _q(api, ("ppp", "active"), ["address", "uptime"], "name", uid)
            if not a:
                continue
            i = _safe(lambda: _q(api, ("interface",), ["rx-byte", "tx-byte"], "name", f"<pppoe-{uid}>"), [])
            if not i:
                continue
            return dict(found=True, router=r.get("name"), ip=a[0].get("address"), uptime=a[0].get("uptime"),
                        down_bytes=int(i[0].get("tx-byte") or 0), up_bytes=int(i[0].get("rx-byte") or 0),
                        ts=time.time())
        except Exception as e:
            return dict(found=False, error=str(e))
        finally:
            api.close()
    return dict(found=False)


def disconnect(uid, routers):
    """Remove the active PPP session so the customer router redials."""
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            a = list(api.path("ppp", "active").select(Key(".id"), Key("name")).where(Key("name") == uid))
            if a:
                api.path("ppp", "active").remove(a[0][".id"])
                return dict(ok=True, router=r.get("name"))
        except Exception as e:
            return dict(ok=False, error=str(e))
        finally:
            api.close()
    return dict(ok=False, error="No active session found for this user")


def l2_info(r, mac, vlan):
    """MikroTik side of the L2 path: VLAN interfaces, PPPoE servers, bridge host entry."""
    api = _connect(r)
    try:
        vlans = []
        if vlan:
            vlans = _safe(lambda: [dict(name=x.get("name"), parent=x.get("interface"), vid=x.get("vlan-id"))
                                   for x in api.path("interface", "vlan") if str(x.get("vlan-id")) == str(vlan)], [])
        servers = _safe(lambda: [dict(service=x.get("service-name"), interface=x.get("interface"),
                                      disabled=_flag(x.get("disabled")))
                                 for x in api.path("interface", "pppoe-server", "server")], [])
        names = {v["name"] for v in vlans}
        matched = [s_ for s_ in servers if s_["interface"] in names] if names else []
        host = _safe(lambda: [dict(interface=x.get("on-interface"), vid=x.get("vid"), bridge=x.get("bridge"))
                              for x in _q(api, ("interface", "bridge", "host"),
                                          ["mac-address", "on-interface", "vid", "bridge"], "mac-address", mac)], []) if mac else []
        return dict(router=r.get("name"), vlan_ifaces=vlans, servers=matched or servers, servers_matched=bool(matched),
                    bridge_host=host)
    finally:
        api.close()


def system_stats(r):
    """Router health for the dashboard: CPU, memory, uptime, version, active PPPoE users."""
    out = dict(ok=False, error="", cpu=None, mem_pct=None, uptime=None, version=None, board=None, identity=None,
               active=None, via=None)
    if r.get("api_enabled", True):
        try:
            api = _connect(r)
        except Exception as e:
            out["error"] = str(e)[:150]
            api = None
        if api:
            try:
                res = list(api.path("system", "resource"))[0]
                out.update(ok=True, via="api", cpu=int(res.get("cpu-load", 0)), uptime=res.get("uptime"),
                           version=res.get("version"), board=res.get("board-name"))
                tm, fm = int(res.get("total-memory", 0)), int(res.get("free-memory", 0))
                out["mem_pct"] = round(100 * (tm - fm) / tm) if tm else None
                out["identity"] = _safe(lambda: list(api.path("system", "identity"))[0]["name"])
                cnt = _safe(lambda: list(api.rawCmd("/ppp/active/print", "=count-only=")), [])
                n = next((int(x["ret"]) for x in cnt if isinstance(x, dict) and str(x.get("ret", "")).isdigit()), None)
                if n is None:
                    n = len(_safe(lambda: list(api.path("ppp", "active").select(Key("name"))), []))
                out["active"] = n
                return out
            except Exception as e:
                out["error"] = str(e)[:150]
            finally:
                try:
                    api.close()
                except Exception:
                    pass
    if r.get("snmp_enabled"):
        try:
            d = snmp_dev(r)
            g = snmp.get(d, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
            loads = [snmp.num(v) for _, _, v in snmp.walk(d, "1.3.6.1.2.1.25.3.3.1.2", timeout=15)]
            loads = [x for x in loads if x is not None]
            ticks = snmp.num((g.get("1.3.6.1.2.1.1.3.0") or (0, ""))[1])
            out.update(ok=True, via="snmp", error="", identity=(g.get("1.3.6.1.2.1.1.5.0") or (0, ""))[1],
                       cpu=round(sum(loads) / len(loads)) if loads else None, uptime=f"{int(ticks / 8640000)}d" if ticks else None)
        except Exception as e:
            out["error"] = (out["error"] + " | " if out["error"] else "") + str(e)[:100]
    return out


# ------------------------------------------------------------------ PPPoE user management (needs write permission)
def list_profiles(r):
    api = _connect(r)
    try:
        return [p["name"] for p in api.path("ppp", "profile") if p.get("name")]
    finally:
        api.close()


def secret_get(r, name):
    api = _connect(r)
    try:
        s = _q(api, ("ppp", "secret"), ["name", "service", "profile", "disabled", "comment", "remote-address",
                                         "last-logged-out"], "name", name)
        return s[0] if s else None
    finally:
        api.close()


def create_secret(r, name, password, profile, comment="", service="pppoe"):
    api = _connect(r)
    try:
        if _q(api, ("ppp", "secret"), ["name"], "name", name):
            raise ValueError("A PPP secret with this name already exists on the router")
        api.path("ppp", "secret").add(name=name, password=password, profile=profile, service=service, comment=comment)
    finally:
        api.close()


def secret_set(r, name, **kw):
    api = _connect(r)
    try:
        s = list(api.path("ppp", "secret").select(Key(".id")).where(Key("name") == name))
        if not s:
            raise ValueError("Secret not found on this router")
        api.path("ppp", "secret").update(**{".id": s[0][".id"], **kw})
    finally:
        api.close()


def secret_remove(r, name):
    api = _connect(r)
    try:
        s = list(api.path("ppp", "secret").select(Key(".id")).where(Key("name") == name))
        if not s:
            raise ValueError("Secret not found on this router")
        api.path("ppp", "secret").remove(s[0][".id"])
    finally:
        api.close()
# ------------------------------------------------------------------ SNMP side of the router
def snmp_dev(r):
    return dict(host=r["host"], port=r.get("snmp_port") or 161, community=r.get("snmp_community") or "public",
                version="2c")


def snmp_test(r):
    g = snmp.get(snmp_dev(r), ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
    return dict(name=(g.get("1.3.6.1.2.1.1.5.0") or (0, "?"))[1], uptime=(g.get("1.3.6.1.2.1.1.3.0") or (0, "?"))[1])


_ifcache = {}


def _ifindex(dev, host, name):
    c = _ifcache.get(host)
    if c and name in c[1]:
        return c[1][name]
    if c and time.time() - c[0] < 20:
        return None
    m = {}
    for o, _, v in snmp.walk(dev, "1.3.6.1.2.1.31.1.1.1.1", timeout=60):
        m[v] = o.rsplit(".", 1)[1]
    _ifcache[host] = (time.time(), m)
    return m.get(name)


def snmp_ppp(r, uid):
    """PPPoE interface counters + live rate over SNMP (needs the user online)."""
    dev = snmp_dev(r)
    try:
        ix = _ifindex(dev, r["host"], f"<pppoe-{uid}>")
        if not ix:
            return dict(ok=False, error="PPPoE interface not found over SNMP (user offline?)")
        ino, outo = f"1.3.6.1.2.1.31.1.1.1.6.{ix}", f"1.3.6.1.2.1.31.1.1.1.10.{ix}"
        a = snmp.get(dev, [ino, outo, f"1.3.6.1.2.1.2.2.1.8.{ix}", f"1.3.6.1.2.1.2.2.1.14.{ix}",
                           f"1.3.6.1.2.1.2.2.1.20.{ix}", f"1.3.6.1.2.1.2.2.1.13.{ix}", f"1.3.6.1.2.1.2.2.1.19.{ix}"])
        t0 = time.time()
        time.sleep(2)
        b = snmp.get(dev, [ino, outo])
        dt = time.time() - t0
        n = lambda d, k: snmp.num((d.get(k) or (0, ""))[1])
        di, do = n(b, ino) - n(a, ino), n(b, outo) - n(a, outo)
        pick = lambda base: n(a, f"{base}.{ix}")
        return dict(ok=True, router=r.get("name"), down_bps=max(do, 0) * 8 / dt, up_bps=max(di, 0) * 8 / dt,
                    oper={1: "up", 2: "down"}.get(int(pick("1.3.6.1.2.1.2.2.1.8") or 0)),
                    in_errors=pick("1.3.6.1.2.1.2.2.1.14"), out_errors=pick("1.3.6.1.2.1.2.2.1.20"),
                    in_discards=pick("1.3.6.1.2.1.2.2.1.13"), out_discards=pick("1.3.6.1.2.1.2.2.1.19"))
    except Exception as e:
        return dict(ok=False, error=str(e))


# ------------------------------------------------------------------ user directory (suggestions)
def list_users(r):
    """All PPPoE secrets + active sessions of one router (names, comments)."""
    api = _connect(r)
    try:
        sec = list(api.path("ppp", "secret").select(Key("name"), Key("comment"), Key("disabled")))
        act = list(api.path("ppp", "active").select(Key("name"), Key("address")))
    finally:
        api.close()
    return sec, act


def lookup(uid, routers):
    """Live check whether a PPPoE user exists (secret or active session)."""
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            api = _connect(r)
        except Exception:
            continue
        try:
            sec = _safe(lambda: _q(api, ("ppp", "secret"), ["name", "comment"], "name", uid), [])
            act = _safe(lambda: _q(api, ("ppp", "active"), ["name"], "name", uid), [])
            if sec or act:
                return dict(router_id=r["id"], comment=(sec[0].get("comment") or "") if sec else "")
        finally:
            api.close()
    return None
