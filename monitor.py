"""Background health monitor: routers (API/SNMP) + OLTs (IF-MIB). Keeps a live snapshot and raises alarms."""
import collections
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html import escape

import ctx
import mikrotik
import olt as oltlib
import telegram_bot
from db import OLT, Alarm, OltProfile, SessionLocal, get_setting

log = logging.getLogger("monitor")
SNAP = dict(ts=0, interval=30, routers=[], olts=[])
HIST = {}                 # key -> deque[(ts, value)]
FAILS = collections.Counter()
_lock = threading.Lock()
_poll_lock = threading.Lock()


def cfg(key, default):
    try:
        return float(get_setting(key, "") or default)
    except ValueError:
        return float(default)


def _hist(key, val, window=3600):
    d = HIST.setdefault(key, collections.deque(maxlen=240))
    now = time.time()
    peak = max([v for t, v in d if now - t <= window] or [val])
    d.append((now, val))
    return peak


# ------------------------------------------------------------------ alarms
def _notify(text):
    try:
        telegram_bot.send(text)
    except Exception:
        pass


def raise_alarm(key, level, device, message):
    with SessionLocal() as db:
        a = db.query(Alarm).filter(Alarm.key == key, Alarm.cleared_at.is_(None)).first()
        if a:
            changed = a.level != level
            a.last_seen, a.message, a.level = datetime.utcnow(), message, level
            db.commit()
            if changed and level == "critical":
                _notify(f"🚨 <b>ALARM escalated</b> · {escape(device)}\n{escape(message)}")
            return
        db.add(Alarm(key=key, level=level, device=device, message=message))
        db.commit()
    _notify(f"{'🚨' if level == 'critical' else '⚠️'} <b>ALARM</b> · {escape(device)}\n{escape(message)}")


def clear_alarm(key):
    with SessionLocal() as db:
        a = db.query(Alarm).filter(Alarm.key == key, Alarm.cleared_at.is_(None)).first()
        if not a:
            return
        a.cleared_at = datetime.utcnow()
        dev, msg = a.device, a.message
        db.commit()
    _notify(f"✅ <b>Cleared</b> · {escape(dev)}\n{escape(msg)}")


# ------------------------------------------------------------------ evaluation
def evaluate_router(r, s):
    key = f"router:{r['id']}"
    name = r["name"]
    if not s["ok"]:
        FAILS[key] += 1
        if FAILS[key] >= 2:
            raise_alarm(key + ":down", "critical", name, f"Router unreachable ({s.get('error') or 'no response'})")
        return
    FAILS[key] = 0
    clear_alarm(key + ":down")
    cpu = s.get("cpu")
    if cpu is not None:
        crit, warn = cfg("mon_cpu_crit", 95), cfg("mon_cpu_warn", 85)
        if cpu >= crit:
            raise_alarm(key + ":cpu", "critical", name, f"CPU load {cpu}%")
        elif cpu >= warn:
            raise_alarm(key + ":cpu", "warning", name, f"CPU load {cpu}%")
        else:
            clear_alarm(key + ":cpu")
    if s.get("active") is not None:
        peak = _hist(("r", r["id"], "active"), s["active"])
        pct = cfg("mon_drop_pct", 20)
        if peak >= 50 and s["active"] <= peak * (1 - pct / 100):
            raise_alarm(key + ":users", "critical", name, f"Active PPPoE users dropped: {peak} → {s['active']}")
        elif s["active"] >= peak * (1 - pct / 200):
            clear_alarm(key + ":users")


def evaluate_olt(o, s):
    key = f"olt:{o['id']}"
    name = o["name"]
    if not s["ok"]:
        FAILS[key] += 1
        if FAILS[key] >= 2:
            raise_alarm(key + ":down", "critical", name, f"OLT unreachable over SNMP ({s.get('error') or 'no response'})")
        return
    FAILS[key] = 0
    clear_alarm(key + ":down")
    pct = cfg("mon_pon_drop_pct", 50)
    for p in s["pons"]:
        k = f"{key}:pon:{p['pon']}"
        if p["total"] > 0 and not p["up"]:
            raise_alarm(k + ":down", "critical", name, f"PON {p['pon']} is DOWN ({p['total']} ONUs registered)")
        else:
            clear_alarm(k + ":down")
        base = _hist(("o", o["id"], p["pon"]), p["online"])
        if base >= 4 and p["online"] <= base * (1 - pct / 100) and p["up"]:
            raise_alarm(k + ":drop", "critical", name, f"PON {p['pon']}: ONUs online dropped {base} → {p['online']}")
        elif p["online"] >= base * (1 - pct / 200):
            clear_alarm(k + ":drop")
    if s["onu_supported"]:
        base = _hist(("o", o["id"], "all"), s["onu_online"])
        if base >= 10 and s["onu_online"] <= base * 0.8:
            raise_alarm(key + ":onudrop", "critical", name, f"ONUs online dropped {base} → {s['onu_online']}")
        elif s["onu_online"] >= base * 0.9:
            clear_alarm(key + ":onudrop")


# ------------------------------------------------------------------ polling
def _olt_snap(o):
    try:
        s = oltlib.snapshot(o)
    except Exception as e:
        s = dict(ok=False, error=str(e)[:150], pons=[], onu_total=0, onu_online=0, onu_supported=False)
    return s


def poll_once():
    if not _poll_lock.acquire(blocking=False):
        return
    try:
        t0 = time.time()
        with SessionLocal() as db:
            routers = ctx.router_dicts(db)
            profs = {p.id: p for p in db.query(OltProfile)}
            olts = [ctx.olt_dict(o, profs) for o in db.query(OLT).filter(OLT.enabled.is_(True))]
        with ThreadPoolExecutor(max_workers=8) as ex:
            rf = [(r, ex.submit(mikrotik.system_stats, r)) for r in routers]
            of = [(o, ex.submit(_olt_snap, o)) for o in olts]
            rs, os_ = [], []
            for r, f in rf:
                try:
                    s = f.result()
                except Exception as e:
                    s = dict(ok=False, error=str(e)[:100])
                s.update(id=r["id"], name=r["name"], host=r["host"], api=r.get("api_enabled", True), snmp=r.get("snmp_enabled"))
                rs.append(s)
            for o, f in of:
                s = f.result()
                s.update(id=o["id"], name=o["name"], host=o["host"], vendor=o.get("vendor"))
                os_.append(s)
        for r, s in zip(routers, rs):
            try:
                evaluate_router(r, s)
                h = HIST.get(("r", r["id"], "active"))
                s["spark"] = [v for _, v in list(h)[-40:]] if h else []
            except Exception:
                log.exception("router eval")
        for o, s in zip(olts, os_):
            try:
                evaluate_olt(o, s)
            except Exception:
                log.exception("olt eval")
        with _lock:
            SNAP.update(ts=time.time(), routers=rs, olts=os_, took=round(time.time() - t0, 1),
                        interval=int(cfg("mon_interval", 30)))
    finally:
        _poll_lock.release()


def snapshot():
    with _lock:
        return dict(SNAP)


def start():
    def loop():
        time.sleep(6)
        while True:
            try:
                poll_once()
            except Exception:
                log.exception("poll")
            time.sleep(max(10, cfg("mon_interval", 30)))
    threading.Thread(target=loop, daemon=True).start()
