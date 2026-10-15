"""In-memory directory of PPPoE users read from the routers (for live search suggestions)."""
import threading
import time

import mikrotik
import util

TTL = 180
_users = {}          # replaced atomically, never mutated after build
_getter = None


def _build(routers):
    users = {}
    for r in routers:
        if not r.get("api_enabled", True):
            continue
        try:
            sec, act = mikrotik.list_users(r)
        except Exception:
            continue
        for s in sec:
            n = s.get("name")
            if n:
                name, phone = util.parse_comment(s.get("comment", ""))
                users[n] = dict(uid=n, name=name, phone=phone, router_id=r["id"], router=r["name"],
                                online=False, disabled=mikrotik._flag(s.get("disabled")))
        for a in act:
            n = a.get("name")
            if not n:
                continue
            u = users.setdefault(n, dict(uid=n, name="", phone="", router_id=r["id"], router=r["name"],
                                         disabled=False))
            u["online"] = True
            u["ip"] = a.get("address")
    return users


def refresh():
    global _users
    if not _getter:
        return
    try:
        users = _build(_getter())
    except Exception:
        return
    if users:
        _users = users


def refresh_async():
    threading.Thread(target=refresh, daemon=True).start()


def start(getter):
    global _getter
    _getter = getter

    def loop():
        while True:
            refresh()
            time.sleep(TTL)
    threading.Thread(target=loop, daemon=True).start()


def size():
    return len(_users)


def get(uid):
    return _users.get(uid)


def exact(q):
    ql = (q or "").lower()
    for uid, u in _users.items():
        if uid.lower() == ql:
            return u
    return None


def search(q, limit=8):
    ql = q.lower()
    digits = util.norm_phone(q)
    pre, con = [], []
    for uid, u in _users.items():
        l = uid.lower()
        if l.startswith(ql):
            pre.append(u)
        elif ql in l or (u["name"] and ql in u["name"].lower()) or (len(digits) >= 4 and digits in u["phone"]):
            con.append(u)
    key = lambda u: u["uid"].lower()
    pre.sort(key=key)
    con.sort(key=key)
    return (pre + con)[:limit]
