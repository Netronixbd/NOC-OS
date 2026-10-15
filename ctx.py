"""Shared helpers: DB -> plain dicts for routers/OLTs, search, and the one-call diagnosis."""
import json
from datetime import datetime, timedelta

import diag
import mikrotik
import olt as oltlib
import rusers
import snmp
import util
from db import OLT, Complaint, Customer, OltProfile, Router, SessionLocal


def router_dicts(db, prefer=None):
    rs = db.query(Router).all()
    rs.sort(key=lambda r: r.id != prefer)
    return [dict(id=r.id, name=r.name, host=r.host, port=r.port, username=r.username, password=r.password,
                 use_ssl=r.use_ssl, api_enabled=r.api_enabled is not False, snmp_enabled=bool(r.snmp_enabled),
                 snmp_port=r.snmp_port or 161, snmp_community=r.snmp_community or "public") for r in rs]


def all_routers_fresh():
    with SessionLocal() as db:
        return router_dicts(db)


def profile_dict(p):
    if not p:
        return dict(id=None, name="(no profile)", enterprise_oid="", index_template="{ifindex}", oids={}, status_map={})
    try:
        oids = json.loads(p.oids or "{}")
    except ValueError:
        oids = {}
    return dict(id=p.id, name=p.name, enterprise_oid=p.enterprise_oid or "", index_template=p.index_template or "{ifindex}",
                oids=oids, status_map=oltlib.parse_status_map(p.status_map))


def olt_dict(o, profs):
    return dict(id=o.id, name=o.name, vendor=o.vendor, host=o.host, port=o.snmp_port or 161,
                community=o.community or "public", version=o.snmp_version or "2c",
                vlans=[v.strip() for v in (o.vlans or "").split(",") if v.strip()],
                profile=profile_dict(profs.get(o.profile_id)))


def olt_dicts(db):
    profs = {p.id: p for p in db.query(OltProfile)}
    return [olt_dict(o, profs) for o in db.query(OLT).filter(OLT.enabled.is_(True))]


def suggest(db, q, limit=8):
    """Customers from DB + PPPoE users read live from the routers."""
    q = q.strip()
    ql = q.lower()
    phone = util.norm_phone(q)
    cond = Customer.user_id.ilike(f"%{q}%") | Customer.name.ilike(f"%{q}%")
    if len(phone) >= 4:
        cond = cond | Customer.phone.ilike(f"%{phone}%")
    rows = db.query(Customer).filter(cond).limit(80).all()
    rows.sort(key=lambda c: (not c.user_id.lower().startswith(ql), c.user_id.lower()))
    out, seen = [], set()
    for c in rows[:limit]:
        u = rusers.get(c.user_id) or {}
        out.append(dict(uid=c.user_id, name=c.name or u.get("name", ""), phone=c.phone or u.get("phone", ""),
                        source="db", online=u.get("online")))
        seen.add(c.user_id.lower())
    for u in rusers.search(q, limit * 2):
        if len(out) >= limit:
            break
        if u["uid"].lower() in seen:
            continue
        out.append(dict(uid=u["uid"], name=u["name"], phone=u["phone"], source="router", online=u.get("online")))
        seen.add(u["uid"].lower())
    return out


def find(db, q, limit=8):
    q = q.strip()
    if util.looks_mac(q):
        mac = snmp.norm_mac(q)
        uid = mikrotik.find_by_mac(mac, router_dicts(db))
        if uid:
            u = rusers.get(uid) or {}
            c = db.query(Customer).filter_by(user_id=uid).first()
            return [dict(uid=uid, name=(c.name if c else "") or u.get("name", ""), phone=(c.phone if c else "") or u.get("phone", ""),
                         source="mac", online=True, mac=mac)]
        return [dict(uid="", name="(MAC only, no active PPPoE session)", phone="", source="mac", online=None, mac=mac)]
    return suggest(db, q, limit)


def diagnose(uid, mac=None, exclude=None):
    with SessionLocal() as db:
        cust = db.query(Customer).filter_by(user_id=uid).first() if uid else None
        hist, name, phone = None, "", ""
        if cust:
            name, phone = cust.name or "", cust.phone or ""
            q = db.query(Complaint).filter(Complaint.customer_id == cust.id,
                                           Complaint.created_at >= datetime.utcnow() - timedelta(days=30))
            if exclude:
                q = q.filter(Complaint.id != exclude)
            hist = dict(count30=q.count())
        u = rusers.get(uid) if uid else None
        if u:
            name, phone = name or u["name"], phone or u["phone"]
        d = diag.collect(uid, mac, cust.onu_mac if cust else None,
                         router_dicts(db, cust.router_id if cust else None), olt_dicts(db), history=hist)
        d["name"], d["phone"] = name, phone
        d["report"] = diag.summary(d, True)
        d["reply_bn"] = diag.customer_reply(d, "bn", name)
        d["reply_en"] = diag.customer_reply(d, "en", name)
        d["tickets"] = [dict(id=c.id, category=c.category, status=c.status)
                        for c in (cust.complaints if cust else []) if c.status != "closed"]
        return d
