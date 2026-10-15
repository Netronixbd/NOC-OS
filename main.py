import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from db import Setting
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from starlette.middleware.sessions import SessionMiddleware

import diag
import mikrotik
import olt as oltlib
import oui
import snmp
import ctx
import monitor
import interface_monitor as ifmon
import rusers
import telegram_bot
import util
from ctx import olt_dict, olt_dicts, profile_dict, router_dicts
from starlette.concurrency import run_in_threadpool
from util import looks_mac, mask_name, mask_phone, mask_uid, norm_phone, parse_comment
from db import (OLT, STATUS_LABEL, Admin, Alarm, AuditLog, Complaint, Customer, OltProfile, Router, SessionLocal,
                apply_action, audit, get_setting, init_db, set_setting)

log = logging.getLogger("portal")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY") or secrets.token_hex(32),
                   same_site="strict", max_age=8 * 3600)
templates = Jinja2Templates(directory="templates")
DHAKA = ZoneInfo("Asia/Dhaka")
templates.env.filters["dt"] = lambda d: (d.replace(tzinfo=ZoneInfo("UTC")).astimezone(DHAKA)
                                         .strftime("%d %b %Y, %I:%M %p") if d else "-")
templates.env.globals["STATUS_LABEL"] = STATUS_LABEL
CATEGORIES = ["No internet", "Slow speed", "Frequent disconnect", "Billing / payment", "Other"]
VENDORS = ["BDCOM", "VSOL", "C-Data", "Other"]


# ---------------------------------------------------------------- helpers
def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(16)
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), 200000).hex()}"


def check_pw(p, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(p, salt).split("$")[1], h)


_hits = {}


def limited(key, n, window):
    now = time.time()
    l = [t for t in _hits.get(key, []) if now - t < window]
    if len(l) >= n:
        _hits[key] = l
        return True
    l.append(now)
    _hits[key] = l
    return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def flash(request, msg, kind="ok"):
    f = request.session.get("flash", [])
    f.append([kind, msg])
    request.session["flash"] = f


def render(request, name, **ctx):
    ctx["flash"] = request.session.pop("flash", [])
    ctx["site_title"] = get_setting("site_title", "Customer Support Portal")
    ctx["site_logo"] = get_setting("site_logo_ext", "")
    ctx["is_admin"] = bool(request.session.get("admin"))
    if ctx["is_admin"]:
        with SessionLocal() as _db:
            ctx["alarm_count"] = _db.query(Alarm).filter(Alarm.cleared_at.is_(None)).count()
            ctx["admin_name"] = request.session.get("admin")
            with SessionLocal() as _role_db:
                _role_account = _role_db.query(Admin).filter_by(
                    username=request.session.get("admin")
                ).first()
                ctx["admin_role"] = getattr(_role_account, "role", "admin") if _role_account else ""
    ctx["path"] = request.url.path
    if not ctx.get("title"):
        for pre, ttl in (("/admin/devices", "Devices"), ("/admin/customers", "Users"), ("/admin/users", "Users"),
                         ("/admin/tickets", "Tickets"), ("/admin/complaints", "Tickets"), ("/admin/diagnose", "Diagnose"),
                         ("/admin/d", "Customer diagnosis"), ("/admin/alarms", "Alarms"), ("/admin/audit", "Activity log"),
                         ("/admin/settings", "Settings"), ("/admin", "Dashboard")):
            if request.url.path.startswith(pre):
                ctx["title"] = ttl
                break
    return templates.TemplateResponse(request, name, ctx)


class NeedLogin(Exception):
    pass


@app.exception_handler(NeedLogin)
def _need_login(request, exc):
    return RedirectResponse("/admin/login", 303)


# ISP_ROLE_ACCESS_V1
def admin_required(request: Request):
    from fastapi import HTTPException
    username = request.session.get("admin")
    if not username:
        raise NeedLogin()

    with SessionLocal() as db:
        account = db.query(Admin).filter_by(username=username).first()
        if not account:
            request.session.clear()
            raise NeedLogin()
        role = getattr(account, "role", "admin") or "admin"

    request.state.admin_role = role
    if request.method.upper() not in ("GET", "HEAD", "OPTIONS") and role == "read_only":
        raise HTTPException(status_code=403, detail="Read Access account is view-only.")
    return role


ADMIN = [Depends(admin_required)]


def require_super_admin(request: Request):
    from fastapi import HTTPException
    if getattr(request.state, "admin_role", "") != "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin permission required.")


@app.on_event("startup")
def startup():
    if not os.getenv("SECRET_KEY"):
        log.warning("SECRET_KEY is not configured. Session cookies will be invalidated on each restart; set a persistent random SECRET_KEY in the service environment.")
    init_db()
    with SessionLocal() as db:
        accounts = db.query(Admin).all()
        if not accounts:
            user = os.getenv("ADMIN_USER", "admin")
            pw = os.getenv("ADMIN_PASS")
            if not pw:
                pw = secrets.token_urlsafe(18)
                log.error("Initial admin password was generated but not displayed. Set ADMIN_PASS in .env and restart.")
            db.add(Admin(username=user, password_hash=hash_pw(pw), role="super_admin"))
            db.commit()
        else:
            # One-time bootstrap: ensure there is a Super Admin, without
            # overwriting roles once a Super Admin already exists.
            if not any((getattr(a, "role", "") == "super_admin") for a in accounts):
                primary = next((a for a in accounts if a.username == "admin"), None)
                if primary is None and len(accounts) == 1:
                    primary = accounts[0]
                if primary is not None:
                    primary.role = "super_admin"
                    db.commit()
    oui.background_init()
    rusers.start(ctx.all_routers_fresh)
    monitor.start()
    ifmon.start()
    telegram_bot.start_poller()


# ================================================================ public portal
@app.get("/")
def home(request: Request):
    return render(request, "index.html", results=None, q="")


@app.get("/brand-logo")
def brand_logo():
    """Serve the currently configured portal logo without exposing upload paths."""
    ext = get_setting("site_logo_ext", "").lower()
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext)
    if not mime:
        return Response(status_code=404)
    path = os.path.join(os.path.dirname(__file__), "data", "portal-logo." + ext)
    try:
        with open(path, "rb") as f:
            payload = f.read(2 * 1024 * 1024 + 1)
        if len(payload) > 2 * 1024 * 1024:
            return Response(status_code=413)
        return Response(content=payload, media_type=mime, headers={"Cache-Control": "no-cache"})
    except OSError:
        return Response(status_code=404)


def adopt_router_user(db, uid):
    """Customer typed a PPPoE user ID that is not in our customer table: build the record from the router."""
    if not re.fullmatch(r"\S{3,64}", uid):
        return None
    u = rusers.exact(uid)
    if u:
        name, phone, rid, canon = u["name"], u["phone"], u["router_id"], u["uid"]
    else:
        info = mikrotik.lookup(uid, router_dicts(db))
        if not info:
            return None
        (name, phone), rid, canon = parse_comment(info["comment"]), info["router_id"], uid
    c = db.query(Customer).filter_by(user_id=canon).first()
    if not c:
        c = Customer(user_id=canon, token=secrets.token_hex(8), name=name or canon, phone=norm_phone(phone), router_id=rid)
        db.add(c)
        db.commit()
        db.refresh(c)
    return c


@app.post("/search")
def search(request: Request, q: str = Form(""), db=Depends(get_db)):
    q = q.strip()
    if limited(f"s:{request.client.host}", 25, 600):
        flash(request, "Too many searches. Please wait a few minutes.", "err")
        return RedirectResponse("/", 303)
    if len(q) < 3:
        flash(request, "Please enter at least 3 characters.", "err")
        return RedirectResponse("/", 303)
    qs = db.query(Customer)
    found = qs.filter(func.lower(Customer.user_id) == q.lower()).all()
    digits = norm_phone(q)
    if not found and len(digits) >= 10:
        found = qs.filter(Customer.phone == digits).all()
    if not found:
        c = adopt_router_user(db, q)
        if c:
            return RedirectResponse(f"/c/{c.token}", 303)
    if len(found) == 1:
        return RedirectResponse(f"/c/{found[0].token}", 303)
    if not found:
        found = qs.filter(Customer.name.ilike(f"%{q}%")).limit(10).all()
    return render(request, "index.html", results=[
        dict(token=c.token, name=c.name or "-", uid=mask_uid(c.user_id), phone=mask_phone(c.phone))
        for c in found], q=q)


@app.get("/api/suggest")
def api_suggest(request: Request, q: str = "", db=Depends(get_db)):
    q = q.strip()
    if get_setting("public_suggest", "1") != "1" or len(q) < 3 or limited(f"sg:{request.client.host}", 80, 600):
        return JSONResponse([])
    return JSONResponse([dict(uid=i["uid"], name=mask_name(i["name"])) for i in ctx.suggest(db, q, 6)])


def get_cust(db, token):
    return db.query(Customer).filter_by(token=token).first()


@app.get("/c/{token}")
def customer_page(request: Request, token: str, db=Depends(get_db)):
    c = get_cust(db, token)
    if not c:
        return RedirectResponse("/", 303)
    st = mikrotik.status(c.user_id, router_dicts(db, c.router_id))
    return render(request, "customer.html", c=c, phone=mask_phone(c.phone), st=st,
                  cats=CATEGORIES, complaints=c.complaints[:10])


_pon_alerts = {}


def notify_new(cid):
    """Background: post the complaint, then a threaded auto-diagnosis (verdict + draft reply) to Telegram."""
    with SessionLocal() as db:
        c = db.get(Complaint, cid)
        cust = c.customer
        d, same = None, 0
        try:
            d = ctx.diagnose(cust.user_id, None, exclude=cid)
            opt = d.get("optical") or {}
            if opt.get("found"):
                c.olt_name, c.pon = opt.get("olt") or "", opt.get("pon") or ""
            lines = list(d["report"])
            if c.pon:
                same = db.query(Complaint).filter(
                    Complaint.olt_name == c.olt_name, Complaint.pon == c.pon, Complaint.status != "closed",
                    Complaint.created_at >= datetime.utcnow() - timedelta(hours=1), Complaint.id != c.id).count()
            if same >= 2:
                lines.append(f"🚨 {same} other open complaints on {c.olt_name} PON {c.pon} in the last hour: possible PON / fiber outage")
                d["report"] = lines
            c.diag_json = json.dumps(dict(lines=lines, reply_bn=d["reply_bn"], reply_en=d["reply_en"]), ensure_ascii=False)
        except Exception as e:
            log.warning("diag failed: %s", e)
        try:
            res = telegram_bot.send(telegram_bot.complaint_text(c, cust), buttons=telegram_bot.buttons_for(c.id))
            c.tg_message_id = res["message_id"]
            if d:
                r2 = telegram_bot.send(telegram_bot.diag_reply_text(c, d), rows=telegram_bot.draft_rows(c.id),
                                       reply_to=c.tg_message_id)
                c.tg_diag_message_id = r2["message_id"]
            key = (c.olt_name, c.pon)
            if same >= 2 and time.time() - _pon_alerts.get(key, 0) > 3600:
                _pon_alerts[key] = time.time()
                telegram_bot.send(f"🚨 <b>Possible PON outage</b>\n{same + 1} open complaints on {c.olt_name} PON {c.pon} within 1 hour.")
        except Exception as e:
            c.notify_error = str(e)[:250]
            log.warning("Telegram notify failed: %s", e)
        db.commit()


@app.post("/c/{token}/complaint")
def complaint_submit(request: Request, bg: BackgroundTasks, token: str, category: str = Form(...),
                     message: str = Form(""), contact_phone: str = Form(""), db=Depends(get_db)):
    c = get_cust(db, token)
    if not c:
        return RedirectResponse("/", 303)
    back = RedirectResponse(f"/c/{token}", 303)
    if category not in CATEGORIES:
        category = "Other"
    open_n = db.query(Complaint).filter(Complaint.customer_id == c.id, Complaint.status != "closed").count()
    if open_n >= 3 or limited(f"c:{c.id}", 3, 3600):
        flash(request, "You already have open complaints. Our team is working on them.", "err")
        return back
    cm = Complaint(customer_id=c.id, category=category, message=message.strip()[:1000],
                   contact_phone=norm_phone(contact_phone)[:15])
    db.add(cm)
    db.commit()
    db.refresh(cm)
    bg.add_task(notify_new, cm.id)
    flash(request, f"Your complaint #{cm.id} has been received. We will fix it as soon as possible.")
    return back


@app.post("/c/{token}/followup/{cid}")
def customer_followup(request: Request, token: str, cid: int, message: str = Form(""), db=Depends(get_db)):
    c = get_cust(db, token)
    cm = db.get(Complaint, cid)
    back = RedirectResponse(f"/c/{token}", 303)
    if not c or not cm or cm.customer_id != c.id or cm.status == "closed" or not message.strip():
        return back
    if limited(f"f:{c.id}", 6, 3600):
        flash(request, "Too many messages. Please wait.", "err")
        return back
    apply_action(db, cid, "reply", c.name or c.user_id, message, "customer")
    try:
        if cm.tg_message_id:
            from html import escape
            telegram_bot.send(f"💬 <b>Customer follow-up on #{cid}</b>\n{escape(message.strip()[:600])}",
                              reply_to=cm.tg_message_id)
    except Exception:
        pass
    flash(request, "Your message was sent to our team.")
    return back


# ================================================================ admin auth
@app.get("/admin/login")
def login_page(request: Request):
    return render(request, "admin_login.html")


@app.post("/admin/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), db=Depends(get_db)):
    if limited(f"l:{request.client.host}", 8, 600):
        flash(request, "Too many attempts. Try again later.", "err")
        return RedirectResponse("/admin/login", 303)
    a = db.query(Admin).filter_by(username=username).first()
    if a and check_pw(password, a.password_hash):
        request.session["admin"] = a.username
        return RedirectResponse("/admin", 303)
    flash(request, "Wrong username or password.", "err")
    return RedirectResponse("/admin/login", 303)


@app.get("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", 303)


# ================================================================ admin: complaints
@app.get("/admin/tickets", dependencies=ADMIN)
@app.get("/admin/complaints", dependencies=ADMIN)
def admin_home(request: Request, status: str = "active", db=Depends(get_db)):
    q = db.query(Complaint)
    if status == "active":
        q = q.filter(Complaint.status != "closed")
    elif status in STATUS_LABEL:
        q = q.filter(Complaint.status == status)
    since = datetime.utcnow() - timedelta(hours=24)
    stats = dict(active=db.query(Complaint).filter(Complaint.status != "closed").count(),
                 today=db.query(Complaint).filter(Complaint.created_at >= since).count(),
                 closed=db.query(Complaint).filter_by(status="closed").count(),
                 customers=db.query(Customer).count())
    items = q.order_by(Complaint.id.desc()).limit(200).all()
    snaps = {}
    for x in items:
        try:
            snaps[x.id] = json.loads(x.diag_json or "{}").get("lines", [])
        except ValueError:
            snaps[x.id] = []
    return render(request, "admin_complaints.html", items=items, status=status, stats=stats, snaps=snaps)


@app.post("/admin/complaints/{cid}/act", dependencies=ADMIN)
def complaint_act(request: Request, cid: int, action: str = Form(...), message: str = Form(""),
                  db=Depends(get_db)):
    by = request.session["admin"]
    back = RedirectResponse(request.headers.get("referer") or "/admin/tickets", 303)
    if action not in ("wait", "reply", "close"):
        return back
    if action == "reply" and not message.strip():
        flash(request, "Write a reply message first.", "err")
        return back
    c = apply_action(db, cid, action, by, message)
    if not c:
        flash(request, "Complaint not found or already closed.", "err")
        return back
    from html import escape
    txt = {"wait": f"⏳ #{cid} → Waiting for update (by {escape(by)})",
           "reply": f"💬 #{cid} reply by {escape(by)}:\n{escape(message.strip()[:500])}",
           "close": f"✅ #{cid} closed by {escape(by)}" + (f"\n📝 {escape(message.strip()[:300])}" if message.strip() else "")}[action]
    try:
        telegram_bot.send(txt, reply_to=c.tg_message_id)
        if action == "close" and c.tg_message_id:
            telegram_bot._remove_buttons(get_setting("tg_chat_id"), c.tg_message_id)
    except Exception:
        pass
    flash(request, f"Complaint #{cid} updated.")
    return back


# ================================================================ admin: diagnose
@app.get("/admin/diagnose", dependencies=ADMIN)
def diagnose_search(request: Request, q: str = "", db=Depends(get_db)):
    q = q.strip()
    results = None
    if q:
        results = ctx.find(db, q)
        if len(results) == 1:
            r = results[0]
            return RedirectResponse(f"/admin/d?uid={r['uid']}&mac={r.get('mac', '')}", 303)
    recent = db.query(Complaint).filter(Complaint.status != "closed").order_by(Complaint.id.desc()).limit(8).all()
    return render(request, "admin_diagnose.html", q=q, results=results, recent=recent)


@app.get("/admin/api/suggest", dependencies=ADMIN)
def admin_suggest(q: str = "", db=Depends(get_db)):
    q = q.strip()
    if len(q) < 2:
        return JSONResponse([])
    return JSONResponse(ctx.suggest(db, q, 10))


@app.get("/admin/d", dependencies=ADMIN)
def diag_page(request: Request, uid: str = "", mac: str = "", db=Depends(get_db)):
    cust = db.query(Customer).filter_by(user_id=uid).first() if uid else None
    return render(request, "admin_diag.html", uid=uid, mac=mac, cust=cust)


@app.get("/admin/api/diag", dependencies=ADMIN)
async def api_diag(uid: str = "", mac: str = ""):
    try:
        return JSONResponse(await run_in_threadpool(ctx.diagnose, uid, mac or None))
    except Exception as e:
        log.exception("diag failed")
        return JSONResponse(dict(error=str(e)), status_code=500)


@app.get("/admin/api/ping", dependencies=ADMIN)
async def api_ping(uid: str):
    return JSONResponse(await run_in_threadpool(lambda: mikrotik.ping(uid, ctx.all_routers_fresh())))


@app.get("/admin/api/live", dependencies=ADMIN)
async def api_live(uid: str):
    return JSONResponse(await run_in_threadpool(lambda: mikrotik.session_live(uid, ctx.all_routers_fresh())))


@app.post("/admin/api/disconnect", dependencies=ADMIN)
async def api_disconnect(request: Request, uid: str = Form(...)):
    res = await run_in_threadpool(lambda: mikrotik.disconnect(uid, ctx.all_routers_fresh()))
    with SessionLocal() as db:
        audit(db, request.session["admin"], "disconnect", uid, "ok" if res.get("ok") else res.get("error", ""))
    return JSONResponse(res)


@app.post("/admin/diag/telegram", dependencies=ADMIN)
async def diag_to_telegram(request: Request, uid: str = Form(...), cid: int = Form(0)):
    """Option 3: post the full technical report (verdict + findings) to the Telegram group."""
    d = await run_in_threadpool(ctx.diagnose, uid, None)
    reply_to = None
    if cid:
        with SessionLocal() as db:
            c = db.get(Complaint, cid)
            reply_to = (c.tg_diag_message_id or c.tg_message_id) if c else None
    txt = f"🔎 <b>Diagnosis report · {util_escape(uid)}</b>\n" + "\n".join(util_escape(l) for l in d["report"])
    try:
        await run_in_threadpool(lambda: telegram_bot.send(txt, reply_to=reply_to))
        with SessionLocal() as db:
            audit(db, request.session["admin"], "tg_report", uid)
        return JSONResponse(dict(ok=True))
    except Exception as e:
        return JSONResponse(dict(ok=False, error=str(e)))


def util_escape(s):
    from html import escape
    return escape(str(s))


# ================================================================ admin: dashboard / alarms / audit

# ---- Read-only device details pages; credentials are deliberately excluded.
@app.get("/admin/device-details/router/{rid}", dependencies=ADMIN)
def router_details_page(request: Request, rid: int, db=Depends(get_db)):
    r = db.get(Router, rid)
    if not r:
        return RedirectResponse("/admin/devices", 303)
    snap = monitor.snapshot()
    live = next((x for x in snap.get("routers", []) if x.get("id") == rid), {})
    return render(request, "admin_device_details.html",
                  title=f"Router Details: {r.name}", kind="router",
                  device=r, live=live, back="/admin")


@app.get("/admin/device-details/olt/{oid}", dependencies=ADMIN)
def olt_details_page(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    if not o:
        return RedirectResponse("/admin/devices", 303)
    snap = monitor.snapshot()
    live = next((x for x in snap.get("olts", []) if x.get("id") == oid), {})
    profile = db.get(OltProfile, o.profile_id) if o.profile_id else None
    return render(request, "admin_device_details.html",
                  title=f"OLT Details: {o.name}", kind="olt",
                  device=o, live=live, profile=profile, back="/admin")



# DASHBOARD_USER_PREFERENCES_V1
_DASHBOARD_PREF_KEYS = {
    "ispPortalDashboardLayoutV1",
    "ispPortalHiddenDevicesV1",
    "ispPortalRefreshRate",
    "ispPortalRecentHistoryV1",
}

def _dashboard_pref_key(username):
    # Fixed-length key compatible with the existing settings table schema.
    return "dp:" + hashlib.sha256((username or "").encode("utf-8")).hexdigest()[:32]


@app.get("/admin/api/dashboard/preferences", dependencies=ADMIN)
def get_dashboard_preferences(request: Request):
    username = request.session.get("admin", "")
    with SessionLocal() as db:
        row = db.get(Setting, _dashboard_pref_key(username))
        try:
            saved = json.loads(row.value or "{}") if row else {}
        except (TypeError, ValueError):
            saved = {}
    if not isinstance(saved, dict):
        saved = {}
    return JSONResponse({
        k: v for k, v in saved.items()
        if k in _DASHBOARD_PREF_KEYS and isinstance(v, str)
    })


@app.put("/admin/api/dashboard/preferences", dependencies=ADMIN)
async def put_dashboard_preferences(request: Request):
    from fastapi import HTTPException

    raw = await request.body()
    if len(raw) > 65536:
        raise HTTPException(status_code=413, detail="Dashboard preferences are too large.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid preferences JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Preferences must be a JSON object.")

    clean = {
        k: v for k, v in payload.items()
        if k in _DASHBOARD_PREF_KEYS and isinstance(v, str)
    }
    username = request.session.get("admin", "")
    key = _dashboard_pref_key(username)
    with SessionLocal() as db:
        row = db.get(Setting, key)
        if row is None:
            row = Setting(key=key, value="{}")
            db.add(row)
        row.value = json.dumps(clean, ensure_ascii=False, separators=(",", ":"))
        db.commit()
    return JSONResponse({"ok": True})


@app.get("/admin", dependencies=ADMIN)
def dashboard(request: Request):
    username = request.session.get("admin", "")
    with SessionLocal() as db:
        row = db.get(Setting, _dashboard_pref_key(username))
        try:
            prefs = json.loads(row.value or "{}") if row else {}
        except (TypeError, ValueError):
            prefs = {}
    if not isinstance(prefs, dict):
        prefs = {}
    prefs = {
        k: v for k, v in prefs.items()
        if k in _DASHBOARD_PREF_KEYS and isinstance(v, str)
    }
    return render(request, "admin_dashboard.html", dashboard_preferences=prefs)


@app.get("/admin/api/dashboard", dependencies=ADMIN)
async def api_dashboard(refresh: int = 0):
    if refresh:
        await run_in_threadpool(monitor.poll_once)
    snap = monitor.snapshot()
    with SessionLocal() as db:
        alarms = [dict(id=a.id, level=a.level, device=a.device, message=a.message, key=a.key, ack=a.ack_by,
                       since=int((datetime.utcnow() - a.created_at).total_seconds()))
                  for a in db.query(Alarm).filter(Alarm.cleared_at.is_(None)).order_by(Alarm.id.desc()).limit(30)]
        tk = dict(open=db.query(Complaint).filter(Complaint.status != "closed").count(),
                  today=db.query(Complaint).filter(Complaint.created_at >= datetime.utcnow() - timedelta(hours=24)).count())
    snap.update(alarms=alarms, tickets=tk, age=int(time.time() - snap["ts"]) if snap["ts"] else None)
    return JSONResponse(snap)


@app.get("/admin/alarms", dependencies=ADMIN)
def alarms_page(request: Request, db=Depends(get_db)):
    active = db.query(Alarm).filter(Alarm.cleared_at.is_(None)).order_by(Alarm.id.desc()).all()
    hist = db.query(Alarm).filter(Alarm.cleared_at.isnot(None)).order_by(Alarm.id.desc()).limit(60).all()
    return render(request, "admin_alarms.html", active=active, hist=hist)


@app.post("/admin/alarms/{aid}/ack", dependencies=ADMIN)
def alarm_ack(request: Request, aid: int, db=Depends(get_db)):
    a = db.get(Alarm, aid)
    if a:
        a.ack_by = request.session["admin"]
        db.commit()
    return RedirectResponse("/admin/alarms", 303)


@app.get("/admin/audit", dependencies=ADMIN)
def audit_page(request: Request, db=Depends(get_db)):
    return render(request, "admin_audit.html", items=db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all())


# ================================================================ admin: PPPoE user management (router write access)
@app.get("/admin/api/profiles", dependencies=ADMIN)
async def api_profiles(router: int, db=Depends(get_db)):
    r = next((x for x in router_dicts(db) if x["id"] == router), None)
    if not r:
        return JSONResponse([])
    try:
        return JSONResponse(await run_in_threadpool(mikrotik.list_profiles, r))
    except Exception as e:
        return JSONResponse(dict(error=str(e)), status_code=500)


@app.get("/admin/users/new", dependencies=ADMIN)
def user_new(request: Request, db=Depends(get_db)):
    return render(request, "admin_user_new.html", routers=[r for r in db.query(Router).all() if r.api_enabled is not False],
                  pw=secrets.token_urlsafe(8))


@app.post("/admin/users/new", dependencies=ADMIN)
async def user_create(request: Request, db=Depends(get_db)):
    f = await request.form()
    rid, uid = int(f.get("router") or 0), (f.get("user_id") or "").strip()
    r = next((x for x in router_dicts(db) if x["id"] == rid), None)
    if not r or not uid or not f.get("password"):
        flash(request, "Router, user ID and password are required.", "err")
        return RedirectResponse("/admin/users/new", 303)
    name, phone = (f.get("name") or "").strip(), norm_phone(f.get("phone") or "")
    comment = " ".join(x for x in (name, phone) if x)
    try:
        await run_in_threadpool(mikrotik.create_secret, r, uid, f["password"], f.get("profile") or "default", comment,
                                f.get("service") or "pppoe")
    except Exception as e:
        flash(request, f"Router refused: {e}", "err")
        return RedirectResponse("/admin/users/new", 303)
    upsert_customer(db, uid, name or uid, phone, (f.get("address") or "").strip(), router_id=rid)
    db.commit()
    audit(db, request.session["admin"], "user_create", uid, f"router={r['name']} profile={f.get('profile')}")
    rusers.refresh_async()
    flash(request, f"PPPoE user '{uid}' created on {r['name']}.")
    return RedirectResponse(f"/admin/users/manage?uid={uid}", 303)


@app.get("/admin/users/manage", dependencies=ADMIN)
async def user_manage(request: Request, uid: str, db=Depends(get_db)):
    cust = db.query(Customer).filter_by(user_id=uid).first()
    routers = router_dicts(db, cust.router_id if cust else None)
    sec, rname, rid, err = None, None, None, ""
    for r in routers:
        if not r["api_enabled"]:
            continue
        try:
            sec = await run_in_threadpool(mikrotik.secret_get, r, uid)
        except Exception as e:
            err = str(e)
            continue
        if sec:
            rname, rid = r["name"], r["id"]
            break
    return render(request, "admin_user_manage.html", uid=uid, cust=cust, sec=sec, rname=rname, rid=rid, err=err)


@app.post("/admin/users/manage", dependencies=ADMIN)
async def user_manage_act(request: Request, db=Depends(get_db)):
    f = await request.form()
    uid, act, rid = (f.get("uid") or ""), f.get("action"), int(f.get("rid") or 0)
    r = next((x for x in router_dicts(db) if x["id"] == rid), None)
    back = RedirectResponse(f"/admin/users/manage?uid={uid}", 303)
    if not r:
        flash(request, "Router not found.", "err")
        return back
    try:
        if act == "password":
            await run_in_threadpool(mikrotik.secret_set, r, uid, password=f.get("password"))
        elif act == "profile":
            await run_in_threadpool(mikrotik.secret_set, r, uid, profile=f.get("profile"))
        elif act in ("enable", "disable"):
            await run_in_threadpool(mikrotik.secret_set, r, uid, disabled=(act == "disable"))
            if act == "disable":
                await run_in_threadpool(mikrotik.disconnect, uid, [r])
        elif act == "remove":
            await run_in_threadpool(mikrotik.secret_remove, r, uid)
            audit(db, request.session["admin"], "user_remove", uid, r["name"])
            flash(request, f"Secret '{uid}' removed from {r['name']}.")
            return RedirectResponse("/admin/customers", 303)
        audit(db, request.session["admin"], f"user_{act}", uid, r["name"])
        flash(request, f"Done: {act}.")
    except Exception as e:
        flash(request, f"Router refused: {e}", "err")
    return back


# ================================================================ admin: customers
@app.get("/admin/customers", dependencies=ADMIN)
def admin_customers(request: Request, q: str = "", db=Depends(get_db)):
    qs = db.query(Customer)
    if q:
        like = f"%{q}%"
        qs = qs.filter(Customer.user_id.ilike(like) | Customer.name.ilike(like) | Customer.phone.ilike(like))
    return render(request, "admin_customers.html", items=qs.order_by(Customer.id.desc()).limit(300).all(),
                  q=q, total=db.query(Customer).count())


def upsert_customer(db, user_id, name="", phone="", address="", router_id=None, overwrite=True):
    user_id = user_id.strip()
    if not user_id:
        return None
    c = db.query(Customer).filter_by(user_id=user_id).first()
    if not c:
        db.add(Customer(user_id=user_id, token=secrets.token_hex(8), name=name, phone=norm_phone(phone),
                        address=address, router_id=router_id))
        return "new"
    if overwrite or not c.name:
        c.name = name or c.name
    if (overwrite or not c.phone) and phone:
        c.phone = norm_phone(phone)
    if address:
        c.address = address
    if router_id and not c.router_id:
        c.router_id = router_id
    return "updated"


@app.post("/admin/customers/add", dependencies=ADMIN)
def customer_add(request: Request, user_id: str = Form(...), name: str = Form(""), phone: str = Form(""),
                 address: str = Form(""), db=Depends(get_db)):
    r = upsert_customer(db, user_id, name, phone, address)
    db.commit()
    flash(request, "Customer added." if r == "new" else "Customer updated.")
    return RedirectResponse("/admin/customers", 303)


@app.post("/admin/customers/import", dependencies=ADMIN)
async def customer_import(request: Request, file: UploadFile = File(...), db=Depends(get_db)):
    text = (await file.read()).decode("utf-8-sig", errors="ignore")
    n = 0
    for row in csv.DictReader(io.StringIO(text)):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if upsert_customer(db, row.get("user_id", ""), row.get("name", ""), row.get("phone", ""), row.get("address", "")):
            n += 1
    db.commit()
    flash(request, f"{n} rows imported.")
    return RedirectResponse("/admin/customers", 303)


@app.get("/admin/customers/{cid}", dependencies=ADMIN)
def customer_edit_page(request: Request, cid: int, db=Depends(get_db)):
    c = db.get(Customer, cid)
    if not c:
        return RedirectResponse("/admin/customers", 303)
    fields = [fld("name", "Name", c.name), fld("phone", "Phone", c.phone), fld("address", "Address", c.address),
              fld("onu_mac", "ONU MAC (optional, used if router MAC lookup fails)", c.onu_mac)]
    return render(request, "admin_form.html", title=f"Edit {c.user_id}", fields=fields, back="/admin/customers",
                  action=f"/admin/customers/{cid}")


@app.post("/admin/customers/{cid}", dependencies=ADMIN)
async def customer_edit(request: Request, cid: int, db=Depends(get_db)):
    f = await request.form()
    c = db.get(Customer, cid)
    if c:
        c.name, c.phone, c.address = f.get("name", "").strip(), norm_phone(f.get("phone", "")), f.get("address", "").strip()
        c.onu_mac = snmp.norm_mac(f.get("onu_mac", "")) or ""
        db.commit()
        flash(request, "Saved.")
    return RedirectResponse("/admin/customers", 303)


@app.post("/admin/customers/{cid}/delete", dependencies=ADMIN)
def customer_delete(request: Request, cid: int, db=Depends(get_db)):
    c = db.get(Customer, cid)
    if c:
        db.delete(c)
        db.commit()
        flash(request, "Customer removed.")
    return RedirectResponse("/admin/customers", 303)


# ISP_PORTAL_PPTP_GUI_V2: multi-CCR, multi-tunnel, multi-subnet PPTP manager
import ipaddress as _pptp_ipaddress
import json as _pptp_json
import os as _pptp_os
import subprocess as _pptp_subprocess

_PPTP_INDEX_KEY = "pptp_connections_index_v2"

def _pptp_load_all():
    try:
        ids = _pptp_json.loads(get_setting(_PPTP_INDEX_KEY, "[]") or "[]")
        if not isinstance(ids, list): ids = []
    except Exception:
        ids = []
    result = {}
    for cid in ids:
        try:
            cid = int(cid)
            raw = get_setting(f"pptp_connection_v2_{cid}", "")
            obj = _pptp_json.loads(raw) if raw else None
            if isinstance(obj, dict) and int(obj.get("connection_id", -1)) == cid:
                result[cid] = obj
        except Exception:
            continue
    # One-time migration of old single-tunnel-per-router profiles.
    if get_setting("pptp_v2_migration_done", "") != "1":
        with SessionLocal() as _legacy_db:
            for r in _legacy_db.query(Router).order_by(Router.id).all():
                try:
                    raw = get_setting(f"pptp_profile_router_{int(r.id)}", "")
                    old = _pptp_json.loads(raw) if raw else {}
                    if old.get("server_host") and old.get("username") and old.get("password"):
                        cid = int(r.id)
                        subnet = old.get("remote_subnet", "")
                        result[cid] = {"connection_id": cid, "router_id": cid,
                            "name": f"{r.name} (migrated)", "server_host": old.get("server_host", r.host),
                            "username": old.get("username", ""), "password": old.get("password", ""),
                            "subnets": [subnet] if subnet else []}
                except Exception:
                    pass
        if result: _pptp_save_all_index(result)
        set_setting("pptp_v2_migration_done", "1")
    return result

def _pptp_save_all_index(all_profiles):
    ids = sorted(int(x) for x in all_profiles)
    set_setting(_PPTP_INDEX_KEY, _pptp_json.dumps(ids))
    for cid, profile in all_profiles.items():
        set_setting(f"pptp_connection_v2_{int(cid)}", _pptp_json.dumps(profile))

def _pptp_profile(cid):
    return _pptp_load_all().get(int(cid))

def _pptp_helper(action, connection_id, payload=None):
    helper = "/usr/local/sbin/isp-portal-pptp"
    if not _pptp_os.path.isfile(helper):
        return {"ok": False, "message": "PPTP helper is not installed."}
    cmd = [helper, action, str(int(connection_id))]
    if _pptp_os.geteuid() != 0: cmd = ["sudo", "-n"] + cmd
    try:
        proc = _pptp_subprocess.run(cmd, input=_pptp_json.dumps(payload or {}), text=True,
            stdout=_pptp_subprocess.PIPE, stderr=_pptp_subprocess.STDOUT, timeout=45,
            check=False, cwd="/opt/isp-portal")
        raw = (proc.stdout or "").strip()
        try: result = _pptp_json.loads(raw.splitlines()[-1]) if raw else {}
        except Exception: result = {"ok": False, "message": raw[-700:] or "PPTP helper returned no output."}
        if proc.returncode != 0: result["ok"] = False
        return result
    except Exception as exc:
        return {"ok": False, "message": f"PPTP helper error: {exc}"}

def _pptp_redirect(cid=0):
    from fastapi.responses import RedirectResponse as _RedirectResponse
    return _RedirectResponse(f"/admin/pptp" + (f"?connection_id={int(cid)}" if cid else ""), 303)

@app.get("/admin/pptp", dependencies=ADMIN)
def admin_pptp_page(request: Request, connection_id: int = 0, db=Depends(get_db)):
    routers = db.query(Router).order_by(Router.name).all()
    profiles = _pptp_load_all()
    selected = profiles.get(connection_id) if connection_id else None
    if selected is None and profiles:
        selected = profiles[sorted(profiles)[0]]
    status = _pptp_helper("status", selected["connection_id"]) if selected else {"ok": True, "connected": False, "message": "Create a PPTP connection to begin."}
    # Do not expose passwords to the rendered page.
    safe_profiles = []
    for p in profiles.values():
        router = next((r for r in routers if r.id == int(p.get("router_id", 0))), None)
        st = _pptp_helper("status", p["connection_id"])
        safe_profiles.append({**p, "password": "", "has_password": bool(p.get("password")),
            "router_name": router.name if router else f"Router #{p.get('router_id')}",
            "connected": bool(st.get("connected")), "status_message": st.get("message", "")})
    return render(request, "admin_pptp.html", routers=routers, profiles=safe_profiles,
        selected=selected, status=status)

@app.post("/admin/pptp/save", dependencies=ADMIN)
async def admin_pptp_save(request: Request, db=Depends(get_db)):
    import secrets as _pptp_secrets
    from fastapi.responses import RedirectResponse as _RedirectResponse
    form = await request.form()
    all_profiles = _pptp_load_all()
    try:
        cid_raw = (form.get("connection_id") or "").strip()
        cid = int(cid_raw) if cid_raw else 0
        rid = int(form.get("router_id", "0"))
        if rid <= 0 or not db.get(Router, rid): raise ValueError("Select an existing CCR/router.")
        old = all_profiles.get(cid, {}) if cid else {}
        server = str(form.get("server_host") or "").strip()
        addr = _pptp_ipaddress.ip_address(server)
        if addr.version != 4: raise ValueError("PPTP server must be IPv4.")
        username = str(form.get("username") or "").strip()
        password = str(form.get("password") or "") or old.get("password", "")
        for label, value in (("username", username), ("password", password)):
            if not value or any(c.isspace() for c in value) or any(c in value for c in '"\\'):
                raise ValueError(f"{label} must be non-empty and contain no whitespace, quotes, or backslashes.")
        name = str(form.get("name") or "").strip()[:80]
        if not name: name = f"{db.get(Router, rid).name} PPTP"
        raw_subnets = str(form.get("subnets") or "")
        subnets, seen = [], set()
        for line in raw_subnets.replace(",", "\n").splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            net = _pptp_ipaddress.ip_network(line, strict=False)
            if net.version != 4 or not net.is_private or net.prefixlen == 0:
                raise ValueError(f"Invalid private IPv4 subnet: {line}")
            if str(net) not in seen: subnets.append(str(net)); seen.add(str(net))
        if not subnets: raise ValueError("Add at least one private IPv4 subnet, one CIDR per line.")
        for i, a in enumerate(subnets):
            na = _pptp_ipaddress.ip_network(a)
            for b in subnets[i+1:]:
                if na.overlaps(_pptp_ipaddress.ip_network(b)):
                    raise ValueError(f"Subnets overlap inside this connection: {a} and {b}")
        if cid and cid not in all_profiles: raise ValueError("PPTP connection not found; refresh and try again.")
        if not cid: cid = max([0, *all_profiles.keys(), *[r.id for r in db.query(Router).all()]]) + 1
        all_profiles[cid] = {"connection_id": cid, "router_id": rid, "name": name,
            "server_host": str(addr), "username": username, "password": password, "subnets": subnets}
        _pptp_save_all_index(all_profiles)
        audit(db, request.session.get("admin", ""), "pptp_save", name,
            f"connection_id={cid}; router_id={rid}; server={addr}; subnets={','.join(subnets)}; username={username}")
        flash(request, f"Saved {name} with {len(subnets)} subnet(s).")
        return _RedirectResponse(f"/admin/pptp?connection_id={cid}", 303)
    except Exception as exc:
        flash(request, f"Could not save PPTP connection: {exc}", "err")
        return _RedirectResponse(f"/admin/pptp" + (f"?connection_id={cid}" if cid else ""), 303)

@app.post("/admin/pptp/connect", dependencies=ADMIN)
def admin_pptp_connect(request: Request, connection_id: int = Form(...), db=Depends(get_db)):
    profile = _pptp_profile(connection_id)
    if not profile:
        flash(request, "PPTP connection not found.", "err"); return _pptp_redirect()
    result = _pptp_helper("connect", connection_id, profile)
    router = db.get(Router, int(profile.get("router_id", 0)))
    if result.get("ok"):
        audit(db, request.session.get("admin", ""), "pptp_connect", profile.get("name", "PPTP"),
            f"connection_id={connection_id}; server={profile.get('server_host')}; subnets={','.join(profile.get('subnets', []))}")
        flash(request, result.get("message", "PPTP connected."))
    else: flash(request, result.get("message", "PPTP connection failed."), "err")
    return _pptp_redirect(connection_id)

@app.post("/admin/pptp/disconnect", dependencies=ADMIN)
def admin_pptp_disconnect(request: Request, connection_id: int = Form(...), db=Depends(get_db)):
    profile = _pptp_profile(connection_id)
    result = _pptp_helper("disconnect", connection_id)
    if result.get("ok") and profile:
        audit(db, request.session.get("admin", ""), "pptp_disconnect", profile.get("name", "PPTP"), f"connection_id={connection_id}")
        flash(request, result.get("message", "PPTP disconnect requested."))
    else: flash(request, result.get("message", "PPTP disconnect failed."), "err")
    return _pptp_redirect(connection_id)

@app.post("/admin/pptp/delete", dependencies=ADMIN)
def admin_pptp_delete(request: Request, connection_id: int = Form(...), db=Depends(get_db)):
    all_profiles = _pptp_load_all()
    profile = all_profiles.get(connection_id)
    if not profile:
        flash(request, "PPTP connection not found.", "err"); return _pptp_redirect()
    result = _pptp_helper("delete", connection_id)
    if not result.get("ok"):
        flash(request, result.get("message", "Could not remove connection; it may still be active."), "err")
        return _pptp_redirect(connection_id)
    all_profiles.pop(connection_id, None)
    set_setting(_PPTP_INDEX_KEY, _pptp_json.dumps(sorted(all_profiles)))
    set_setting(f"pptp_connection_v2_{connection_id}", "")
    audit(db, request.session.get("admin", ""), "pptp_delete", profile.get("name", "PPTP"), f"connection_id={connection_id}")
    flash(request, "PPTP connection removed.")
    return _pptp_redirect()


# ================================================================ admin: devices (routers / OLTs / profiles)
def fld(name, label, value="", type="text", options=None, help=""):
    return dict(name=name, label=label, value=value if value is not None else "", type=type, options=options or [], help=help)


@app.get("/admin/devices", dependencies=ADMIN)
def devices_page(request: Request, db=Depends(get_db)):
    profs = db.query(OltProfile).all()
    pn = {p.id: p.name for p in profs}
    pc = {p.id: sum(1 for c in profile_dict(p)["oids"].values() if c.get("oid")) for p in profs}
    return render(request, "admin_devices.html", routers=db.query(Router).all(), olts=db.query(OLT).all(),
                  profiles=profs, pn=pn, pc=pc)


def router_fields(r=None):
    r = r or Router(name="", host="", api_enabled=True, port=8728, username="", password="", use_ssl=False,
                    snmp_enabled=False, snmp_port=161, snmp_community="public")
    return [fld("name", "Name", r.name), fld("host", "IP / host", r.host),
            fld("api_enabled", "Enable API (user details, session, logs)", r.api_enabled is not False, "checkbox"),
            fld("port", "API port (8728 / 8729 SSL)", r.port, "number"), fld("use_ssl", "Use SSL (api-ssl)", r.use_ssl, "checkbox"),
            fld("username", "API user", r.username),
            fld("password", "API password", "", "password", help="Leave blank to keep the saved password" if r.id else ""),
            fld("snmp_enabled", "Enable SNMP (live interface rate, errors)", r.snmp_enabled, "checkbox"),
            fld("snmp_port", "SNMP port", r.snmp_port or 161, "number"),
            fld("snmp_community", "SNMP community", r.snmp_community or "public")]


@app.get("/admin/devices/router/new", dependencies=ADMIN)
def router_new(request: Request):
    return render(request, "admin_form.html", title="Add MikroTik router", fields=router_fields(), back="/admin/devices",
                  action="/admin/devices/router/new")


@app.get("/admin/devices/router/{rid}", dependencies=ADMIN)
def router_edit_page(request: Request, rid: int, db=Depends(get_db)):
    r = db.get(Router, rid)
    if not r:
        return RedirectResponse("/admin/devices", 303)
    return render(request, "admin_form.html", title=f"Edit router {r.name}", fields=router_fields(r),
                  back="/admin/devices", action=f"/admin/devices/router/{rid}")


async def _save_router(request, db, r):
    f = await request.form()
    r.name, r.host = f.get("name", "").strip(), f.get("host", "").strip()
    r.api_enabled, r.use_ssl, r.snmp_enabled = bool(f.get("api_enabled")), bool(f.get("use_ssl")), bool(f.get("snmp_enabled"))
    r.port, r.snmp_port = int(f.get("port") or 8728), int(f.get("snmp_port") or 161)
    r.username, r.snmp_community = f.get("username", "").strip(), f.get("snmp_community", "").strip() or "public"
    if f.get("password"):
        r.password = f["password"]
    db.add(r)
    db.commit()


@app.post("/admin/devices/router/new", dependencies=ADMIN)
async def router_create(request: Request, db=Depends(get_db)):
    await _save_router(request, db, Router(password=""))
    rusers.refresh_async()
    flash(request, "Router added. Use Test API / Test SNMP / Sync to verify.")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/router/{rid}", dependencies=ADMIN)
async def router_update(request: Request, rid: int, db=Depends(get_db)):
    r = db.get(Router, rid)
    if r:
        await _save_router(request, db, r)
        rusers.refresh_async()
        flash(request, "Router saved.")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/router/{rid}/delete", dependencies=ADMIN)
def router_delete(request: Request, rid: int, db=Depends(get_db)):
    r = db.get(Router, rid)
    if r:
        db.query(Customer).filter_by(router_id=rid).update({"router_id": None})
        db.delete(r)
        db.commit()
        flash(request, "Router removed.")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/router/{rid}/test", dependencies=ADMIN)
def router_test(request: Request, rid: int, db=Depends(get_db)):
    try:
        flash(request, f"API connected. Router identity: {mikrotik.test(router_dicts(db, rid)[0])}")
    except Exception as e:
        flash(request, f"API connection failed: {e}", "err")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/router/{rid}/snmp-test", dependencies=ADMIN)
def router_snmp_test(request: Request, rid: int, db=Depends(get_db)):
    try:
        r = mikrotik.snmp_test(router_dicts(db, rid)[0])
        flash(request, f"SNMP OK. Name: {r['name']}, uptime ticks: {r['uptime']}")
    except Exception as e:
        flash(request, f"SNMP failed: {e}", "err")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/router/{rid}/sync", dependencies=ADMIN)
def router_sync(request: Request, rid: int, overwrite: str = Form(""), db=Depends(get_db)):
    try:
        secs = mikrotik.fetch_secrets(router_dicts(db, rid)[0])
    except Exception as e:
        flash(request, f"Sync failed: {e}", "err")
        return RedirectResponse("/admin/devices", 303)
    new = upd = 0
    for s in secs:
        uid = s.get("name")
        if not uid:
            continue
        name, phone = parse_comment(s.get("comment", ""))
        r = upsert_customer(db, uid, name or uid, phone, router_id=rid, overwrite=bool(overwrite))
        new += r == "new"
        upd += r == "updated"
    db.commit()
    rusers.refresh_async()
    flash(request, f"Sync done: {new} new, {upd} existing users from {len(secs)} PPPoE secrets.")
    return RedirectResponse("/admin/devices", 303)


# ---- OLTs
def olt_fields(o, db):
    o = o or OLT(name="", vendor="BDCOM", host="", snmp_port=161, community="public", snmp_version="2c", vlans="",
                 enabled=True)
    profs = [(str(p.id), p.name) for p in db.query(OltProfile).all()]
    return [fld("name", "OLT name", o.name), fld("vendor", "Vendor", o.vendor, "select", [(v, v) for v in VENDORS]),
            fld("host", "OLT IP", o.host), fld("snmp_port", "SNMP port", o.snmp_port or 161, "number"),
            fld("community", "SNMP community (read)", o.community),
            fld("snmp_version", "SNMP version", o.snmp_version, "select", [("2c", "v2c"), ("1", "v1")]),
            fld("profile_id", "OID profile", str(o.profile_id or ""), "select", profs),
            fld("vlans", "PPPoE VLAN IDs (optional, comma separated)", o.vlans,
                help="Only needed if the OLT FDB lookup requires community@vlan"),
            fld("enabled", "Enabled", o.enabled is not False, "checkbox")]


async def _save_olt(request, db, o):
    f = await request.form()
    o.name, o.vendor, o.host = f.get("name", "").strip(), f.get("vendor", "Other"), f.get("host", "").strip()
    o.snmp_port, o.community = int(f.get("snmp_port") or 161), f.get("community", "").strip() or "public"
    o.snmp_version = f.get("snmp_version", "2c")
    o.profile_id = int(f["profile_id"]) if f.get("profile_id") else None
    o.vlans, o.enabled = f.get("vlans", "").strip(), bool(f.get("enabled"))
    db.add(o)
    db.commit()


@app.get("/admin/devices/olt/new", dependencies=ADMIN)
def olt_new(request: Request, db=Depends(get_db)):
    return render(request, "admin_form.html", title="Add OLT", fields=olt_fields(None, db), back="/admin/devices",
                  action="/admin/devices/olt/new")


@app.post("/admin/devices/olt/new", dependencies=ADMIN)
async def olt_create(request: Request, db=Depends(get_db)):
    await _save_olt(request, db, OLT())
    flash(request, "OLT added. Test SNMP, then open Tools to set up OIDs.")
    return RedirectResponse("/admin/devices", 303)


@app.get("/admin/devices/olt/{oid}", dependencies=ADMIN)
def olt_edit_page(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    if not o:
        return RedirectResponse("/admin/devices", 303)
    return render(request, "admin_form.html", title=f"Edit OLT {o.name}", fields=olt_fields(o, db),
                  back="/admin/devices", action=f"/admin/devices/olt/{oid}")


@app.post("/admin/devices/olt/{oid}", dependencies=ADMIN)
async def olt_update(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    if o:
        await _save_olt(request, db, o)
        flash(request, "OLT saved.")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/olt/{oid}/delete", dependencies=ADMIN)
def olt_delete(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    if o:
        db.delete(o)
        db.commit()
        flash(request, "OLT removed.")
    return RedirectResponse("/admin/devices", 303)


@app.post("/admin/devices/olt/{oid}/test", dependencies=ADMIN)
def olt_test(request: Request, oid: int, db=Depends(get_db)):
    profs = {p.id: p for p in db.query(OltProfile)}
    try:
        i = oltlib.sys_info(olt_dict(db.get(OLT, oid), profs))
        flash(request, f"SNMP OK: {i['name']} | {i['descr']}")
    except Exception as e:
        flash(request, f"SNMP failed: {e}", "err")
    return RedirectResponse("/admin/devices", 303)


@app.get("/admin/devices/olt/{oid}/tools", dependencies=ADMIN)
def olt_tools(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    if not o:
        return RedirectResponse("/admin/devices", 303)
    return render(request, "admin_olt_tools.html", o=o, prof=db.get(OltProfile, o.profile_id), result=None,
                  fields=oltlib.FIELDS, form={})


def _tools_work(action, dev, prof, f):
    if action == "walk":
        rows = snmp.walk(dev, (f.get("oid_in") or "1.3.6.1.2.1.1").strip(), timeout=90)
        return dict(kind="walk", total=len(rows), rows=rows[:400])
    if action == "locate":
        m = snmp.norm_mac(f.get("mac", ""))
        if not m:
            raise ValueError("Enter a valid MAC address")
        return dict(kind="locate", data=oltlib.locate_one(dev, prof, m) or dict(found=False))
    if action == "discover":
        suf, name = (f.get("suffix") or "").strip(), None
        if not suf:
            m = snmp.norm_mac(f.get("mac", ""))
            if not m:
                raise ValueError("Enter a customer router MAC, or the ONU index suffix")
            suf, name = oltlib.resolve_suffix(dev, prof, m)
            if not suf:
                raise ValueError("MAC not found in the OLT MAC table (is that customer online?)")
        st = (f.get("start") or "").strip() or prof["enterprise_oid"] or "1.3.6.1.4.1"
        rows, total = oltlib.discover(dev, st, suf)
        known = {k[6:]: v for k, v in f.items() if k.startswith("known_") and str(v).strip()}
        best = oltlib.match_known(rows, known) if known else []
        return dict(kind="discover", rows=rows, total=total, suffix=suf, ifname=name, start=st, best=best)
    raise ValueError("Unknown action")


@app.post("/admin/devices/olt/{oid}/tools", dependencies=ADMIN)
async def olt_tools_run(request: Request, oid: int, db=Depends(get_db)):
    f = dict((await request.form()).items())
    o = db.get(OLT, oid)
    profs = {p.id: p for p in db.query(OltProfile)}
    dev = olt_dict(o, profs)
    try:
        result = await run_in_threadpool(_tools_work, f.get("action", ""), dev, dev["profile"], f)
    except Exception as e:
        flash(request, f"{f.get('action')} failed: {e}", "err")
        result = None
    return render(request, "admin_olt_tools.html", o=o, prof=db.get(OltProfile, o.profile_id), result=result,
                  fields=oltlib.FIELDS, form=f)


@app.post("/admin/devices/olt/{oid}/scan", dependencies=ADMIN)
async def olt_scan(request: Request, oid: int, db=Depends(get_db)):
    o = db.get(OLT, oid)
    dev = olt_dict(o, {p.id: p for p in db.query(OltProfile)})
    try:
        res = await run_in_threadpool(oltlib.scan, dev, dev["profile"])
    except Exception as e:
        flash(request, f"Scan failed: {e}", "err")
        return RedirectResponse(f"/admin/devices/olt/{oid}/tools", 303)
    return render(request, "admin_olt_scan.html", o=o, res=res)


@app.post("/admin/devices/profile/{pid}/assign-many", dependencies=ADMIN)
async def profile_assign_many(request: Request, pid: int, db=Depends(get_db)):
    f = await request.form()
    p = db.get(OltProfile, pid)
    if p:
        oids = profile_dict(p)["oids"]
        n = 0
        for fld_, col, div, unit in zip(f.getlist("field"), f.getlist("oid_col"), f.getlist("div"), f.getlist("unit")):
            if fld_ in dict(oltlib.FIELDS):
                oids[fld_] = dict(oid=col.strip("."), div=float(div or 1), unit=unit or "dbm")
                n += 1
        p.oids = json.dumps(oids)
        db.commit()
        flash(request, f"{n} OIDs saved to profile. Verify with Locate by MAC.")
    return RedirectResponse(f.get("back") if str(f.get("back", "")).startswith("/admin/") else "/admin/devices", 303)


# ---- profiles
@app.get("/admin/devices/profile/{pid}", dependencies=ADMIN)
def profile_page(request: Request, pid: int, db=Depends(get_db)):
    p = db.get(OltProfile, pid)
    if not p:
        return RedirectResponse("/admin/devices", 303)
    return render(request, "admin_profile.html", p=p, oids=profile_dict(p)["oids"], fields=oltlib.FIELDS)


@app.post("/admin/devices/profile/{pid}", dependencies=ADMIN)
async def profile_save(request: Request, pid: int, db=Depends(get_db)):
    p = db.get(OltProfile, pid)
    f = await request.form()
    p.name, p.vendor = f.get("name", p.name).strip(), f.get("vendor", p.vendor)
    p.enterprise_oid, p.index_template = f.get("enterprise_oid", "").strip(), f.get("index_template", "").strip() or "{ifindex}"
    p.status_map, p.notes = f.get("status_map", "").strip(), f.get("notes", "")
    oids = {}
    for key, _ in oltlib.FIELDS:
        o = f.get(f"oid_{key}", "").strip().strip(".")
        if o:
            oids[key] = dict(oid=o, div=float(f.get(f"div_{key}") or 1), unit=f.get(f"unit_{key}") or "dbm",
                             conf=f.get(f"conf_{key}") or "", index=f.get(f"index_{key}") or "ifindex")
    p.oids = json.dumps(oids)
    db.commit()
    flash(request, "Profile saved. Use OLT → Tools → Locate by MAC to verify.")
    return RedirectResponse(f"/admin/devices/profile/{pid}", 303)


@app.post("/admin/devices/profile/{pid}/assign", dependencies=ADMIN)
def profile_assign(request: Request, pid: int, field: str = Form(...), oid_col: str = Form(...),
                   div: float = Form(1), unit: str = Form("dbm"), back: str = Form("/admin/devices"),
                   db=Depends(get_db)):
    p = db.get(OltProfile, pid)
    if p and field in dict(oltlib.FIELDS):
        oids = profile_dict(p)["oids"]
        oids[field] = dict(oid=oid_col.strip("."), div=div or 1, unit=unit)
        p.oids = json.dumps(oids)
        db.commit()
        flash(request, f"Saved '{field}' → {oid_col}")
    return RedirectResponse(back if back.startswith("/admin/") else "/admin/devices", 303)


@app.post("/admin/devices/profile-new", dependencies=ADMIN)
def profile_new(request: Request, name: str = Form("New profile"), db=Depends(get_db)):
    p = OltProfile(name=name.strip() or "New profile", vendor="Other", index_template="{ifindex}", oids="{}",
                   status_map="1=Online,2=Offline")
    db.add(p)
    db.commit()
    return RedirectResponse(f"/admin/devices/profile/{p.id}", 303)


@app.post("/admin/devices/profile/{pid}/delete", dependencies=ADMIN)
def profile_delete(request: Request, pid: int, db=Depends(get_db)):
    p = db.get(OltProfile, pid)
    if p:
        db.query(OLT).filter_by(profile_id=pid).update({"profile_id": None})
        db.delete(p)
        db.commit()
        flash(request, "Profile deleted.")
    return RedirectResponse("/admin/devices", 303)


# ================================================================ admin: settings
@app.get("/admin/settings", dependencies=ADMIN)
def settings_page(request: Request):
    tok = get_setting("tg_token")
    return render(request, "admin_settings.html", tg_token_masked=(tok[:6] + "…" + tok[-4:]) if tok else "",
                  tg_chat=get_setting("tg_chat_id"), seen=telegram_bot.seen_chats, oui_n=oui.size(),
                  title=get_setting("site_title", "Customer Support Portal"),
                  public_suggest=get_setting("public_suggest", "1") == "1", ru_n=rusers.size(),
                  mon={k: get_setting(k, d) for k, d in (("mon_interval", "30"), ("mon_cpu_warn", "85"), ("mon_cpu_crit", "95"),
                                                         ("mon_drop_pct", "20"), ("mon_pon_drop_pct", "50"))})


@app.post("/admin/settings/general", dependencies=ADMIN)
def set_general(request: Request, site_title: str = Form(""), public_suggest: str = Form("")):
    require_super_admin(request)
    set_setting("site_title", site_title.strip()[:80] or "Customer Support Portal")
    set_setting("public_suggest", "1" if public_suggest else "0")
    flash(request, "Saved.")
    return RedirectResponse("/admin/settings", 303)


@app.post("/admin/settings/branding", dependencies=ADMIN)
async def set_branding(request: Request, site_title: str = Form(""), logo: UploadFile = File(None), action: str = Form("save")):
    require_super_admin(request)
    title = site_title.strip()
    if title:
        set_setting("site_title", title[:80])
    if action == "remove_logo":
        set_setting("site_logo_ext", "")
        flash(request, "Logo removed. Default branding is active.")
        return RedirectResponse("/admin/settings", 303)
    if logo is not None and logo.filename:
        raw = await logo.read(2 * 1024 * 1024 + 1)
        content_type = (logo.content_type or "").lower()
        allowed = {"image/png": ("png", b"\x89PNG\r\n\x1a\n"),
                   "image/jpeg": ("jpg", b"\xff\xd8\xff"),
                   "image/webp": ("webp", b"RIFF")}
        item = allowed.get(content_type)
        if len(raw) > 2 * 1024 * 1024:
            flash(request, "Logo file must be 2 MB or smaller.", "err")
        elif not item or not raw.startswith(item[1]) or (item[0] == "webp" and raw[8:12] != b"WEBP"):
            flash(request, "Upload a valid PNG, JPG or WEBP image.", "err")
        else:
            ext, _ = item
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(data_dir, exist_ok=True)
            for old_ext in ("png", "jpg", "jpeg", "webp"):
                old_path = os.path.join(data_dir, "portal-logo." + old_ext)
                if os.path.exists(old_path):
                    os.remove(old_path)
            with open(os.path.join(data_dir, "portal-logo." + ext), "wb") as f:
                f.write(raw)
            set_setting("site_logo_ext", ext)
            flash(request, "Portal name and logo saved.")
    else:
        flash(request, "Portal name saved. Logo unchanged.")
    return RedirectResponse("/admin/settings", 303)


@app.post("/admin/settings/monitor", dependencies=ADMIN)
async def set_monitor(request: Request):
    require_super_admin(request)
    f = await request.form()
    for k in ("mon_interval", "mon_cpu_warn", "mon_cpu_crit", "mon_drop_pct", "mon_pon_drop_pct"):
        v = (f.get(k) or "").strip()
        if v.replace(".", "", 1).isdigit():
            set_setting(k, v)
    flash(request, "Monitoring thresholds saved.")
    return RedirectResponse("/admin/settings", 303)


@app.post("/admin/settings/password", dependencies=ADMIN)
def set_password(request: Request, old: str = Form(""), new: str = Form(""), db=Depends(get_db)):
    a = db.query(Admin).filter_by(username=request.session["admin"]).first()
    if not check_pw(old, a.password_hash) or len(new) < 8:
        flash(request, "Old password wrong, or new password shorter than 8 characters.", "err")
    else:
        a.password_hash = hash_pw(new)
        db.commit()
        flash(request, "Password changed.")
    return RedirectResponse("/admin/settings", 303)


@app.post("/admin/settings/oui", dependencies=ADMIN)
async def set_oui(request: Request, file: UploadFile = File(None)):
    require_super_admin(request)
    try:
        if file is not None and file.filename:
            n = oui.save_upload(await file.read())
        else:
            n = oui.update()
        flash(request, f"OUI database loaded: {n} vendors.")
    except Exception as e:
        flash(request, f"OUI update failed: {e}", "err")
    return RedirectResponse("/admin/settings", 303)


@app.post("/admin/settings/telegram", dependencies=ADMIN)
def set_telegram(request: Request, action: str = Form("save"), token: str = Form(""), chat_id: str = Form("")):
    require_super_admin(request)
    if action == "remove":
        set_setting("tg_token", "")
        set_setting("tg_chat_id", "")
        flash(request, "Telegram settings removed.")
    else:
        if token.strip():
            set_setting("tg_token", token.strip())
        if chat_id.strip():
            set_setting("tg_chat_id", chat_id.strip())
        if action == "test":
            try:
                telegram_bot.send("✅ Test message from the support portal.")
                flash(request, "Test message sent. Check your Telegram group.")
            except Exception as e:
                flash(request, f"Telegram error: {e}", "err")
        else:
            flash(request, "Telegram settings saved.")
    return RedirectResponse("/admin/settings", 303)

# ISP_PORTAL_STAFF_ONLY_V2
# Customer-facing portal and complaint/follow-up routes are disabled.
# Only the staff admin UI and the public logo asset remain accessible without a session.
@app.middleware("http")
async def isp_portal_security_headers_and_origin_guard(request, call_next):
    """Reject explicitly cross-origin admin mutations and add baseline browser headers.

    Compatibility note: requests without Origin/Referer are allowed so local tools and
    existing integrations are not broken. SameSite=strict session cookies remain enabled.
    """
    from urllib.parse import urlsplit
    from fastapi.responses import JSONResponse

    path = request.url.path
    method = request.method.upper()
    if path.startswith("/admin/") and method in ("POST", "PUT", "PATCH", "DELETE"):
        source = request.headers.get("origin")
        if not source:
            referer = request.headers.get("referer")
            if referer:
                parsed = urlsplit(referer)
                source = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
        if source:
            parsed_source = urlsplit(source)
            request_origin = f"{request.url.scheme}://{request.url.netloc}"
            source_origin = f"{parsed_source.scheme}://{parsed_source.netloc}"
            if source_origin.lower() != request_origin.lower():
                return JSONResponse(status_code=403, content={"detail": "Cross-origin admin request blocked."})

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.middleware("http")
async def isp_portal_staff_only(request, call_next):
    from fastapi.responses import JSONResponse, RedirectResponse
    path = request.url.path
    method = request.method.upper()
    if path == "/" and method in ("GET", "HEAD"):
        return RedirectResponse("/admin/login", status_code=303)
    if path == "/search" or path == "/api/suggest" or path.startswith("/c/"):
        if path.startswith("/c/") or path in ("/search", "/api/suggest"):
            return JSONResponse(status_code=404, content={"detail": "Staff-only portal. Customer self-service is disabled."})
    return await call_next(request)


# ISP_ROLE_ACCESS_V1: administrator account management
@app.get("/admin/access", dependencies=ADMIN)
def admin_access_page(request: Request):
    from fastapi.responses import HTMLResponse
    from html import escape
    if getattr(request.state, "admin_role", "") != "super_admin":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Super Admin permission required.")

    with SessionLocal() as db:
        accounts = db.query(Admin).order_by(Admin.username).all()
        rows = []
        for a in accounts:
            role = getattr(a, "role", "admin") or "admin"
            rows.append(
                "<tr><td>" + escape(a.username) + "</td><td>" + escape(role) +
                "</td><td><form method='post' action='/admin/access/action'>"
                "<input type='hidden' name='action' value='role'>"
                "<input type='hidden' name='username' value='" + escape(a.username, quote=True) + "'>"
                "<select name='role'>"
                + "".join("<option value='" + r + "'" + (" selected" if role == r else "") + ">" + label + "</option>"
                          for r, label in (("super_admin","Super Admin"),("admin","Admin"),("read_only","Read Access")))
                + "</select> <button type='submit'>Save Role</button></form></td></tr>"
            )

    page = """<!doctype html><html><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Admin Access</title>
    <style>
    body{font:15px system-ui;background:#0b1220;color:#e8eefc;margin:0;padding:24px}
    main{max-width:900px;margin:auto}section{background:#131e31;padding:20px;border-radius:12px;margin:16px 0}
    input,select,button{padding:10px;margin:5px;border-radius:6px;border:1px solid #40516b}
    button{cursor:pointer;background:#2463eb;color:white}table{width:100%;border-collapse:collapse}
    td,th{text-align:left;padding:10px;border-bottom:1px solid #344258}
    a{color:#9fc2ff}small{color:#b6c4dc}
    </style></head><body><main><h2>Administrator Access</h2>
    <p><a href="/admin">← Back to Dashboard</a></p>
    <section><h3>Create account</h3>
    <form method="post" action="/admin/access/action">
    <input type="hidden" name="action" value="create">
    <label>Username <input name="username" minlength="3" maxlength="64" required autocomplete="off"></label><br>
    <label>Password <input name="password" type="password" minlength="12" required autocomplete="new-password"></label><br>
    <label>Role <select name="role"><option value="admin">Admin</option>
    <option value="read_only">Read Access</option><option value="super_admin">Super Admin</option></select></label>
    <button type="submit">Create account</button></form>
    <small>Use a unique password with at least 12 characters.</small></section>
    <section><h3>Existing accounts</h3><table><thead><tr><th>Username</th><th>Current role</th><th>Change role</th></tr></thead>
    <tbody>__ROWS__</tbody></table></section></main></body></html>"""
    return HTMLResponse(page.replace("__ROWS__", "".join(rows)))


@app.post("/admin/access/action", dependencies=ADMIN)
def admin_access_action(
    request: Request,
    action: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    role: str = Form("admin"),
):
    from fastapi import HTTPException
    if getattr(request.state, "admin_role", "") != "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin permission required.")

    username = username.strip()
    valid_roles = {"super_admin", "admin", "read_only"}
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role.")

    with SessionLocal() as db:
        accounts = db.query(Admin).all()
        current_user = request.session.get("admin")

        if action == "create":
            if len(username) < 3 or len(username) > 64:
                raise HTTPException(status_code=400, detail="Username must be 3-64 characters.")
            if len(password) < 12:
                raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
            if db.query(Admin).filter_by(username=username).first():
                raise HTTPException(status_code=409, detail="Username already exists.")
            db.add(Admin(username=username, password_hash=hash_pw(password), role=role))
            db.commit()
        elif action == "role":
            account = db.query(Admin).filter_by(username=username).first()
            if not account:
                raise HTTPException(status_code=404, detail="Account not found.")
            if username == current_user and role != "super_admin":
                raise HTTPException(status_code=400, detail="You cannot remove your own Super Admin role.")
            if getattr(account, "role", "admin") == "super_admin" and role != "super_admin":
                remaining = sum(1 for a in accounts if a.username != username and getattr(a, "role", "") == "super_admin")
                if remaining == 0:
                    raise HTTPException(status_code=400, detail="At least one Super Admin must remain.")
            account.role = role
            db.commit()
        else:
            raise HTTPException(status_code=400, detail="Invalid action.")

    return RedirectResponse("/admin/access", status_code=303)



# ================================================================ admin: interface traffic monitor
@app.get("/admin/interface-monitor", dependencies=ADMIN)
def interface_monitor_page(request: Request):
    return render(request, "admin_interface_monitor.html", title="Interface Monitor")


@app.get("/admin/interface-monitor/api", dependencies=ADMIN)
def interface_monitor_api():
    data = ifmon.snapshot()
    with SessionLocal() as db:
        data["alarms"] = [
            {"id": a.id, "key": a.key, "level": a.level, "device": a.device, "message": a.message}
            for a in db.query(Alarm).filter(
                Alarm.cleared_at.is_(None), Alarm.key.like("ifmon:%")
            ).order_by(Alarm.id.desc()).limit(100)
        ]
    return JSONResponse(data)


@app.post("/admin/interface-monitor/discover", dependencies=ADMIN)
def interface_monitor_discover():
    return JSONResponse(ifmon.discover_once())


@app.post("/admin/interface-monitor/policy", dependencies=ADMIN)
async def interface_monitor_policy(request: Request):
    try:
        data = await request.json()
        ifmon.save_policy(data)
        return JSONResponse({"ok": True})
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception:
        log.exception("Could not save interface monitor policy")
        return JSONResponse({"detail": "Internal error saving policy"}, status_code=500)


@app.post("/admin/interface-monitor/add", dependencies=ADMIN)
async def interface_monitor_add(request: Request):
    try:
        data = await request.json()
        return JSONResponse(ifmon.add_vlan(data))
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception:
        log.exception("Could not add VLAN to interface monitor")
        return JSONResponse({"detail": "VLAN add failed"}, status_code=500)


@app.post("/admin/interface-monitor/remove", dependencies=ADMIN)
async def interface_monitor_remove(request: Request):
    try:
        data = await request.json()
        return JSONResponse(ifmon.remove_vlan(data))
    except (ValueError, TypeError) as e:
        return JSONResponse({"detail": str(e)}, status_code=400)
    except Exception:
        log.exception("Could not remove VLAN from interface monitor")
        return JSONResponse({"detail": "VLAN remove failed"}, status_code=500)
