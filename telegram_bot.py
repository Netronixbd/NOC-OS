import threading
import time
from html import escape

import httpx

import ctx
import diag
import mikrotik
import json

from db import STATUS_LABEL, Complaint, Customer, SessionLocal, apply_action, get_setting

API = "https://api.telegram.org/bot{}/{}"
seen_chats = {}   # chat_id -> title (filled by the poller so admin can pick the right chat ID)
_member = {}

HELP = ("🤖 <b>Support bot</b>\n\n"
        "Send a <b>User ID, phone, name or MAC</b> here to diagnose a customer.\n\n"
        "/diag &lt;id|phone|name|mac&gt; · full diagnosis\n"
        "/search &lt;text&gt; · find customers\n"
        "/ping &lt;userid&gt; · ping from router\n"
        "/open · open tickets\n"
        "/ticket &lt;n&gt; · ticket details\n"
        "/wait &lt;n&gt; · /close &lt;n&gt; [note] · /reply &lt;n&gt; &lt;text&gt;\n\n"
        "<i>Tip: reply to a ticket message in the group to answer the customer.</i>")
COMMANDS = [("diag", "Diagnose a customer (id/phone/name/mac)"), ("search", "Find customers"),
            ("ping", "Ping a customer from the router"), ("open", "List open tickets"),
            ("ticket", "Show a ticket"), ("help", "Help")]


def _call(method, token=None, _http_timeout=15, **payload):
    token = token or get_setting("tg_token")
    if not token:
        raise RuntimeError("Telegram bot token not set")
    r = httpx.post(API.format(token, method), json=payload, timeout=_http_timeout)
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("description", "Telegram error"))
    return data["result"]


def send(text, buttons=None, reply_to=None, chat_id=None, token=None, rows=None):
    chat_id = chat_id or get_setting("tg_chat_id")
    if not chat_id:
        raise RuntimeError("Telegram chat ID not set")
    p = {"chat_id": chat_id, "text": text[:3900], "parse_mode": "HTML", "disable_web_page_preview": True}
    if rows:
        p["reply_markup"] = {"inline_keyboard": rows}
    elif buttons:
        p["reply_markup"] = {"inline_keyboard": [buttons]}
    if reply_to:
        p["reply_to_message_id"] = reply_to
        p["allow_sending_without_reply"] = True
    return _call("sendMessage", token=token, **p)


def buttons_for(cid):
    return [{"text": "⏳ Waiting for update", "callback_data": f"wait:{cid}"},
            {"text": "✅ Close", "callback_data": f"close:{cid}"}]


def complaint_text(c, cust, lines=None):
    return (f"🆕 <b>New Complaint #{c.id}</b>\n"
            f"👤 {escape(cust.name or '-')}\n"
            f"🆔 <code>{escape(cust.user_id)}</code>\n"
            f"📞 {escape(c.contact_phone or cust.phone or '-')}\n"
            f"📂 {escape(c.category)}\n"
            f"📝 {escape(c.message or '-')}\n\n"
            f"<i>↩️ Reply to this message to answer the customer. Diagnosis follows below…</i>")


def draft_rows(cid):
    return [[{"text": "✅ Send reply (বাংলা)", "callback_data": f"cr:{cid}:bn"},
             {"text": "✅ Send reply (English)", "callback_data": f"cr:{cid}:en"}]]


def diag_reply_text(c, d, drafts=True):
    body = "\n".join(escape(l) for l in d["report"])
    txt = f"🔎 <b>Auto diagnosis · #{c.id}</b>\n" + body
    if drafts:
        txt += "\n\n✉️ <b>Draft reply to customer (বাংলা)</b>\n<i>" + escape(d["reply_bn"]) + "</i>"
    return txt


def _remove_buttons(chat, mid):
    try:
        _call("editMessageReplyMarkup", chat_id=chat, message_id=mid, reply_markup={"inline_keyboard": []})
    except Exception:
        pass


def is_member(user_id):
    chat = get_setting("tg_chat_id")
    if not chat or not user_id:
        return False
    c = _member.get(user_id)
    if c and time.time() - c[0] < 300:
        return c[1]
    try:
        r = _call("getChatMember", chat_id=chat, user_id=user_id)
        ok = r.get("status") in ("creator", "administrator", "member") or (r.get("status") == "restricted" and r.get("is_member"))
    except Exception:
        ok = False
    _member[user_id] = (time.time(), ok)
    return ok


def _bg(fn, *a):
    def run():
        try:
            fn(*a)
        except Exception as e:
            try:
                first = a[0] if a else None
                cid = first if isinstance(first, (int, str)) else (
                    ((first or {}).get("chat") or (first or {}).get("message", {}).get("chat") or {}).get("id"))
                send(f"⚠️ Error: {escape(str(e))[:300]}", chat_id=cid)
            except Exception:
                pass
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ actions
def _dg(uid):
    d = f"dg:{uid}"
    return d if len(d.encode()) <= 64 else None


def send_diag(chat, uid, mac=None):
    try:
        _call("sendChatAction", chat_id=chat, action="typing")
    except Exception:
        pass
    d = ctx.diagnose(uid, mac)
    head = f"🔎 <b>{escape(d.get('name') or uid or mac or '-')}</b>\n"
    if uid:
        head += f"🆔 <code>{escape(uid)}</code>"
    if d.get("phone"):
        head += f" · 📞 {escape(d['phone'])}"
    text = head + "\n\n" + "\n".join(escape(l) for l in d["report"])
    rows = []
    open_t = d.get("tickets") or []
    if open_t:
        tid = open_t[0]["id"]
        with SessionLocal() as db:
            c = db.get(Complaint, tid)
            if c:
                try:
                    snap = json.loads(c.diag_json or "{}")
                except ValueError:
                    snap = {}
                snap.update(lines=d["report"], reply_bn=d["reply_bn"], reply_en=d["reply_en"])
                c.diag_json = json.dumps(snap, ensure_ascii=False)
                db.commit()
        text += f"\n\n✉️ <b>Draft reply for ticket #{tid} (বাংলা)</b>\n<i>{escape(d['reply_bn'])}</i>"
        rows = draft_rows(tid)
    row = []
    if uid and len(f"ping:{uid}".encode()) <= 64:
        row.append({"text": "📡 Ping", "callback_data": f"ping:{uid}"})
    if _dg(uid):
        row.append({"text": "🔄 Refresh", "callback_data": _dg(uid)})
    if uid and len(f"ut:{uid}".encode()) <= 64:
        row.append({"text": "🎫 Tickets", "callback_data": f"ut:{uid}"})
    if row:
        rows.append(row)
    send(text, rows=rows or None, chat_id=chat)


def do_ping(chat, uid):
    p = mikrotik.ping(uid, ctx.all_routers_fresh())
    if p.get("ok"):
        txt = (f"📡 <b>Ping {escape(p['ip'])}</b> (20 × 100 ms, from router)\nSent/received: {p['sent']}/{p['received']} · loss {p['loss']}%\n"
               f"min/avg/max: {p['min']}/{p['avg']}/{p['max']} ms · jitter {p['jitter']} ms")
    else:
        txt = "📡 " + escape(p.get("error", "ping failed"))
    send(txt, chat_id=chat)


def do_search(chat, q, diag_if_one=True):
    with SessionLocal() as db:
        res = ctx.find(db, q)
    if not res:
        send(f"No customer found for <code>{escape(q)}</code>.", chat_id=chat)
        return
    if len(res) == 1 and diag_if_one:
        r = res[0]
        send_diag(chat, r["uid"], r.get("mac"))
        return
    lines, rows = [], []
    for r in res:
        on = {True: "🟢", False: "🔴"}.get(r.get("online"), "⚪")
        lines.append(f"{on} <code>{escape(r['uid'] or r.get('mac', ''))}</code> · {escape(r['name'] or '-')} · {escape(r['phone'] or '-')}")
        data = _dg(r["uid"]) if r["uid"] else f"dm:{r.get('mac')}"
        if data:
            rows.append([{"text": f"🔎 {r['uid'] or r.get('mac')}"[:40], "callback_data": data}])
    send("<b>Matches</b>\n" + "\n".join(lines), rows=rows[:8], chat_id=chat)


def ticket_view(cid):
    with SessionLocal() as db:
        c = db.get(Complaint, cid)
        if not c:
            return None, None
        cu = c.customer
        t = [f"🎫 <b>#{c.id}</b> · {escape(STATUS_LABEL.get(c.status, c.status))}",
             f"👤 {escape(cu.name or '-')} · <code>{escape(cu.user_id)}</code>",
             f"📞 {escape(c.contact_phone or cu.phone or '-')}", f"📂 {escape(c.category)}"]
        if c.message:
            t.append("📝 " + escape(c.message))
        if c.pon:
            t.append(f"🛰 {escape(c.olt_name)} · PON {escape(c.pon)}")
        for r in c.replies[-6:]:
            ic = {"wait": "⏳", "close": "✅"}.get(r.kind, "💬")
            t.append(f"{ic} <i>{escape(r.author)}</i> {escape(r.message or '')}")
        rows = [buttons_for(c.id)] if c.status != "closed" else []
        if _dg(cu.user_id):
            rows.append([{"text": "🔎 Diagnose", "callback_data": _dg(cu.user_id)}])
        return "\n".join(t), rows


def send_ticket(chat, cid):
    text, rows = ticket_view(cid)
    send(text or f"Ticket #{cid} not found.", rows=rows, chat_id=chat)


def list_open(chat):
    with SessionLocal() as db:
        items = db.query(Complaint).filter(Complaint.status != "closed").order_by(Complaint.id.desc()).limit(12).all()
        lines = [f"#{c.id} · {escape(c.customer.name or c.customer.user_id)} · {escape(c.category)} · "
                 f"{escape(STATUS_LABEL.get(c.status, c.status))}" for c in items]
        ids = [c.id for c in items]
    if not ids:
        send("🎉 No open tickets.", chat_id=chat)
        return
    rows = [[{"text": f"#{i}", "callback_data": f"tk:{i}"} for i in ids[k:k + 4]] for k in range(0, len(ids), 4)]
    send("<b>Open tickets</b>\n" + "\n".join(lines), rows=rows, chat_id=chat)


def user_tickets(chat, uid):
    with SessionLocal() as db:
        from db import Customer
        cu = db.query(Customer).filter_by(user_id=uid).first()
        items = list(cu.complaints[:6]) if cu else []
        lines = [f"#{c.id} · {escape(c.category)} · {escape(STATUS_LABEL.get(c.status, c.status))}" for c in items]
        ids = [c.id for c in items]
    send(("<b>Tickets</b> for <code>" + escape(uid) + "</code>\n" + "\n".join(lines)) if lines else "No tickets for this user.",
         rows=[[{"text": f"#{i}", "callback_data": f"tk:{i}"} for i in ids]] if ids else None, chat_id=chat)


# ------------------------------------------------------------------ message / callback routing
def handle_reply(m):
    if str((m.get("chat") or {}).get("id", "")) != str(get_setting("tg_chat_id")):
        return
    rid = m["reply_to_message"]["message_id"]
    who = (m.get("from") or {}).get("first_name", "staff")
    with SessionLocal() as db:
        c = db.query(Complaint).filter((Complaint.tg_message_id == rid) | (Complaint.tg_diag_message_id == rid)).first()
        if not c or c.status == "closed":
            return
        cid = c.id
        apply_action(db, cid, "reply", who, m["text"], "staff")
    try:
        send(f"💬 Reply sent to customer (#{cid})", reply_to=m["message_id"])
    except Exception:
        pass


def handle_message(m):
    text = (m.get("text") or "").strip()
    frm = m.get("from") or {}
    chat = m["chat"]
    if not text or frm.get("is_bot"):
        return
    private = chat.get("type") == "private"
    in_group = str(chat["id"]) == str(get_setting("tg_chat_id"))
    if not (private or in_group):
        return
    if not text.startswith("/"):
        if in_group and m.get("reply_to_message"):
            return handle_reply(m)
        if not private:
            return
    if not is_member(frm.get("id")):
        if private:
            send("⛔ Only members of the support group can use this bot.", chat_id=chat["id"])
        return
    cid = chat["id"]
    if text.startswith("/"):
        cmd, _, arg = text.partition(" ")
        cmd, arg = cmd.split("@")[0].lower(), arg.strip()
    else:
        cmd, arg = "/diag", text
    who = f"telegram: {frm.get('first_name', '?')}"
    if cmd in ("/start", "/help"):
        send(HELP, chat_id=cid)
    elif cmd in ("/diag", "/search"):
        if not arg:
            send("Usage: /diag &lt;user id | phone | name | MAC&gt;", chat_id=cid)
        else:
            do_search(cid, arg, diag_if_one=(cmd == "/diag"))
    elif cmd == "/ping":
        do_ping(cid, arg) if arg else send("Usage: /ping &lt;user id&gt;", chat_id=cid)
    elif cmd == "/open":
        list_open(cid)
    elif cmd == "/ticket":
        send_ticket(cid, int(arg)) if arg.isdigit() else send("Usage: /ticket &lt;number&gt;", chat_id=cid)
    elif cmd in ("/wait", "/close", "/reply"):
        n, _, rest = arg.partition(" ")
        if not n.isdigit() or (cmd == "/reply" and not rest.strip()):
            send(f"Usage: {cmd} &lt;ticket number&gt;" + (" &lt;text&gt;" if cmd == "/reply" else ""), chat_id=cid)
            return
        act = cmd[1:]
        with SessionLocal() as db:
            c = apply_action(db, int(n), act, who, rest)
        msg = {"wait": "⏳ Waiting for update", "close": "✅ Closed", "reply": "💬 Reply sent"}[act]
        send(f"{msg}: #{n}" if c else f"Ticket #{n} not found or already closed.", chat_id=cid)
        if c and str(cid) != str(get_setting("tg_chat_id")):
            send(f"{msg}: #{n} by {escape(frm.get('first_name', '?'))}")
    else:
        send(HELP, chat_id=cid)


def _answer(cq_id, text=""):
    try:
        _call("answerCallbackQuery", callback_query_id=cq_id, text=text)
    except Exception:
        pass


def handle_callback(cq):
    data = cq.get("data", "")
    msg = cq.get("message") or {}
    chat = (msg.get("chat") or {}).get("id")
    frm = cq.get("from") or {}
    group = str(get_setting("tg_chat_id"))
    if not (str(chat) == group or is_member(frm.get("id"))):
        _answer(cq["id"], "Not allowed")
        return
    act, _, arg = data.partition(":")
    if act in ("wait", "close", "resolve"):
        act = "close" if act == "resolve" else act
        if not arg.isdigit():
            return
        who = frm.get("first_name", "?")
        with SessionLocal() as db:
            c = apply_action(db, int(arg), act, f"telegram: {who}")
        _answer(cq["id"], "Done ✅" if c else "Already closed")
        if c:
            if act == "close":
                _remove_buttons(chat, msg.get("message_id"))
            label = "⏳ Waiting for update" if act == "wait" else "✅ Closed"
            try:
                send(f"{label}: complaint #{arg} by {escape(who)}",
                     reply_to=msg.get("message_id") if str(chat) == group else None)
            except Exception:
                pass
        return
    if act == "cr":
        cid_s, _, lang = arg.partition(":")
        who = frm.get("first_name", "?")
        text = None
        with SessionLocal() as db:
            c = db.get(Complaint, int(cid_s)) if cid_s.isdigit() else None
            if c and c.status != "closed":
                try:
                    text = json.loads(c.diag_json or "{}").get("reply_" + ("en" if lang == "en" else "bn"))
                except ValueError:
                    text = None
                if text:
                    apply_action(db, c.id, "reply", f"telegram: {who}", text, "staff")
        _answer(cq["id"], "Sent ✅" if text else "No draft / ticket closed")
        if text:
            _remove_buttons(chat, msg.get("message_id"))
            try:
                send(f"💬 Reply sent to customer (#{cid_s}) by {escape(who)}")
            except Exception:
                pass
        return
    _answer(cq["id"], "Working…")
    if act == "dg":
        _bg(send_diag, chat, arg)
    elif act == "dm":
        _bg(send_diag, chat, "", arg)
    elif act == "ping":
        _bg(do_ping, chat, arg)
    elif act == "ut":
        _bg(user_tickets, chat, arg)
    elif act == "tk" and arg.isdigit():
        _bg(send_ticket, chat, int(arg))


def poll_loop():
    offset, last_token = None, None
    while True:
        token = get_setting("tg_token")
        if not token:
            time.sleep(10)
            continue
        if token != last_token:
            offset, last_token = None, token
            try:
                _call("setMyCommands", token=token, commands=[dict(command=c, description=d) for c, d in COMMANDS])
            except Exception:
                pass
        try:
            p = {"timeout": 25, "allowed_updates": ["callback_query", "message", "my_chat_member"]}
            if offset:
                p["offset"] = offset
            for u in _call("getUpdates", token=token, _http_timeout=35, **p):
                offset = u["update_id"] + 1
                if "callback_query" in u:
                    _bg(handle_callback, u["callback_query"])
                m = u.get("message")
                if m and m.get("text"):
                    _bg(handle_message, m)
                for k in ("message", "my_chat_member"):
                    ch = (u.get(k) or {}).get("chat")
                    if ch:
                        seen_chats[str(ch["id"])] = ch.get("title") or ch.get("first_name") or "private"
        except Exception:
            time.sleep(5)


def start_poller():
    threading.Thread(target=poll_loop, daemon=True).start()
