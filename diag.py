"""Collects MikroTik (API+SNMP) + OUI + OLT + ping data for one PPPoE user; derives hints, verdict, replies."""
import time

import mikrotik
import olt
import oui
import snmp


def collect(uid, mac_hint, onu_mac, routers, olts, history=None, with_ping=True):
    mt = mikrotik.diagnose(uid, routers) if uid else dict(found=False)
    sn = None
    if mt.get("found"):
        r = next((x for x in routers if x.get("name") == mt.get("router")), None)
        if r and r.get("snmp_enabled") and mt.get("state") == "online":
            sn = mikrotik.snmp_ppp(r, uid)
    elif uid:   # SNMP-only routers
        for r in routers:
            if r.get("snmp_enabled") and not r.get("api_enabled", True):
                s = mikrotik.snmp_ppp(r, uid)
                if s.get("ok"):
                    sn, mt = s, dict(found=True, router=r.get("name"), state="online", snmp_only=True)
                    break
    mac = snmp.norm_mac(mac_hint) if mac_hint else snmp.norm_mac(mt.get("mac"))
    device = oui.describe(mac)
    opt = olt.locate(olts, mac, onu_mac) if olts and (mac or onu_mac) else None
    if opt and opt.get("found"):
        om = (opt["fields"].get("mac") or {}).get("value")
        x = oui.describe(om) if om else None
        opt["onu_brand"] = (x or {}).get("short") or (x or {}).get("vendor")
    ping = mikrotik.ping(uid, routers) if (with_ping and mt.get("found") and mt.get("state") == "online"
                                          and not mt.get("snmp_only")) else None
    l2 = dict(vlan=(opt or {}).get("vlan"), checked=(opt or {}).get("checked") or [], mikrotik=None)
    if mt.get("found") and mac and not mt.get("snmp_only"):
        r = next((x for x in routers if x.get("name") == mt.get("router")), None)
        if r:
            try:
                l2["mikrotik"] = mikrotik.l2_info(r, mac, l2["vlan"])
            except Exception as e:
                l2["mikrotik"] = dict(error=str(e)[:120])
    d = dict(uid=uid, mikrotik=mt, snmp=sn, device=device, optical=opt, ping=ping, l2=l2, mac=mac, ts=int(time.time()),
             olts_configured=bool(olts), history=history or {})
    d["hints"] = hints(d)
    d["verdict"] = verdict(d)
    d["report"] = summary(d, True)
    return d


def hints(d):
    mt, opt, sn, pg = d["mikrotik"], d["optical"], d["snmp"], d.get("ping")
    H = []
    add = lambda lv, code, t: H.append(dict(level=lv, code=code, text=t))
    logs = " ".join((l.get("message") or "").lower() for l in mt.get("logs", []))
    if not mt.get("found"):
        add("err", "not_found", "User ID not found on any connected MikroTik (check user ID spelling / router API settings).")
    else:
        st = mt.get("state")
        if mt.get("disabled"):
            add("err", "disabled", "PPPoE secret is DISABLED on the router (expired / billing block?).")
        for l in mt.get("lists", []):
            add("warn", "blocklist", f"Customer IP is in address-list '{l}' (possible block / expired list).")
        if st == "online":
            add("ok", "online", f"PPPoE session online{' (up ' + mt['uptime'] + ')' if mt.get('uptime') else ''}.")
            if mt.get("uptime_sec") is not None and mt["uptime_sec"] < 600:
                add("warn", "new_session", "Session is very new (<10 min): link may be flapping, check disconnect history/logs.")
        else:
            onu_down = opt and opt.get("found") and (
                opt.get("link") == "down" or (opt["fields"].get("status") or {}).get("online") is False)
            if onu_down:
                add("err", "onu_down", "ONU is OFFLINE on the OLT: likely fiber cut / ONU power off / LOS. Check ONU power and fiber.")
            elif opt and opt.get("found"):
                add("warn", "onu_up_ppp_down", "ONU is online but PPPoE is down: check customer router (PPPoE user/pass, WAN cable) and logs.")
            elif opt and not opt.get("found"):
                add("info", "onu_unknown", "ONU not found on any OLT by MAC (MAC may have aged out while offline). "
                                           "Try setting the ONU MAC on the customer.")
            else:
                add("info", "no_olt", "No OLT lookup available, fiber side not verified.")
        if any(k in logs for k in ("authentication failed", "auth failed", "bad password")):
            add("err", "auth_fail", "Logs show PPPoE authentication failures: customer router has a wrong username/password.")
        if any(k in logs for k in ("not responding", "timeout", "lcp")):
            add("warn", "lcp", "Logs show LCP/keepalive timeouts: unstable line or ONU/router issue.")
        i = mt.get("iface") or {}
        if any(int(i.get(k) or 0) > 0 for k in ("rx_error", "tx_error")):
            add("warn", "iface_err", "Interface errors present on the PPPoE interface (cable / ONU LAN port / router).")
        dr = (mt.get("queue") or {}).get("dropped")
        if dr and any((x or 0) > 0 for x in mikrotik._pair(dr)):
            add("info", "queue_drop", "Queue is dropping packets (speed limit reached / congestion).")
    if sn and sn.get("ok") and ((sn.get("in_errors") or 0) > 0 or (sn.get("out_errors") or 0) > 0):
        add("warn", "iface_err", "SNMP shows errors on the PPPoE interface.")
    if pg and pg.get("ok"):
        if pg["loss"] >= 20:
            add("err", "loss", f"Ping to customer router: {pg['loss']}% packet loss ({pg['received']}/{pg['sent']} replies).")
        elif pg["loss"] >= 5:
            add("warn", "loss", f"Ping to customer router: {pg['loss']}% packet loss.")
        if pg.get("avg") is not None and pg["avg"] > 20:
            add("warn", "latency", f"High latency to customer router: avg {pg['avg']} ms.")
        if pg.get("jitter") is not None and pg["jitter"] > 10:
            add("warn", "jitter", f"High jitter to customer router: {pg['jitter']} ms.")
        if pg["loss"] < 5 and (pg.get("avg") or 0) <= 20 and (pg.get("jitter") or 0) <= 10:
            add("ok", "ping_ok", f"Ping 20×100 ms clean: avg {pg.get('avg')} ms, jitter {pg.get('jitter')} ms, no loss.")
    dev = d.get("device")
    if dev and dev.get("local"):
        add("info", "local_mac", "Customer MAC is locally-administered (random/virtual); the brand shown may not be reliable.")
    if opt and opt.get("found"):
        f = opt["fields"]
        for key, label in (("rx", "ONU Rx"), ("olt_rx", "OLT Rx")):
            v = f.get(key) or {}
            q, val = v.get("quality"), v.get("value")
            if q == "bad":
                add("err", "rx_bad", f"{label} {val} dBm is below -27: very weak (dirty connector, bend, bad splice or long split).")
            elif q == "weak":
                add("warn", "rx_weak", f"{label} {val} dBm is weak (-24 to -27): needs attention soon.")
            elif q == "high":
                add("warn", "rx_high", f"{label} {val} dBm is too strong (> -8): may need an attenuator.")
        if (f.get("distance") or {}).get("value", 0) > 20000:
            add("warn", "far", "ONU distance is above 20 km.")
        if not opt.get("configured"):
            add("info", "no_oids", f"OLT profile '{opt.get('profile')}' has no optical OIDs yet: Devices → OLT → Tools → Discover.")
        if any((v or {}).get("conf") == "low" for v in f.values()):
            add("info", "low_conf", "Some optical values come from low-confidence OIDs (shown with ⚠). Verify them once against the OLT CLI.")
    n30 = (d.get("history") or {}).get("count30") or 0
    if n30 >= 2:
        add("warn", "repeat", f"Repeat complaint: {n30} other complaints in the last 30 days.")
    return H


def verdict(d):
    errs = [h for h in d["hints"] if h["level"] == "err"]
    warns = [h for h in d["hints"] if h["level"] == "warn"]
    if errs:
        t = f"❌ {len(errs)} problem(s) found" + (f", {len(warns)} warning(s)" if warns else "")
    elif warns:
        t = f"⚠️ {len(warns)} warning(s), no hard fault"
    else:
        t = "✅ No issue found: all checks passed"
    return dict(ok=not errs and not warns, errors=len(errs), warnings=len(warns), text=t)


def _bps(n):
    if n is None:
        return None
    return f"{n / 1e6:.2f} Mbps" if n >= 1e6 else f"{n / 1e3:.1f} Kbps"


def summary(d, full=False):
    """Plain-text lines for Telegram / ticket snapshot / copy-report."""
    mt, opt, dev, sn, pg = d["mikrotik"], d["optical"], d.get("device"), d.get("snmp"), d.get("ping")
    L = []
    if full and d.get("verdict"):
        L.append("🧾 " + d["verdict"]["text"])
    if mt.get("found"):
        em = {"online": "🟢 Online", "offline": "🔴 Offline", "disabled": "⛔ Disabled"}.get(mt["state"], mt["state"])
        L.append(f"🌐 PPPoE: {em}" + (f" · {mt['ip']}" if mt.get("ip") else "") +
                 (f" · up {mt['uptime']}" if mt.get("uptime") else "") + (f" · {mt['router']}" if mt.get("router") else ""))
        t = (sn if sn and sn.get("ok") else mt.get("traffic")) or {}
        live = f" · ↓ {_bps(t['down_bps'])} ↑ {_bps(t['up_bps'])}" if t.get("down_bps") is not None else ""
        pool = mt.get("profile_pool") or mt.get("pool_by_ip")
        if mt.get("profile") or live or pool:
            L.append(f"⚡ Profile: {mt.get('profile') or '-'}" + (f" ({mt['rate_limit']})" if mt.get("rate_limit") else "")
                     + (f" · pool {pool}" if pool else "") + live)
        s = mt.get("session")
        if s and mt.get("state") == "online":
            L.append(f"📊 Session: ↓ {s['down_bytes'] / 1e6:.1f} MB · ↑ {s['up_bytes'] / 1e6:.1f} MB")
        if mt.get("state") != "online":
            if mt.get("last_disconnect_reason"):
                L.append(f"🔌 Last disconnect: {mt['last_disconnect_reason']}")
            if mt.get("last_logged_out"):
                L.append(f"🕒 Last logout: {mt['last_logged_out']}")
    else:
        L.append("❔ PPPoE: user not found on router / router unreachable")
    if dev:
        L.append(f"📟 Customer router: {dev.get('short') or dev.get('vendor') or 'Unknown brand'} · {dev['mac']}")
    if pg and pg.get("ok"):
        L.append(f"📡 Ping 20×100ms: loss {pg['loss']}% · avg {pg.get('avg')} ms · max {pg.get('max')} ms · jitter {pg.get('jitter')} ms")
    if opt and opt.get("found"):
        f = opt["fields"]
        fv = lambda k: (f.get(k) or {}).get("value")
        L.append(f"🛰 OLT: {opt['olt']} ({opt.get('vendor') or '-'}) · PON {opt.get('pon') or '?'} · ONU {opt.get('onu') or '?'}"
                 f" ({opt.get('ifname')}) · link {opt.get('link') or '?'}" + (f" · VLAN {opt['vlan']}" if opt.get("vlan") else "") +
                 (f" · {fv('status')}" if fv("status") else ""))
        brand = " / ".join(x for x in (fv("vendor"), fv("model")) if x)
        extra = []
        if opt.get("onu_brand"):
            extra.append(f"MAC brand {opt['onu_brand']}")
        if fv("mac"):
            extra.append(f"MAC {fv('mac')}")
        if brand or extra:
            L.append("🏷 ONU: " + (brand or "-") + (" · " + " · ".join(extra) if extra else ""))
        bits = []
        for k, lab in (("rx", "ONU Rx"), ("tx", "ONU Tx"), ("olt_rx", "OLT Rx")):
            v = f.get(k) or {}
            if v.get("value") is not None:
                q = {"good": " ✅", "weak": " ⚠️", "bad": " 🚨", "high": " ⚠️"}.get(v.get("quality"), "")
                bits.append(f"{lab} {v['value']} dBm{q}{' ⚠unverified' if v.get('conf') == 'low' else ''}")
        for k, u in (("distance", " m"), ("temp", " °C"), ("voltage", " V")):
            if fv(k) is not None:
                bits.append(f"{fv(k)}{u}{' ⚠' if (f.get(k) or {}).get('conf') == 'low' else ''}")
        if fv("uni_speed") is not None:
            bits.append(f"LAN port {fv('uni_speed')} Mbps")
        if bits:
            L.append("📉 " + " · ".join(bits))
    elif opt is not None:
        L.append("🛰 OLT: ONU not found by MAC")
    n30 = (d.get("history") or {}).get("count30")
    if n30:
        L.append(f"📚 Previous complaints (30 days): {n30}")
    if full:
        q = mt.get("queue") or {}
        if q.get("max_limit"):
            L.append(f"🚦 Queue: {q['max_limit']} · drops {q.get('dropped')}")
        for l in (mt.get("logs") or [])[-3:]:
            L.append(f"📜 {l.get('time')} {(l.get('message') or '')[:110]}")
    icon = {"err": "🚨", "warn": "⚠️", "ok": "✅", "info": "ℹ️"}
    for h in d["hints"]:
        if full or h["level"] in ("err", "warn"):
            L.append(f"{icon[h['level']]} {h['text']}")
    return L


# ------------------------------------------------------------------ customer-facing reply
BN = dict(
    hello="প্রিয় গ্রাহক{n},", bye="আপনার ধৈর্যের জন্য ধন্যবাদ।\n— সাপোর্ট টিম",
    ok=("আমরা আপনার লাইনটি পরীক্ষা করেছি। বর্তমানে আমাদের দিক থেকে কোনো সমস্যা পাওয়া যায়নি; আপনার সংযোগ সক্রিয় আছে এবং সিগন্যাল স্বাভাবিক। "
        "অনুগ্রহ করে আপনার রাউটার ও ডিভাইস একবার রিস্টার্ট করুন। ওয়াই-ফাইতে সমস্যা হলে রাউটারের কাছে গিয়ে বা LAN ক্যাবল দিয়ে পরীক্ষা করুন। "
        "এরপরও সমস্যা থাকলে আমাদের জানান, আমরা আবার দেখব।"),
    intro="আপনার লাইনটি পরীক্ষা করে নিচের বিষয়গুলো পাওয়া গেছে:",
    disabled="আপনার ইন্টারনেট সংযোগটি বর্তমানে বন্ধ আছে (বিল বা মেয়াদ সংক্রান্ত কারণে হতে পারে)। বিল পরিশোধ করে আমাদের জানালে সংযোগ দ্রুত চালু করে দেওয়া হবে।",
    blocklist="আপনার সংযোগটি বিল/মেয়াদ সংক্রান্ত কারণে সীমিত করা আছে বলে দেখা যাচ্ছে। অনুগ্রহ করে বিল পরিশোধ করে আমাদের জানান।",
    onu_down=("আপনার ফাইবার লাইনে সিগন্যাল পাওয়া যাচ্ছে না। অনুগ্রহ করে ONU/মডেমের পাওয়ার অ্যাডাপ্টার চালু আছে কিনা এবং ফাইবার ক্যাবলটি ঠিকমতো লাগানো আছে কিনা দেখুন। "
              "ঠিক থাকলে আমাদের টেকনিশিয়ান শীঘ্রই আপনার সাথে যোগাযোগ করবেন।"),
    onu_up_ppp_down=("আপনার ফাইবার লাইনের সিগন্যাল ঠিক আছে, তবে রাউটার থেকে ইন্টারনেট কানেক্ট হচ্ছে না। অনুগ্রহ করে রাউটার একবার বন্ধ করে চালু করুন "
                     "এবং ONU থেকে রাউটারের WAN পোর্টের ক্যাবলটি ঠিকমতো লাগানো আছে কিনা দেখুন।"),
    auth_fail=("আপনার রাউটারে ইউজারনেম বা পাসওয়ার্ড ভুল দেওয়া আছে বলে মনে হচ্ছে। অনুগ্রহ করে রাউটারের PPPoE সেটিং ঠিক করুন, প্রয়োজনে আমরা সঠিক তথ্য জানিয়ে দেব।"),
    rx_bad="আপনার ফাইবার লাইনের সিগন্যাল খুবই দুর্বল পাওয়া গেছে, যা ইন্টারনেট ধীর বা বারবার বিচ্ছিন্ন হওয়ার কারণ। আমাদের টেকনিশিয়ান লাইনটি পরীক্ষা করে ঠিক করে দেবেন।",
    rx_weak="আপনার ফাইবার লাইনের সিগন্যাল কিছুটা দুর্বল পাওয়া গেছে। আমরা বিষয়টি দেখছি এবং প্রয়োজনে টেকনিশিয়ান পাঠানো হবে।",
    lcp="আপনার সংযোগ মাঝে মাঝে বিচ্ছিন্ন হচ্ছে বলে দেখা যাচ্ছে। অনুগ্রহ করে ONU ও রাউটারের পাওয়ার এবং LAN ক্যাবলের প্লাগ ঠিকমতো লাগানো আছে কিনা দেখুন।",
    loss="আপনার লাইনে প্যাকেট লস বা ল্যাটেন্সি বেশি পাওয়া গেছে। ওয়াই-ফাইয়ের বদলে LAN ক্যাবল দিয়ে পরীক্ষা করে দেখুন এবং রাউটার রিস্টার্ট করুন। সমস্যা থাকলে আমরা লাইন আরও পরীক্ষা করব।",
    iface_err="আপনার লাইনের ক্যাবল বা ONU-এর LAN পোর্টে সমস্যা থাকতে পারে। অনুগ্রহ করে LAN ক্যাবলটি ঠিকমতো লাগানো আছে কিনা দেখুন।",
    not_found="আপনার ইউজার আইডিটি আমাদের সিস্টেমে খুঁজে পাওয়া যায়নি। অনুগ্রহ করে সঠিক ইউজার আইডি জানান।",
    followup="আমরা বিষয়টি দেখছি এবং খুব শীঘ্রই আপনাকে জানাব।",
)
EN = dict(
    hello="Dear customer{n},", bye="Thank you for your patience.\n— Support Team",
    ok=("We have checked your line and found no problem on our side: your connection is active and the signal is normal. "
        "Please restart your router and devices. If Wi-Fi is slow, try closer to the router or with a LAN cable. "
        "If the problem continues, let us know and we will look again."),
    intro="We checked your line and found the following:",
    disabled="Your connection is currently disabled (possibly due to billing/expiry). Please pay the bill and let us know; we will reactivate it quickly.",
    blocklist="Your connection appears to be restricted for billing/expiry reasons. Please clear the bill and let us know.",
    onu_down=("We are not receiving a signal on your fiber line. Please check that the ONU/modem power adapter is on and the fiber cable is plugged in properly. "
              "If both are fine, our technician will contact you shortly."),
    onu_up_ppp_down=("Your fiber signal is fine, but your router is not connecting to the internet. Please power-cycle the router and check the cable from the ONU to the router WAN port."),
    auth_fail="Your router seems to have a wrong PPPoE username or password. Please correct the PPPoE settings; we can share the correct details if needed.",
    rx_bad="Your fiber signal is very weak, which causes slow speed or disconnections. Our technician will inspect and fix the line.",
    rx_weak="Your fiber signal is slightly weak. We are looking into it and will send a technician if needed.",
    lcp="Your connection seems to drop now and then. Please check the power and LAN cable plugs of your ONU and router.",
    loss="We noticed packet loss / high latency on your line. Please test with a LAN cable instead of Wi-Fi and restart the router. We will check further if it continues.",
    iface_err="There may be an issue with the cable or the ONU LAN port. Please make sure the LAN cable is plugged in firmly.",
    not_found="We could not find your user ID in our system. Please send the correct user ID.",
    followup="We are looking into it and will update you soon.",
)
ORDER = ["not_found", "disabled", "blocklist", "onu_down", "auth_fail", "onu_up_ppp_down", "rx_bad", "rx_weak", "lcp",
         "loss", "latency", "jitter", "iface_err"]
ALIAS = {"latency": "loss", "jitter": "loss"}


def customer_reply(d, lang="bn", name=""):
    T = BN if lang == "bn" else EN
    codes = {h["code"] for h in d["hints"] if h["level"] in ("err", "warn")}
    picked, seen = [], set()
    for c in ORDER:
        if c in codes:
            k = ALIAS.get(c, c)
            if k not in seen:
                seen.add(k)
                picked.append(T[k])
    n = f" {name}" if name else ""
    body = T["ok"] if not picked else (T["intro"] + "\n" + "\n".join(f"{i}. {m}" for i, m in enumerate(picked[:3], 1)))
    return T["hello"].format(n=n) + "\n\n" + body + "\n\n" + T["bye"]
