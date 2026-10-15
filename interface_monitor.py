import logging
import threading
import time
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, BigInteger
from db import Base, engine, SessionLocal, Router, Alarm
import ctx
import mikrotik
import monitor

log = logging.getLogger("interface_monitor")
Base.metadata.create_all(bind=engine)

class InterfacePolicy(Base):
    __tablename__ = "interface_monitor_policies"
    id = Column(Integer, primary_key=True)
    router_id = Column(Integer, ForeignKey("routers.id", ondelete="CASCADE"), nullable=False, index=True)
    interface_name = Column(String(128), nullable=False)
    interface_type = Column(String(64), default="")
    enabled = Column(Boolean, default=False, nullable=False)
    alert_down = Column(Boolean, default=True, nullable=False)
    rx_limit_mbps = Column(Float, default=0, nullable=False)
    tx_limit_mbps = Column(Float, default=0, nullable=False)
    warning_pct = Column(Float, default=80, nullable=False)
    running = Column(Boolean, default=False)
    rx_mbps = Column(Float, default=0)
    tx_mbps = Column(Float, default=0)
    rx_bytes = Column(BigInteger, default=0)
    tx_bytes = Column(BigInteger, default=0)
    sampled_at = Column(Float, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow)

# SQLite-safe unique key enforced in code.
_lock = threading.Lock()
_started = False
_last_error = {}

def _api_interfaces(router):
    """Read-only RouterOS interface discovery and counter polling."""
    api = mikrotik._connect(router)
    try:
        rows = []
        try:
            rows = list(api.path("interface").call("print", {"stats": ""}))
        except Exception:
            rows = list(api.path("interface"))
        result = []
        for row in rows:
            name = str(row.get("name") or "")
            if not name:
                continue
            rx = row.get("rx-byte", row.get("rx-bytes"))
            tx = row.get("tx-byte", row.get("tx-bytes"))
            # If print stats did not expose counters, ask RouterOS for
            # instantaneous traffic. This is read-only.
            rxrate = txrate = None
            if rx is None or tx is None:
                try:
                    traffic = list(api.path("interface").call(
                        "monitor-traffic", {"interface": name, "once": ""}
                    ))
                    if traffic:
                        rxrate = float(traffic[0].get("rx-bits-per-second", 0)) / 1_000_000
                        txrate = float(traffic[0].get("tx-bits-per-second", 0)) / 1_000_000
                except Exception:
                    pass
            result.append({
                "name": name,
                "type": str(row.get("type") or ""),
                "running": str(row.get("running", "false")).lower() in ("true", "yes", "1"),
                "disabled": str(row.get("disabled", "false")).lower() in ("true", "yes", "1"),
                "rx": int(rx) if rx is not None else None,
                "tx": int(tx) if tx is not None else None,
                "rxrate": rxrate,
                "txrate": txrate,
            })
        return result
    finally:
        api.close()


def discover_once():
    """List VLAN candidates only; do not automatically add them."""
    result = {"routers": 0, "interfaces": 0, "vlans": [], "errors": []}
    with SessionLocal() as db:
        routers = ctx.router_dicts(db)
    for router in routers:
        if not router.get("api_enabled", True):
            continue
        result["routers"] += 1
        try:
            rows = _api_interfaces(router)
            with SessionLocal() as db:
                existing = {
                    p.interface_name for p in db.query(InterfacePolicy).filter_by(
                        router_id=router["id"]
                    ).all()
                }
            for row in rows:
                if row["type"].strip().lower() != "vlan":
                    continue
                result["interfaces"] += 1
                result["vlans"].append({
                    "router_id": router["id"], "router": router["name"],
                    "name": row["name"], "type": row["type"],
                    "running": row["running"], "disabled": row["disabled"],
                    "added": row["name"] in existing
                })
        except Exception as e:
            msg = str(e)[:180]
            _last_error[router["id"]] = msg
            result["errors"].append({"router": router["name"], "error": msg})
    return result


def add_vlan(data):
    rid = int(data.get("router_id", 0))
    name = str(data.get("name", "")).strip()
    if not rid or not name or len(name) > 128:
        raise ValueError("Select a valid router and VLAN.")
    with SessionLocal() as db:
        router = next((r for r in ctx.router_dicts(db) if r["id"] == rid), None)
    if not router or not router.get("api_enabled", True):
        raise ValueError("Router API is unavailable or disabled.")
    rows = _api_interfaces(router)
    row = next((x for x in rows if x["name"] == name and
                x["type"].strip().lower() == "vlan"), None)
    if not row:
        raise ValueError("VLAN not found on router. Run discovery again.")
    with SessionLocal() as db:
        p = db.query(InterfacePolicy).filter_by(
            router_id=rid, interface_name=name
        ).first()
        if p is None:
            p = InterfacePolicy(
                router_id=rid, interface_name=name, interface_type="vlan",
                enabled=False, alert_down=True, rx_limit_mbps=0,
                tx_limit_mbps=0, warning_pct=80
            )
            db.add(p)
        else:
            p.interface_type = "vlan"
        db.commit()
    return {"ok": True, "router_id": rid, "name": name}


def remove_vlan(data):
    rid = int(data.get("router_id", 0))
    name = str(data.get("name", "")).strip()
    with SessionLocal() as db:
        p = db.query(InterfacePolicy).filter_by(
            router_id=rid, interface_name=name,
            interface_type="vlan"
        ).first()
        if not p:
            raise ValueError("Monitored VLAN not found.")
        pid = p.id
        db.delete(p)
        db.commit()
    for suffix in (":down", ":rx", ":tx"):
        try:
            monitor.clear_alarm(f"ifmon:{rid}:{name}{suffix}")
        except Exception:
            log.exception("Could not clear removed VLAN alarm")
    return {"ok": True, "id": pid}

def poll_once():
    if not _lock.acquire(blocking=False):
        return
    try:
        with SessionLocal() as db:
            routers = {r.id: r for r in db.query(Router).all()}
            policies = db.query(InterfacePolicy).filter(InterfacePolicy.interface_type == 'vlan').all()
        grouped = {}
        for p in policies:
            grouped.setdefault(p.router_id, []).append(p)
        now = time.time()
        for rid, plist in grouped.items():
            router_obj = routers.get(rid)
            if not router_obj:
                continue
            # API config is obtained through the existing secure router helper.
            with SessionLocal() as db:
                rd = next((x for x in ctx.router_dicts(db) if x["id"] == rid), None)
            if not rd or not rd.get("api_enabled", True):
                continue
            try:
                rows = _api_interfaces(rd)
                by_name = {x["name"]: x for x in rows}
                _last_error.pop(rid, None)
            except Exception as e:
                _last_error[rid] = str(e)[:180]
                continue
            with SessionLocal() as db:
                for old in plist:
                    p = db.query(InterfacePolicy).filter_by(id=old.id).first()
                    if not p:
                        continue
                    row = by_name.get(p.interface_name)
                    if row is None:
                        continue
                    rx, tx = row["rx"], row["tx"]
                    elapsed = now - float(p.sampled_at or 0)
                    if rx is not None and tx is not None and elapsed > 0 and p.sampled_at:
                        if rx >= (p.rx_bytes or 0) and tx >= (p.tx_bytes or 0):
                            p.rx_mbps = round((rx - (p.rx_bytes or 0)) * 8 / elapsed / 1_000_000, 3)
                            p.tx_mbps = round((tx - (p.tx_bytes or 0)) * 8 / elapsed / 1_000_000, 3)
                        else:
                            p.rx_mbps = p.tx_mbps = 0
                    elif row["rxrate"] is not None:
                        p.rx_mbps, p.tx_mbps = round(row["rxrate"], 3), round(row["txrate"], 3)
                    p.running = bool(row["running"] and not row["disabled"])
                    p.interface_type = row["type"]
                    if rx is not None:
                        p.rx_bytes = rx
                    if tx is not None:
                        p.tx_bytes = tx
                    p.sampled_at = now
                    p.updated_at = datetime.utcnow()

                    key = f"ifmon:{rid}:{p.interface_name}"
                    dev = f"{router_obj.name} / {p.interface_name}"
                    if p.enabled and p.alert_down and not p.running:
                        monitor.raise_alarm(key + ":down", "critical", dev, "Interface is DOWN")
                    else:
                        monitor.clear_alarm(key + ":down")
                    if p.enabled and p.running:
                        for direction, value, limit in (
                            ("RX", p.rx_mbps or 0, p.rx_limit_mbps or 0),
                            ("TX", p.tx_mbps or 0, p.tx_limit_mbps or 0),
                        ):
                            alarm_key = key + ":" + direction.lower()
                            if limit > 0 and value >= limit * 1.2:
                                monitor.raise_alarm(alarm_key, "critical", dev,
                                    f"{direction} traffic {value:.3f} Mbps exceeds critical threshold ({limit:.3f} Mbps)")
                            elif limit > 0 and value >= limit * (p.warning_pct or 80) / 100:
                                monitor.raise_alarm(alarm_key, "warning", dev,
                                    f"{direction} traffic {value:.3f} Mbps is near/exceeds limit ({limit:.3f} Mbps)")
                            else:
                                monitor.clear_alarm(alarm_key)
                db.commit()
    finally:
        _lock.release()

def start():
    global _started
    if _started:
        return
    _started = True
    def worker():
        time.sleep(5)
        while True:
            try:
                discover_once()
                poll_once()
            except Exception:
                log.exception("Interface monitor polling failed")
            time.sleep(15)
    threading.Thread(target=worker, daemon=True, name="interface-monitor").start()

def snapshot():
    with SessionLocal() as db:
        policies = db.query(InterfacePolicy).order_by(
            InterfacePolicy.router_id, InterfacePolicy.interface_name
        ).filter(InterfacePolicy.interface_type == 'vlan').all()
        routers = {r.id: r.name for r in db.query(Router).all()}
        return {
            "ts": time.time(),
            "interval": 15,
            "errors": [{"router_id": k, "error": v} for k, v in _last_error.items()],
            "interfaces": [{
                "id": p.id, "router_id": p.router_id,
                "router": routers.get(p.router_id, f"Router {p.router_id}"),
                "name": p.interface_name, "type": p.interface_type,
                "enabled": bool(p.enabled), "alert_down": bool(p.alert_down),
                "running": bool(p.running), "rx_mbps": p.rx_mbps or 0,
                "tx_mbps": p.tx_mbps or 0, "rx_limit_mbps": p.rx_limit_mbps or 0,
                "tx_limit_mbps": p.tx_limit_mbps or 0, "warning_pct": p.warning_pct or 80,
                "sampled_at": p.sampled_at or 0,
            } for p in policies]
        }

def save_policy(data):
    with SessionLocal() as db:
        p = db.query(InterfacePolicy).filter_by(id=int(data.get("id", 0))).first()
        if not p:
            raise ValueError("Interface not found; run discovery first.")
        def number(key, default, maximum):
            value = float(data.get(key, default) or 0)
            if value < 0 or value > maximum:
                raise ValueError(f"Invalid {key}")
            return value
        p.enabled = bool(data.get("enabled"))
        p.alert_down = bool(data.get("alert_down", True))
        p.rx_limit_mbps = number("rx_limit_mbps", 0, 10_000_000)
        p.tx_limit_mbps = number("tx_limit_mbps", 0, 10_000_000)
        p.warning_pct = number("warning_pct", 80, 100)
        p.updated_at = datetime.utcnow()
        db.commit()
        return True
