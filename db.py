import json
import os
from datetime import datetime
from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine,
                        inspect, text)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

os.makedirs("data", exist_ok=True)
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./data/portal.db")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

STATUS_LABEL = {"open": "Open", "waiting": "Waiting for update", "replied": "Replied", "closed": "Closed"}


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")


class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True)
    password_hash = Column(String(256))
    role = Column(String(24), default="admin", nullable=False)


class Router(Base):
    __tablename__ = "routers"
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    host = Column(String(128))
    api_enabled = Column(Boolean, default=True)
    port = Column(Integer, default=8728)
    username = Column(String(64), default="")
    password = Column(String(128), default="")
    use_ssl = Column(Boolean, default=False)
    snmp_enabled = Column(Boolean, default=False)
    snmp_port = Column(Integer, default=161)
    snmp_community = Column(String(64), default="public")


class OltProfile(Base):
    """Vendor OID profile. `oids` = {field: {"oid": column OID, "div": 1, "unit": "dbm"}}"""
    __tablename__ = "olt_profiles"
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    vendor = Column(String(32), default="Other")
    enterprise_oid = Column(String(64), default="")
    index_template = Column(String(64), default="{ifindex}")   # vars: ifindex slot pon onu
    oids = Column(Text, default="{}")
    status_map = Column(String(255), default="")             # "1=Online,2=Offline"
    notes = Column(Text, default="")


class OLT(Base):
    __tablename__ = "olts"
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    vendor = Column(String(32), default="BDCOM")
    host = Column(String(128))
    snmp_port = Column(Integer, default=161)
    community = Column(String(64), default="public")
    snmp_version = Column(String(4), default="2c")
    profile_id = Column(Integer, ForeignKey("olt_profiles.id", ondelete="SET NULL"), nullable=True)
    vlans = Column(String(255), default="")      # optional: community@vlan tries for FDB lookup
    enabled = Column(Boolean, default=True)


class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True)
    token = Column(String(32), unique=True, index=True)
    user_id = Column(String(128), unique=True, index=True)   # PPPoE username
    name = Column(String(128), default="")
    phone = Column(String(20), default="", index=True)
    address = Column(String(255), default="")
    onu_mac = Column(String(20), default="")                 # optional manual ONU MAC
    router_id = Column(Integer, ForeignKey("routers.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    complaints = relationship("Complaint", back_populates="customer", cascade="all, delete-orphan",
                              order_by="Complaint.id.desc()")


class Complaint(Base):
    __tablename__ = "complaints"
    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"))
    category = Column(String(64))
    message = Column(Text, default="")
    contact_phone = Column(String(20), default="")
    status = Column(String(16), default="open", index=True)   # open / waiting / replied / closed
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(64), default="")
    resolve_note = Column(Text, default="")
    tg_message_id = Column(Integer, nullable=True)
    notify_error = Column(String(255), default="")
    diag_json = Column(Text, default="")
    tg_diag_message_id = Column(Integer, nullable=True)
    olt_name = Column(String(64), default="")
    pon = Column(String(16), default="")
    customer = relationship("Customer", back_populates="complaints")
    replies = relationship("ComplaintReply", cascade="all, delete-orphan", order_by="ComplaintReply.id")


class ComplaintReply(Base):
    __tablename__ = "complaint_replies"
    id = Column(Integer, primary_key=True)
    complaint_id = Column(Integer, ForeignKey("complaints.id"))
    role = Column(String(12), default="staff")      # staff / customer / system
    author = Column(String(64), default="")
    kind = Column(String(12), default="reply")      # reply / wait / close
    message = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Alarm(Base):
    __tablename__ = "alarms"
    id = Column(Integer, primary_key=True)
    key = Column(String(128), index=True)
    level = Column(String(12), default="warning")      # critical / warning
    device = Column(String(64), default="")
    message = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    cleared_at = Column(DateTime, nullable=True)
    ack_by = Column(String(64), default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow)
    who = Column(String(64), default="")
    action = Column(String(32), default="")
    target = Column(String(128), default="")
    detail = Column(Text, default="")


def audit(db, who, action, target="", detail=""):
    db.add(AuditLog(who=who or "", action=action, target=target, detail=(detail or "")[:500]))
    db.commit()


def _migrate():
    """Add columns that new versions introduced (SQLite has no auto-migrate)."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for t in Base.metadata.sorted_tables:
            if not insp.has_table(t.name):
                continue
            have = {c["name"] for c in insp.get_columns(t.name)}
            for col in t.columns:
                if col.name in have:
                    continue
                d = col.default.arg if col.default is not None else None
                if callable(d):
                    d = None
                ddl = f'ALTER TABLE {t.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}'
                if isinstance(d, bool):
                    ddl += f" DEFAULT {int(d)}"
                elif isinstance(d, (int, float)):
                    ddl += f" DEFAULT {d}"
                elif isinstance(d, str):
                    ddl += " DEFAULT '" + d.replace("'", "''") + "'"
                conn.execute(text(ddl))
        conn.execute(text("UPDATE complaints SET status='closed' WHERE status='resolved'"))


DEFAULT_PROFILES = [
    ("BDCOM EPON", "BDCOM", "1.3.6.1.4.1.3320"),
    ("V-SOL EPON", "VSOL", "1.3.6.1.4.1.37950"),
    ("C-Data EPON", "C-Data", "1.3.6.1.4.1.17409"),
    ("Generic (standard MIB only)", "Other", ""),
]


# Documented BDCOM EPON OIDs. conf="high": confirmed by several independent public sources
# (LibreNMS BDCOM support, NAG wiki, ixnfo.com, ISP forums). conf="low": single source, verify first.
BDCOM_OIDS = {
    "rx": dict(oid="1.3.6.1.4.1.3320.101.10.5.1.5", div=10, unit="dbm", conf="high"),
    "tx": dict(oid="1.3.6.1.4.1.3320.101.10.5.1.6", div=10, unit="dbm", conf="high"),
    "mac": dict(oid="1.3.6.1.4.1.3320.101.10.1.1.3", div=1, unit="dbm", conf="high"),
    "temp": dict(oid="1.3.6.1.4.1.3320.101.10.5.1.2", div=256, unit="dbm", conf="low"),
    "voltage": dict(oid="1.3.6.1.4.1.3320.101.10.5.1.3", div=10000, unit="dbm", conf="low"),
    "distance": dict(oid="1.3.6.1.4.1.3320.101.11.1.1.7", div=1, unit="dbm", conf="low", index="auto"),
    "model": dict(oid="1.3.6.1.4.1.3320.101.10.1.1.2", div=1, unit="dbm", conf="low"),
    "vendor": dict(oid="1.3.6.1.4.1.3320.101.10.1.1.1", div=1, unit="dbm", conf="low"),
}
BDCOM_NOTES = ("Index = ONU ifIndex (EPON0/x:y). Rx/Tx unit 0.1 dBm (-2147483648 = ONU offline). "
               "Temp unit 1/256 °C, voltage unit 100 µV. Distance table .11.1.1.7 may be indexed by "
               "<PON ifIndex>.<ONU MAC> (index mode auto tries both). conf=low rows: verify against the OLT CLI "
               "(show epon optical-transceiver-diagnosis interface EPON 0/1:5).")
NOTES = {
    "V-SOL EPON": ("V1600D EPON reports ONU power as TEXT like '0.02 mW (-18.12 dBm)': use unit 'dBm from text'. "
                   "Public sources point at enterprise 37950 (.1.1.5.12...) but the exact table index is not confirmed. "
                   "Use OLT Tools -> Discover with the values from the OLT CLI."),
    "C-Data EPON": ("Public Zabbix template for FD1304E-B1 (enterprise 17409): status .2.3.4.1.1.8 (1=online,2=offline), "
                    "Rx .2.3.4.2.1.4 and Tx .2.3.4.2.1.5 (unit 0.01 dBm), voltage .2.1.6 (mV), temperature .2.1.7 (0.0001 °C), "
                    "indexed by ONU_ID.1.<port>. How ONU_ID maps to a PON/ONU is NOT confirmed: use Discover."),
}


def seed_profiles(db):
    import json as _json
    for p in db.query(OltProfile).all():
        if p.name == "BDCOM EPON" and (not p.oids or p.oids.strip() in ("", "{}")):
            p.oids, p.notes, p.status_map = _json.dumps(BDCOM_OIDS), BDCOM_NOTES, ""
        if p.name in NOTES and not p.notes:
            p.notes = NOTES[p.name]
    db.commit()


def init_db():
    Base.metadata.create_all(engine)
    _migrate()
    with SessionLocal() as db:
        if not db.query(OltProfile).count():
            for n, v, e in DEFAULT_PROFILES:
                db.add(OltProfile(name=n, vendor=v, enterprise_oid=e, index_template="{ifindex}", oids="{}",
                                  status_map="1=Online,2=Offline"))
            db.commit()
        seed_profiles(db)


def get_setting(key, default=""):
    with SessionLocal() as db:
        s = db.get(Setting, key)
        return s.value if s and s.value is not None else default


def set_setting(key, value):
    with SessionLocal() as db:
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
        db.commit()


def apply_action(db, cid, action, by, message="", role="staff"):
    """action: reply / wait / close. Returns complaint, or None if missing/closed."""
    c = db.get(Complaint, cid)
    if not c or c.status == "closed":
        return None
    message = (message or "").strip()[:1000]
    if action == "close":
        c.status, c.resolved_at, c.resolved_by, c.resolve_note = "closed", datetime.utcnow(), by[:64], message
    elif action == "wait":
        c.status = "waiting"
    elif action == "reply":
        c.status = "replied" if role == "staff" else "open"
    db.add(ComplaintReply(complaint_id=c.id, role=role, author=by[:64], kind=action, message=message))
    db.commit()
    return c
