"""MAC vendor lookup from the IEEE OUI list (data/oui.csv)."""
import csv
import os
import re
import threading

import httpx

PATH = "data/oui.csv"
URL = "https://standards-oui.ieee.org/oui/oui.csv"
_db = {}


def load():
    global _db
    d = {}
    if os.path.exists(PATH):
        with open(PATH, encoding="utf-8", errors="ignore", newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
                    d[row[1].strip().upper()] = row[2].strip()
    _db = d
    return len(d)


def update():
    r = httpx.get(URL, timeout=90, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 isp-portal"})
    r.raise_for_status()
    if "Assignment" not in r.text[:200]:
        raise RuntimeError("Unexpected OUI file format")
    with open(PATH, "w", encoding="utf-8") as f:
        f.write(r.text)
    return load()


def save_upload(data: bytes):
    with open(PATH, "wb") as f:
        f.write(data)
    return load()


def size():
    return len(_db)


def short(name):
    s = re.sub(r"(?i)[,.\s]*(co\.?,?\s*ltd\.?|technolog\w*|corporation|corp\.?|inc\.?|limited|ltd\.?|"
               r"international|electronics?|communications?).*$", "", name or "").strip(" ,.-")
    return s or name


def describe(mac):
    if not mac:
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(h) < 6:
        return None
    name = _db.get(h[:6])
    return dict(mac=mac, vendor=name, short=short(name) if name else None,
                local=bool(int(h[:2], 16) & 2))


def background_init():
    load()
    if not _db:
        threading.Thread(target=lambda: _try(update), daemon=True).start()


def _try(fn):
    try:
        fn()
    except Exception:
        pass
