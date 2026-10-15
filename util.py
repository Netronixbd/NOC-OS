import re

import snmp


def norm_phone(s):
    d = re.sub(r"\D", "", s or "")
    if d.startswith("880"):
        d = "0" + d[3:]
    elif len(d) == 10 and d.startswith("1"):
        d = "0" + d
    return d


def mask_phone(p):
    return p[:3] + "****" + p[-3:] if p and len(p) >= 8 else ("****" if p else "-")


def mask_uid(u):
    return u[:2] + "*" * max(len(u) - 2, 2)


def mask_name(n):
    n = (n or "").strip()
    return n[:2] + "*" * max(len(n) - 2, 2) if n else ""


def parse_comment(comment):
    pat = r"(?:\+?88)?01\d{9}"
    m = re.search(pat, comment or "")
    phone = norm_phone(m.group(0)) if m else ""
    name = re.sub(pat, "", comment or "").strip(" -|,:/")
    return name, phone


def looks_mac(s):
    s = (s or "").strip()
    return snmp.norm_mac(s) is not None and bool(re.fullmatch(r"[0-9A-Fa-f:.\-]{12,17}", s))
