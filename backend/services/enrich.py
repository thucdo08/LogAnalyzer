# backend/services/enrich.py
import re
import pandas as pd
from ipaddress import ip_address
from datetime import datetime
import functools
import bisect

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TOKEN_RE = re.compile(r"(?:apikey|api_key|token|bearer)\s*[:=]\s*([A-Za-z0-9\-\._]+)", re.I)

def _is_private(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except Exception:
        return False

def classify_ip(df: pd.DataFrame) -> pd.DataFrame:
    if "source_ip" in df.columns:
        df["ip_private"] = df["source_ip"].astype(str).map(lambda x: _is_private(x))
        df["ip_scope"] = df["ip_private"].map(lambda b: "private" if b else "public")
    return df

def mask_pii(df: pd.DataFrame) -> pd.DataFrame:
    if "message" in df.columns:
        def _mask(s: str) -> str:
            if not isinstance(s, str):
                return s
            s = EMAIL_RE.sub("[redacted@email]", s)
            s = TOKEN_RE.sub(lambda m: m.group(0).replace(m.group(1), "***"), s)
            return s
        df["message"] = df["message"].map(_mask)
    return df

def geoip_enrich(df: pd.DataFrame, city_mmdb=None, asn_mmdb=None) -> pd.DataFrame:
    if not city_mmdb and not asn_mmdb:
        return df
    try:
        import geoip2.database
    except Exception:
        return df
    if "source_ip" not in df.columns or df.empty:
        return df
    reader_city = reader_asn = None
    try:
        if city_mmdb:
            reader_city = geoip2.database.Reader(city_mmdb)
        if asn_mmdb:
            reader_asn = geoip2.database.Reader(asn_mmdb)
        country, asn = [], []
        for ip in df["source_ip"].astype(str):
            c = a = None
            try:
                if reader_city:
                    c = reader_city.city(ip).country.iso_code
            except Exception:
                pass
            try:
                if reader_asn:
                    a = reader_asn.asn(ip).autonomous_system_organization
            except Exception:
                pass
            country.append(c)
            asn.append(a)
        if reader_city:
            reader_city.close()
        if reader_asn:
            reader_asn.close()
        if city_mmdb:
            df["geoip_country"] = country
        if asn_mmdb:
            df["asn_org"] = asn
    except Exception:
        pass
    return df

def enrich_df(df: pd.DataFrame, cfg) -> pd.DataFrame:
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return df
    if not isinstance(cfg, dict):
        cfg = {}
    cfg = cfg or {}
    df = df.copy()
    df = classify_ip(df)
    if cfg.get("mask_pii", True):
        df = mask_pii(df)
    df = geoip_enrich(df, cfg.get("geoip_mmdb"), cfg.get("asn_mmdb"))
    df = map_to_ecs(df)
    df = enrich_threat_intel(df, cfg)
    df = enrich_assets(df, cfg)
    df = enrich_identity(df, cfg)
    df = correlate_dhcp(df, cfg)
    return df

# -------------------- ECS-like mapping --------------------
def _safe_int(val):
    try:
        if val in (None, "", float("nan")):
            return None
    except Exception:
        pass
    try:
        return int(val)
    except Exception:
        return None

def _map_outcome(status: str | None) -> str | None:
    if not status:
        return None
    s = str(status).lower()
    if s in ("success", "ok", "accept", "allowed"):
        return "success"
    if s in ("failed", "failure", "blocked", "reject", "denied"):
        return "failure"
    if s in ("alert", "info", "unknown"):
        return s
    return None

def map_to_ecs(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    # timestamps already UTC; ensure proper dtype
    if "timestamp" in out.columns:
        out["@timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)

    # event.*
    out["event.action"] = out.get("action")
    out["event.outcome"] = out.get("status").map(_map_outcome) if "status" in out.columns else None
    if "program" in out.columns:
        out["event.module"] = out["program"]

    # source/destination
    out["source.ip"] = out.get("source_ip")
    out["source.port"] = out.get("src_port").map(_safe_int) if "src_port" in out.columns else None
    out["destination.ip"] = out.get("dest_ip")
    # allow alternate naming
    if out["destination.ip"].isna().all() and "dst_ip" in out.columns:
        out["destination.ip"] = out["dst_ip"]
    out["destination.port"] = (
        out.get("dest_port").map(_safe_int) if "dest_port" in out.columns else None
    )
    if out.get("destination.port") is None and "dst_port" in out.columns:
        out["destination.port"] = out["dst_port"].map(_safe_int)

    # user/process/host
    out["user.name"] = out.get("username")
    proc_col = "process_name" if "process_name" in out.columns else "process"
    if proc_col in out.columns:
        out["process.name"] = out[proc_col]
    if "host" in out.columns:
        out["host.name"] = out["host"]

    # http/url convenience
    if "url" in out.columns:
        out["url.full"] = out["url"]
    if "path" in out.columns:
        out["url.path"] = out["path"]
    if "method" in out.columns:
        out["http.request.method"] = out["method"]
    if "http_status" in out.columns:
        try:
            out["http.response.status_code"] = out["http_status"].astype("Int64")
        except Exception:
            out["http.response.status_code"] = out["http_status"]

    # Apache/HTTP-specific enrichment
    if "device" in out.columns:
        out["client.device"] = out["device"]
    if "dept" in out.columns:
        out["client.department"] = out["dept"]
    if "attack_type" in out.columns:
        out["threat.attack_type"] = out["attack_type"]
    if "vhost" in out.columns:
        out["server.domain"] = out["vhost"]

    # Firewall-specific enrichment
    if "rule" in out.columns:
        out["network.rule"] = out["rule"]
    if "dst_host" in out.columns:
        out["destination.domain"] = out["dst_host"]
    if "protocol" in out.columns:
        out["network.transport"] = out["protocol"].astype(str).str.lower()

    # Syslog-specific enrichment
    if "facility" in out.columns:
        out["log.syslog.facility"] = out["facility"]
    if "severity" in out.columns:
        out["log.syslog.severity"] = out["severity"]

    return out

# -------------------- Threat Intel --------------------
def _to_set(val):
    if not val:
        return set()
    if isinstance(val, list):
        return set(str(x).strip() for x in val if str(x).strip())
    return set(str(val).split(","))

def enrich_threat_intel(df: pd.DataFrame, cfg) -> pd.DataFrame:
    ti = cfg.get("threat_intel", {}) if isinstance(cfg, dict) else {}
    bad_ips = _to_set(ti.get("bad_ips"))
    bad_domains = _to_set(ti.get("bad_domains"))
    bad_urls = _to_set(ti.get("bad_urls"))
    if df is None or df.empty:
        return df
    out = df.copy()
    hits = []
    for _, row in out.iterrows():
        indicators = []
        sip = str(row.get("source_ip") or "")
        dip = str(row.get("dest_ip") or row.get("dst_ip") or "")
        dom = str(row.get("domain") or "")
        url = str(row.get("url") or "")
        if sip and sip in bad_ips:
            indicators.append({"type": "ip", "match": sip, "field": "source_ip"})
        if dip and dip in bad_ips:
            indicators.append({"type": "ip", "match": dip, "field": "dest_ip"})
        if dom and dom in bad_domains:
            indicators.append({"type": "domain", "match": dom, "field": "domain"})
        if url and url in bad_urls:
            indicators.append({"type": "url", "match": url, "field": "url"})
        hits.append(indicators if indicators else None)
    out["threat.indicator"] = hits
    out["threat.matched"] = out["threat.indicator"].apply(lambda v: bool(v))
    return out

# -------------------- Asset Mapping --------------------
def enrich_assets(df: pd.DataFrame, cfg) -> pd.DataFrame:
    assets = cfg.get("assets", {}) if isinstance(cfg, dict) else {}
    if not assets or df is None or df.empty:
        return df
    out = df.copy()
    src_names = []
    dst_names = []
    for _, row in out.iterrows():
        sip = str(row.get("source_ip") or "")
        dip = str(row.get("dest_ip") or row.get("dst_ip") or "")
        src_names.append(assets.get(sip))
        dst_names.append(assets.get(dip))
    out["source.asset.name"] = src_names
    out["destination.asset.name"] = dst_names
    return out

# -------------------- Identity Mapping --------------------
def enrich_identity(df: pd.DataFrame, cfg) -> pd.DataFrame:
    idmap = cfg.get("identity", {}) if isinstance(cfg, dict) else {}
    if not idmap or df is None or df.empty:
        return df
    out = df.copy()
    dept = []
    role = []
    for _, row in out.iterrows():
        user = str(row.get("username") or row.get("user.name") or "")
        meta = idmap.get(user) if user else None
        dept.append((meta or {}).get("department"))
        role.append((meta or {}).get("role"))
    out["user.department"] = dept
    out["user.role"] = role
    return out

# -------------------- DHCP Correlation --------------------
@functools.lru_cache(maxsize=2)
def _load_dhcp_leases(csv_path: str) -> pd.DataFrame | None:
    try:
        import pandas as _pd
        df = _pd.read_csv(csv_path)
        # expected columns: ip, mac, start, end (ISO time)
        for col in ("start", "end"):
            if col in df.columns:
                df[col] = _pd.to_datetime(df[col], errors="coerce", utc=True)
        return df
    except Exception:
        return None

def correlate_dhcp(df: pd.DataFrame, cfg) -> pd.DataFrame:
    leases_csv = None
    if isinstance(cfg, dict):
        leases = cfg.get("dhcp", {})
        leases_csv = leases.get("leases_csv") if isinstance(leases, dict) else None
    if not leases_csv or df is None or df.empty:
        return df
    leases_df = _load_dhcp_leases(leases_csv)
    if leases_df is None or leases_df.empty:
        return df
    out = df.copy()
    macs = []
    for _, row in out.iterrows():
        ts = row.get("timestamp")
        sip = row.get("source_ip")
        mac = None
        try:
            tsu = pd.to_datetime(ts, errors="coerce", utc=True)
            if pd.notna(tsu) and isinstance(sip, str):
                cand = leases_df[leases_df["ip"].astype(str) == sip]
                if not cand.empty and "start" in cand.columns and "end" in cand.columns:
                    m = cand[(cand["start"] <= tsu) & (tsu < cand["end"])].head(1)
                    if not m.empty:
                        mac = m.iloc[0].get("mac")
        except Exception:
            pass
        macs.append(mac)
    out["source.mac"] = macs
    return out

