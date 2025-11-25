# backend/services/preprocess.py
import re
from datetime import datetime
from io import BytesIO, StringIO
from urllib.parse import urlparse
import pandas as pd
import json
import sys

# --- Regex nhận diện các định dạng log mạng ---
# Syslog cổ điển: "Jun  9 06:06:20 host program: message"
_SYSLOG_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'(?P<program>[^:]+):\s(?P<message>.*)$'
)

# OpenSSH log format (subset of syslog)
# e.g. "Dec 10 06:55:46 LabSZ sshd[24200]: Accepted publickey for user from 192.168.1.100 port 22"
_OPENSSH_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'sshd\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# Linux system log (subset of syslog)
# e.g. "Dec 10 06:55:46 LabSZ kernel: [12345.678] eth0: link up"
_LINUX_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'(?P<program>kernel|network|systemd|dhcp|dns|firewall|iptables):\s(?P<message>.*)$'
)

# Network-specific log formats
# Apache Access Log (Common/Combined format)
# e.g. "192.168.1.100 - - [10/Oct/2000:13:55:36 -0700] "GET /path?q=1 HTTP/1.1" 200 2326 "ref" "ua""
_APACHE_ACCESS_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<hostname>\S+)\s+httpd\[\d+\]:\s'
    r'(?P<remote_addr>\S+)\s+\S+\s+(?P<username>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s'
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes_sent>\S+)(?: '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)")?'
    r'(?:\s+vhost=(?P<vhost>\S+))?'
    r'(?:\s+attack=(?P<attack>\S+))?$'
)

# ISO syslog (YYYY-MM-DD HH:MM:SS host program[pid]: message)
_SYSLOG_ISO_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<program>[^:]+):\s(?P<message>.*)$'
)

# Auth (sshd) ISO variant convenience (same as _SYSLOG_ISO_RE then parse message)

# Config change log (configd)
_CONFIG_CHANGE_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<process>configd):\s+(?P<configuration>[A-Za-z0-9_.:\-]+)\s+configuration\s+'
    r'(?P<action>updated|rolled back|applied|reloaded)\s+by\s+(?P<actor>\S+)\s+change_id=(?P<change_id>\d+)(?:\s+.*)?$'
)

# EDR network (Sysmon EventID=3 style, simplified)
_EDR_NET_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+Sysmon:\s*EventID=3.*?'
    r'Image=(?P<image>\S+).*?DestinationIp=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?'
    r'DestinationPort=(?P<dst_port>\d+)\s+Protocol=(?P<proto>\w+)',
    re.IGNORECASE
)

# Netflow aggregated logs
_NETFLOW_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+NETFLOW\s+'
    r'src=(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+'
    r'dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)\s+'
    r'proto=(?P<proto>\w+)\s+bytes=(?P<bytes>\d+)\s+pkts=(?P<pkts>\d+)\s+'
    r'action=(?P<action>\w+)(?:"?\s*)$'
)

# ModSecurity WAF
_MODSEC_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+ModSecurity:\s*(?P<level>Warning|Error)\.\s+.*?'
    r'\[msg\s+"(?P<msg>.*?)"\].*?\[uri\s+"(?P<uri>.*?)"\].*?\[client\s+(?P<client>\d+\.\d+\.\d+\.\d+)\]'
    r'.*?(?:\[id\s+"(?P<rule_id>\d+)"\])?.*$',
    re.IGNORECASE
)

# Simple IDS line (non-EVE), supports both ALERT and INFO levels
# Example:
# 2025-09-29 12:15:16 SURICATA ALERT: signature="..." severity=High src=... dst=... proto=TCP
# 2025-09-30 08:30:00 SURICATA INFO: signature="..." severity=Low src=... dst=... proto=TCP
_IDS_ALERT_SIMPLE_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'SURICATA\s+(?P<level>ALERT|INFO):\s+'
    r'signature="(?P<signature>.*?)"\s+'
    r'severity=(?P<severity>\w+)\s+'
    r'src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'proto=(?P<proto>\w+)',
    re.IGNORECASE
)

# AWS VPC Flow style
_VPCFLOW_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+aws:vpcflow\s+'
    r'src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'dport=(?P<dst_port>\d+)\s+protocol=(?P<proto>\d+)\s+action=(?P<action>ACCEPT|REJECT)\s+bytes=(?P<bytes>\d+)$',
    re.IGNORECASE
)

# IDS Alert (Suricata)
# e.g. "09/27/2025-15:00:01.255000  [**] [1:1000001:1] ET POLICY Suspicious User-Agent [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.100:12345 -> 10.0.0.1:80"
_SURICATA_RE = re.compile(
    r'^(?P<date>\d{2}/\d{2}/\d{4})-(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})\s+'
    r'\[\*\*\]\s+\[(?P<sid>\d+:\d+:\d+)\]\s+(?P<msg>[^\[]+)\s+\[\*\*\]\s+'
    r'\[Classification:\s*(?P<classification>[^\]]+)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+'
    r'\{(?P<proto>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+'
    r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)$'
)

# DNS log (Zeek format)
# e.g. "27-Sep-2025 15:00:01.255 client @0x428da809 172.20.196.49#60416 (telemetry.example.com): query: telemetry.example.com IN CNAME + (192.168.1.53)"
_ZEEK_DNS_RE = re.compile(
    r'^(?P<date>\d{2}-[A-Za-z]{3}-\d{4})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'client\s+@(?P<client_id>\w+)\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)#(?P<src_port>\d+)\s+'
    r'\((?P<query>[^)]+)\):\s+query:\s+(?P<domain>\S+)\s+IN\s+(?P<qtype>\w+)\s+'
    r'(?P<flags>[^)]+)\s+\((?P<server>\d+\.\d+\.\d+\.\d+)\)$'
)

# Firewall log (iptables/netfilter)
# e.g. "Dec 10 06:55:46 LabSZ kernel: [12345.678] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1"
_FIREWALL_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'kernel:\s\[(?P<timestamp>\d+\.\d+)\]\s'
    r'(?P<message>.*)$'
)

# DHCP log
# e.g. "Dec 10 06:55:46 LabSZ dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0"
_DHCP_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?:(?P<host>\S+)\s+)?'               # <-- hostname OPTIONAL
    r'dhcpd(?:\[(?P<pid>\d+)\])?:\s'       # <-- optional [PID]
    r'(?P<message>.*)$'
)


# DNS log (bind/named)
# e.g. "Dec 10 06:55:46 LabSZ named[1234]: client 192.168.1.100#12345: query: example.com IN A"
_DNS_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'named\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# Proxy log (Squid)
# e.g. "1640995201.123 1234 192.168.1.100 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/1.2.3.4 text/html"
_SQUID_RE = re.compile(
    r'^(?P<timestamp>\d+\.\d{3})\s+(?P<duration>\d+)\s+(?P<client_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<result_code>\w+)/(?P<status>\d+)\s+(?P<bytes>\d+)\s+(?P<method>\w+)\s+'
    r'(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<hierarchy_code>\S+)/(?P<peer>\S+)\s+'
    r'(?P<content_type>\S+)$'
)

# Key=Value generic: user=alice ip=1.2.3.4 action=login status=failed msg="..."
_KV_TOKEN_RE = re.compile(r'([A-Za-z0-9_\-\.]+)=(".*?"|\S+)')
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

_WIN_COLS = {"Keywords", "Date and Time", "Source", "Event ID", "Task Category"}

# map Event ID -> action/status (tuỳ bạn mở rộng)
_WIN_EVENT_MAP = {
    4624: ("logon", "success"),
    4625: ("logon", "failed"),
    4672: ("privilege_assign", "granted"),
    4688: ("process_create", "success"),
    4798: ("group_enum", "success"),
    5379: ("credential_read", "success"),
    7045: ("service_install", "success"),
    1102: ("audit_log_cleared", "success"),
}

_key_re = re.compile(r"^\s*([^:\n]+):\s*(.+?)\s*$")

def _parse_windows_message(msg: str) -> dict:
    """
    Tách các block dạng:
      Subject:
          Security ID:   X
          Account Name:  Y
      User:
          ...
      Process Information:
          Process ID:    0x2520
          Process Name:  C:\\Windows\\System32\\mmc.exe
    -> trả về dict flatten: subject.account_name, process.process_name, ...
    """
    out = {}
    if not isinstance(msg, str) or not msg.strip():
        return out

    current = None
    for raw in msg.replace("\r", "").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        # Nhận diện tiêu đề block (kết thúc bằng ":")
        if not line.startswith("\t") and line.endswith(":"):
            current = line[:-1].strip().lower().replace(" ", "_")
            continue
        # Dòng khoá:giá trị
        m = _key_re.match(line)
        if m:
            k = m.group(1).strip().lower().replace(" ", "_")
            v = m.group(2).strip()
            key = f"{current}.{k}" if current else k
            out[key] = v
    return out

def _maybe_parse_windows_security_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Nhận diện CSV xuất từ Windows Event Viewer (Security):
    cột thường có: Keywords, Date and Time, Source, Event ID, Task Category, Message
    -> Chuẩn hoá sang schema chung.
    """
    if not _WIN_COLS.issubset(set(df_in.columns)):
        return df_in  # không phải dạng Windows Security CSV

    df = df_in.copy()

    # parse timestamp: Event Viewer xuất theo local time (ví dụ: 9/16/2025 4:49:46 PM)
    # -> chuẩn hoá UTC tz-aware
    df["timestamp"] = pd.to_datetime(df["Date and Time"], errors="coerce")
    # nếu muốn ép sang Asia/Ho_Chi_Minh rồi convert UTC:
    try:
        df["timestamp"] = df["timestamp"].dt.tz_localize("Asia/Ho_Chi_Minh").dt.tz_convert("UTC")
    except Exception:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    # cột cơ bản
    df["program"] = df["Source"].astype(str)
    df["event_id"] = pd.to_numeric(df["Event ID"], errors="coerce").astype("Int64")
    df["category"] = df["Task Category"].astype(str)
    df["keywords"] = df["Keywords"].astype(str)

    # tách các trường trong Message
    meta = df["Message"].fillna("").apply(_parse_windows_message)
    meta_df = pd.json_normalize(meta)

    # map action/status theo event_id
    act = []
    stat = []
    for eid in df["event_id"]:
        a, s = _WIN_EVENT_MAP.get(int(eid) if pd.notna(eid) else -1, (None, None))
        act.append(a)
        stat.append(s)
    df["action"] = act
    df["status"] = stat

    # pick các field hay dùng từ meta
    pick_cols = {
        "subject.account_name": "username",
        "subject.account_domain": "account_domain",
        "subject.security_id": "user_sid",
        "subject.logon_id": "logon_id",
        "process_information.process_name": "process_name",
        "process_information.process_id": "process_id",
        "network_information.source_network_address": "source_ip",
        "network_information.source_port": "src_port",
        "workstation_name": "workstation",
    }

    for k, newk in pick_cols.items():
        if k in meta_df.columns:
            df[newk] = meta_df[k]
        else:
            df[newk] = None

    # host/computer (nếu CSV có cột "Computer" thì dùng, còn không để None)
    df["host"] = df_in["Computer"] if "Computer" in df_in.columns else None

    # message giữ nguyên để AI/hiển thị
    df["message"] = df_in["Message"].astype(str)

    # đảm bảo đủ các cột schema chung khác (nếu cần)
    for want in ["source_ip", "username", "action", "status", "message"]:
        if want not in df.columns:
            df[want] = None

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df[[
        "timestamp","host","program","event_id","category","keywords",
        "username","account_domain","user_sid","logon_id",
        "process_name","process_id","workstation","source_ip","src_port",
        "action","status","message"
    ]]

# DNS log (named) - syslog format with DNS query info
_DNS_QUERY_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'named\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# Windows Event Log (WinEvent) format - ISO date + syslog-like
_WINEVENT_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'WinEvent:\s+(?P<message>.*)$'
)

# DNS log (named) - syslog format with DNS query info
_DNS_QUERY_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'named\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# coi một dòng là "bắt đầu bản ghi mới" nếu khớp các pattern timestamp/k=v
_START_PATTERNS = (
    _SYSLOG_RE,
    _OPENSSH_RE,
    _LINUX_RE,
    _APACHE_ACCESS_RE,
    _SURICATA_RE,
    _ZEEK_DNS_RE,
    _FIREWALL_RE,
    _DHCP_RE,
    _DNS_RE,
    _SQUID_RE,
    _SYSLOG_ISO_RE,
    _CONFIG_CHANGE_RE,
    _EDR_NET_RE,
    _NETFLOW_RE,
    _MODSEC_RE,
    _IDS_ALERT_SIMPLE_RE,
    _VPCFLOW_RE,
    _WINEVENT_RE,
    re.compile(r"^\d{4}-\d{2}-\d{2}[ T]"),  # 2025-09-07 12:34:56
    re.compile(r"^\d{2}-[A-Za-z]{3}-\d{4}"),  # 27-Sep-2025
    re.compile(r"^\d{2}/\d{2}/\d{4}"),      # 09/27/2025
    re.compile(r"^\d+\.\d{3}"),             # 1640995201.123 (Squid timestamp)
    re.compile(r"^\w+=.+"),                 # key=value
)
def _looks_like_start(ln: str) -> bool:
   return any(p.match(ln) for p in _START_PATTERNS)

def _merge_multiline(lines):
    merged = []
    buf = None
    for ln in lines:
        if buf is None:
            buf = ln
            continue
        if _looks_like_start(ln) and not ln.startswith((" ", "\t")):
            merged.append(buf)
            buf = ln
        else:
            buf += "\n" + ln
    if buf is not None:
        merged.append(buf)
    return merged

def _as_text(file_obj) -> str:
    # 1) Nếu đã là chuỗi
    if isinstance(file_obj, str):
        return file_obj

    # 2) Lấy bytes từ nhiều kiểu đầu vào khác nhau
    data = None
    if hasattr(file_obj, "read"):          # FileStorage / BytesIO / file-like
        try:
            file_obj.seek(0)
        except Exception:
            pass
        data = file_obj.read()
    elif isinstance(file_obj, (bytes, bytearray)):
        data = bytes(file_obj)
    elif hasattr(file_obj, "getvalue"):     # BytesIO không có read?
        data = file_obj.getvalue()
    else:
        raise TypeError("Unsupported file_obj type for text decode")

    # 3) Decode bytes → str với fallback encoding
    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)

    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")

def _extract_syslog_fields(message: str, program: str) -> dict:
    """Extract username, action, status from syslog message.
    IMPORTANT: Extract the ACTUAL user (who ran the action), NOT the target user.
    """
    result = {
        "username": None,
        "action": None,
        "status": None,
        "source_ip": None,
    }
    
    msg_lower = message.lower()
    
    # SSH patterns: Extract the user who logged in (after "for" keyword)
    if "sshd" in program.lower():
        # "Accepted password for huyle from 10.97.208.176"
        if "accepted" in msg_lower:
            result["action"] = "login"
            result["status"] = "success"
            user_match = re.search(r'for\s+(\S+)\s+from', message)
            if user_match:
                result["username"] = user_match.group(1)
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
        
        # "Failed password for minhtq from 10.60.88.220"
        elif "failed" in msg_lower and "password" in msg_lower:
            result["action"] = "login"
            result["status"] = "failed"
            user_match = re.search(r'for\s+(\S+)\s+from', message)
            if user_match:
                result["username"] = user_match.group(1)
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
    
    # Sudo patterns: Extract the ACTUAL user (who ran sudo), NOT "USER=root"
    elif "sudo" in program.lower():
        # Pattern 1: "huydev : TTY=pts/0 ; PWD=/home/huydev ; USER=root ; COMMAND=..."
        # Username is BEFORE the colon and whitespace
        if ":" in message and "TTY=" in message:
            # Extract username (before the colon)
            parts = message.split(":")
            if len(parts) > 0:
                actual_user = parts[0].strip()
                # Validate it looks like a username (not a system message)
                if actual_user and not any(pat in actual_user.lower() for pat in ("pam_unix", "error", "failed")):
                    result["username"] = actual_user
                    result["action"] = "sudo"
                    result["status"] = "success"
        
        # Pattern 2: "pam_unix(sudo:session): session opened for user root by quangdev(uid=1000)"
        # Extract username AFTER "by" keyword (the actual user who escalated)
        elif "session opened" in msg_lower:
            result["action"] = "sudo_session_open"
            result["status"] = "success"
            # Look for "by quangdev(uid=" pattern - extract quangdev
            user_match = re.search(r'by\s+(\w+)\(uid=', message)
            if user_match:
                result["username"] = user_match.group(1)
        
        # Pattern 3: "pam_unix(sudo:session): session closed for user root"
        # In this case we can't extract who closed it, so leave as None
        elif "session closed" in msg_lower:
            result["action"] = "sudo_session_close"
            result["status"] = "success"
    
    # Cron patterns: Extract the user whose cron job is running
    elif "cron" in program.lower():
        # Pattern: "CRON[23112]: (khanhng) CMD (/usr/local/bin/report.sh)"
        # Extract username inside parentheses
        if "cron" in msg_lower and "(" in message and ")" in message:
            result["action"] = "cron_execute"
            result["status"] = "success"
            user_match = re.search(r'\((\w+)\)\s+CMD', message)
            if user_match:
                result["username"] = user_match.group(1)
    
    # PostgreSQL patterns: Extract the executing user from multiple sources
    elif "postgres" in program.lower():
        # Try to extract user from SQL queries (e.g., user='linhfin')
        user_match = re.search(r"user\s*=\s*['\"]?(\w+)['\"]?", message, re.IGNORECASE)
        if user_match:
            result["username"] = user_match.group(1)
            result["action"] = "postgres_query"
            result["status"] = "success"
        
        # Also capture PID for potential matching with sudo logs
        # Format: postgres[38415]: ... → PID = 38415
        if "[" in program and "]" in program:
            pid_match = re.search(r"postgres\[(\d+)\]", program)
            if pid_match:
                # Store PID in username as fallback (will be resolved by PID matching later)
                if not user_match:
                    result["username"] = None  # Let resolver handle it
    
    return result

def _parse_syslog(lines, assume_year=None):
    rows = []
    year = assume_year or datetime.utcnow().year
    
    # Skip if this looks like DNS query logs (named daemon)
    head = [ln for ln in lines[:30] if ln.strip()]
    dns_hits = sum(1 for ln in head if _DNS_QUERY_RE.match(ln))
    if dns_hits >= max(3, len(head)//4):
        # This is DNS query log, not generic syslog - return empty so next handler picks it up
        return pd.DataFrame(columns=["timestamp", "message"])
    
    for ln in lines:
        m = _SYSLOG_RE.match(ln)
        if not m:
            rows.append({
                "timestamp": pd.NaT,
                "host": None, "program": None, "message": ln
            })
            continue
        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
        
        program = m["program"].strip()
        message = m["message"]
        
        # Extract syslog-specific fields
        fields = _extract_syslog_fields(message, program)
        
        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": program,
            "username": fields.get("username"),
            "source_ip": fields.get("source_ip"),
            "action": fields.get("action"),
            "status": fields.get("status"),
            "message": message
        })
    df = pd.DataFrame(rows)
    return df

def _parse_syslog_iso(lines):
    rows = []
    for ln in lines:
        m = _SYSLOG_ISO_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts_str = f"{m['date']} {m['time']}"
        ts = pd.to_datetime(ts_str, utc=True, errors="coerce")
        program = m["program"].strip()
        message = m["message"]
        rec = {
            "timestamp": ts,
            "host": m["host"],
            "program": program,
            "message": message
        }
        # If sshd, extract fields like OpenSSH parser
        if program.startswith("sshd"):
            ip_match = _IP_RE.search(message)
            if ip_match:
                rec["source_ip"] = ip_match.group(0)
            if "Accepted" in message:
                rec["action"] = "login"
                rec["status"] = "success"
                user_match = re.search(r'for (?:invalid user )?(\S+) from', message)
                if user_match:
                    rec["username"] = user_match.group(1)
            elif "Failed password" in message or "Failed" in message:
                rec["action"] = "login"
                rec["status"] = "failed"
                user_match = re.search(r'for (?:invalid user )?(\S+) from', message)
                if user_match:
                    rec["username"] = user_match.group(1)
        rows.append(rec)
    return pd.DataFrame(rows)

def _parse_openssh(lines, assume_year=None):
    """Parse OpenSSH log format."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _OPENSSH_RE.match(ln)
        if not m:
            # Fallback: parse as generic syslog and try common auth patterns (TACACS/RADIUS/PAM)
            ms = _SYSLOG_RE.match(ln)
            if not ms:
                rows.append({"timestamp": pd.NaT, "message": ln})
                continue
            ts_str = f"{year} {ms['mon']} {int(ms['day']):02d} {ms['time']}"
            ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
            message = ms["message"]
            program = ms["program"].strip()
            source_ip = None
            username = None
            action = None
            status = None
            ip_match = _IP_RE.search(message)
            if ip_match:
                source_ip = ip_match.group(0)
            # Common auth variants
            um = re.search(r"Accepted password for (\S+) from", message)
            if um:
                username = um.group(1)
                action = "login"
                status = "success"
            else:
                um = re.search(r"Failed password for (\S+) from", message)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "failed"
            if action is None:
                um = re.search(r"PAM authentication failure for (\S+) from", message, re.IGNORECASE)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "failed"
            if action is None:
                um = re.search(r"RADIUS Access-Accept for (\S+) from", message, re.IGNORECASE)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "success"
            if action is None:
                um = re.search(r"RADIUS Access-Reject for (\S+) from", message, re.IGNORECASE)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "failed"
            if action is None:
                um = re.search(r"TACACS\+ authentication OK for (\S+) from", message, re.IGNORECASE)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "success"
            if action is None:
                um = re.search(r"TACACS\+ authentication FAIL for (\S+) from", message, re.IGNORECASE)
                if um:
                    username = um.group(1)
                    action = "login"
                    status = "failed"
            rows.append({
                "timestamp": ts,
                "host": ms["host"],
                "program": program,
                "source_ip": source_ip,
                "username": username,
                "action": action,
                "status": status,
                "message": message
            })
            continue

        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)

        # Extract IP and user from message
        source_ip = None
        username = None
        action = None
        status = None
        
        msg = m["message"]
        ip_match = _IP_RE.search(msg)
        if ip_match:
            source_ip = ip_match.group(0)
        
        # Common SSH actions
        if "Accepted" in msg:
            action = "login"
            status = "success"
            user_match = re.search(r'for (\S+) from', msg)
            if user_match:
                username = user_match.group(1)
        elif "Failed password" in msg:
            action = "login"
            status = "failed"
            user_match = re.search(r'for (\S+) from', msg)
            if user_match:
                username = user_match.group(1)
        elif "Disconnected from" in msg:
            action = "disconnect"
            status = "success"
        elif "Connection closed" in msg:
            action = "disconnect"
            status = "success"

        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": "sshd",
            "pid": m["pid"],
            "source_ip": source_ip,
            "username": username,
            "action": action,
            "status": status,
            "message": msg
        })
    return pd.DataFrame(rows)

def _parse_linux_network(lines, assume_year=None):
    """Parse Linux network-related logs."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _LINUX_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)

        # Extract network info from message
        source_ip = None
        action = None
        status = None
        
        msg = m["message"]
        ip_match = _IP_RE.search(msg)
        if ip_match:
            source_ip = ip_match.group(0)
        
        # Common network actions
        if "link up" in msg.lower():
            action = "interface_up"
            status = "success"
        elif "link down" in msg.lower():
            action = "interface_down"
            status = "success"
        elif "dhcp" in msg.lower():
            action = "dhcp"
            status = "info"

        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": m["program"],
            "source_ip": source_ip,
            "action": action,
            "status": status,
            "message": msg
        })
    return pd.DataFrame(rows)

def _parse_firewall(lines, assume_year=None):
    """Parse firewall logs - both modern key-value format and legacy iptables."""
    rows = []
    year = assume_year or datetime.utcnow().year
    
    for ln in lines:
        # Try ISO format firewall logs first (with T separator)
        m_iso = _FIREWALL_ISO_RE.match(ln)
        if m_iso:
            ts_str = f"{m_iso['date']} {m_iso['time']}"
            ts = pd.to_datetime(ts_str, format="%Y-%m-%d %H:%M:%S", errors="coerce", utc=True)
            
            msg = m_iso["message"]
            
            # Extract SRC and DST IPs from iptables message
            source_ip = None
            dest_ip = None
            src_port = None
            dest_port = None
            action = None
            status = None
            protocol = None
            
            src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', msg)
            if src_match:
                source_ip = src_match.group(1)
            
            dst_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', msg)
            if dst_match:
                dest_ip = dst_match.group(1)
            
            spt_match = re.search(r'SPT=(\d+)', msg)
            if spt_match:
                src_port = spt_match.group(1)
            
            dpt_match = re.search(r'DPT=(\d+)', msg)
            if dpt_match:
                dest_port = dpt_match.group(1)
            
            proto_match = re.search(r'PROTO=(\w+)', msg)
            if proto_match:
                protocol = proto_match.group(1)
            
            if "ACCEPT" in msg:
                action = "accept"
                status = "success"
            elif "DROP" in msg:
                action = "drop"
                status = "blocked"
            elif "REJECT" in msg:
                action = "reject"
                status = "blocked"
            
            rows.append({
                "timestamp": ts,
                "host": m_iso["host"],
                "program": "firewall",
                "source_ip": source_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "action": action,
                "status": status,
                "message": msg
            })
            continue
        
        # Try key-value format (modern firewall appliances)
        m_kv = _FIREWALL_KV_RE.match(ln)
        if m_kv:
            ts_str = f"{year} {m_kv['mon']} {int(m_kv['day']):02d} {m_kv['time']}"
            ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
            
            msg = m_kv["message"]
            
            # Extract key-value pairs from message
            kv_pairs = {}
            for k, v in _KV_TOKEN_RE.findall(msg):
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                kv_pairs[k.lower()] = v
            
            action = kv_pairs.get("action", "").lower()
            status = "success" if action in ("allow", "accept") else "blocked" if action in ("deny", "drop", "reject") else None
            
            rows.append({
                "timestamp": ts,
                "host": m_kv["host"],
                "program": "firewall",
                "username": kv_pairs.get("user"),
                "device": kv_pairs.get("device"),
                "source_ip": kv_pairs.get("src"),
                "src_port": kv_pairs.get("sport"),
                "dest_ip": kv_pairs.get("dst"),
                "dest_port": kv_pairs.get("dport"),
                "dst_host": kv_pairs.get("dst_host"),
                "protocol": kv_pairs.get("proto"),
                "bytes_sent": kv_pairs.get("bytes"),
                "rule": kv_pairs.get("rule"),
                "action": action,
                "status": status,
                "severity": kv_pairs.get("severity", "INFO"),
                "message": msg
            })
            continue
        
        # Try legacy iptables format
        m_iptables = _FIREWALL_IPTABLES_RE.match(ln)
        if m_iptables:
            ts_str = f"{year} {m_iptables['mon']} {int(m_iptables['day']):02d} {m_iptables['time']}"
            ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
            
            msg = m_iptables["message"]
            
            # Extract SRC and DST IPs from iptables message
            source_ip = None
            dest_ip = None
            action = None
            status = None
            
            src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', msg)
            if src_match:
                source_ip = src_match.group(1)
            
            dst_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', msg)
            if dst_match:
                dest_ip = dst_match.group(1)
            
            if "ACCEPT" in msg:
                action = "accept"
                status = "success"
            elif "DROP" in msg:
                action = "drop"
                status = "blocked"
            elif "REJECT" in msg:
                action = "reject"
                status = "blocked"
            
            rows.append({
                "timestamp": ts,
                "host": m_iptables["host"],
                "program": "firewall",
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "action": action,
                "status": status,
                "message": msg
            })
            continue
        
        # Fallback for unparseable lines
        rows.append({"timestamp": pd.NaT, "message": ln})
    
    return pd.DataFrame(rows)

def _parse_dhcp(lines, assume_year=None):
    """Parse DHCP logs and extract username, device, IP from message."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _DHCP_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)

        msg = m["message"]
        action = None
        status = None
        username = None
        device = None
        mac_address = None
        ip_address = None
        interface = None
        
        # Parse DHCP action
        if "DHCPDISCOVER" in msg:
            action = "discover"
            status = "info"
        elif "DHCPOFFER" in msg:
            action = "offer"
            status = "success"
        elif "DHCPREQUEST" in msg:
            action = "request"
            status = "info"
        elif "DHCPACK" in msg:
            action = "ack"
            status = "success"
        elif "DHCPRELEASE" in msg:
            action = "release"
            status = "success"
        elif "DHCPINFORM" in msg:
            action = "inform"
            status = "info"
        
        # Extract IP address (all forms: "on 10.x.x.x" or "for 10.x.x.x" or "from 10.x.x.x")
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', msg)
        if ip_match:
            ip_address = ip_match.group(1)
        
        # Extract MAC address (xx:xx:xx:xx:xx:xx format)
        mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', msg)
        if mac_match:
            mac_address = mac_match.group(1)
        
        # Extract interface (via eth0, via vlan10, etc.)
        interface_match = re.search(r'via\s+(\S+)(?:\s|:|$)', msg)
        if interface_match:
            interface = interface_match.group(1)
        
        # Extract device name from parentheses: (khanhng-dev3) or (khanhng-dev4)
        device_match = re.search(r'\(([^)]+)\)', msg)
        if device_match:
            device_candidate = device_match.group(1)
            # Validate it looks like a device name (contains "dev" or common patterns)
            if "dev" in device_candidate.lower() or "-" in device_candidate:
                device = device_candidate
        
        # Extract username from "user=username" pattern
        user_match = re.search(r'user=(\S+?)(?:\s|$|:)', msg)
        if user_match:
            username = user_match.group(1)

        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": "dhcpd",
            "username": username,
            "device": device,
            "mac_address": mac_address,
            "ip_address": ip_address,
            "interface": interface,
            "action": action,
            "status": status,
            "message": msg
        })
    return pd.DataFrame(rows)

def _parse_apache_access(lines):
    """Parse Apache Access Log format with extended fields (vhost, attack)."""
    rows = []
    for ln in lines:
        m = _APACHE_ACCESS_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        # Parse syslog timestamp: "Oct 27 12:45:00" + time_local for full timestamp
        year = datetime.now().year  # Use current year as fallback
        ts_str = f"{m['mon']} {m['day']} {m['time']} {year}"
        ts = pd.to_datetime(ts_str, format="%b %d %H:%M:%S %Y", errors="coerce")
        if pd.isna(ts):
            # Try parsing time_local as fallback
            ts = pd.to_datetime(m["time_local"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce")
        if pd.isna(ts):
            ts = pd.to_datetime(m["time_local"], errors="coerce")
        
        # Parse request: "GET /path?q=1 HTTP/1.1"
        request = m["request"] or ""
        method, path, proto = None, None, None
        if request:
            parts = request.split()
            if len(parts) >= 1: method = parts[0]
            if len(parts) >= 2: path = parts[1]
            if len(parts) >= 3: proto = parts[2]

        # Extract Device and Dept from User-Agent
        user_agent = m.groupdict().get("http_user_agent") or ""
        device = None
        dept = None
        attack = None
        
        if "Device/" in user_agent:
            try:
                device_part = user_agent.split("Device/")[1].split()[0]
                device = device_part
            except Exception:
                pass
        
        if "Dept/" in user_agent:
            try:
                dept_part = user_agent.split("Dept/")[1].split()[0]
                dept = dept_part
            except Exception:
                pass
        
        if "Attack/" in user_agent:
            try:
                attack_part = user_agent.split("Attack/")[1].split()[0]
                attack = attack_part
            except Exception:
                pass
        
        # If attack not extracted from UA, try from vhost field
        if not attack:
            attack = m.groupdict().get("attack")

        # Determine action based on status code
        status_code = int(m["status"]) if m["status"].isdigit() else 0
        if 200 <= status_code < 300:
            action = "access"
            status = "success"
        elif 300 <= status_code < 400:
            action = "redirect"
            status = "success"
        elif 400 <= status_code < 500:
            action = "client_error"
            status = "failed"
        elif 500 <= status_code < 600:
            action = "server_error"
            status = "failed"
        else:
            action = "access"
            status = "unknown"

        rows.append({
            "timestamp": ts,
            "host": m["hostname"],
            "source_ip": m["remote_addr"],
            "username": m["username"],
            "method": method,
            "path": path,
            "protocol": proto,
            "http_status": m["status"],
            "bytes_sent": m["body_bytes_sent"],
            "referrer": m.groupdict().get("http_referer"),
            "user_agent": user_agent,
            "vhost": m.groupdict().get("vhost"),
            "device": device,
            "dept": dept,
            "attack_type": attack,
            "action": action,
            "status": status,
            "program": "apache",
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_suricata(lines):
    """Parse Suricata IDS alerts."""
    rows = []
    for ln in lines:
        m = _SURICATA_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        # Parse timestamp: "09/27/2025-15:00:01.255000"
        ts_str = f"{m['date']} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%m/%d/%Y %H:%M:%S.%f", errors="coerce", utc=True)

        # Determine action based on classification
        classification = m["classification"].lower()
        if "attempted" in classification or "attack" in classification:
            action = "attack"
            status = "blocked"
        elif "policy" in classification:
            action = "policy_violation"
            status = "alert"
        elif "malware" in classification:
            action = "malware"
            status = "blocked"
        else:
            action = "alert"
            status = "info"

        rows.append({
            "timestamp": ts,
            "program": "suricata",
            "source_ip": m["src_ip"],
            "dest_ip": m["dst_ip"],
            "src_port": int(m["src_port"]),
            "dest_port": int(m["dst_port"]),
            "protocol": m["proto"],
            "action": action,
            "status": status,
            "classification": m["classification"],
            "priority": int(m["priority"]),
            "sid": m["sid"],
            "message": m["msg"].strip(),
            "full_message": ln
        })
    return pd.DataFrame(rows)

def _parse_zeek_dns(lines):
    """Parse Zeek DNS logs."""
    rows = []
    for ln in lines:
        m = _ZEEK_DNS_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        # Parse timestamp: "27-Sep-2025 15:00:01.255"
        ts_str = f"{m['date']} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%d-%b-%Y %H:%M:%S.%f", errors="coerce", utc=True)

        # Determine action and status
        flags = m["flags"]
        if "+E" in flags:
            action = "query_error"
            status = "failed"
        else:
            action = "query"
            status = "success"

        rows.append({
            "timestamp": ts,
            "program": "zeek_dns",
            "source_ip": m["src_ip"],
            "src_port": int(m["src_port"]),
            "dest_ip": m["server"],
            "action": action,
            "status": status,
            "domain": m["domain"],
            "query_type": m["qtype"],
            "flags": flags,
            "client_id": m["client_id"],
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_squid(lines):
    """Parse Squid proxy logs."""
    rows = []
    for ln in lines:
        m = _SQUID_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        # Parse timestamp: Unix timestamp with milliseconds
        ts = pd.to_datetime(float(m["timestamp"]), unit="s", utc=True)

        # Parse URL to extract domain
        url = m["url"]
        domain = None
        if url.startswith("http://") or url.startswith("https://"):
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
            except Exception:
                pass

        # Determine action based on result code
        result_code = m["result_code"]
        if "MISS" in result_code:
            action = "cache_miss"
            status = "success"
        elif "HIT" in result_code:
            action = "cache_hit"
            status = "success"
        elif "DENIED" in result_code:
            action = "access_denied"
            status = "blocked"
        else:
            action = "proxy_access"
            status = "success"

        rows.append({
            "timestamp": ts,
            "program": "squid",
            "source_ip": m["client_ip"],
            "dest_ip": m["peer"] if m["peer"] != "-" else None,
            "action": action,
            "status": status,
            "method": m["method"],
            "url": url,
            "domain": domain,
            "http_status": m["status"],
            "bytes_sent": int(m["bytes"]),
            "duration": int(m["duration"]),
            "user": m["user"] if m["user"] != "-" else None,
            "content_type": m["content_type"],
            "hierarchy_code": m["hierarchy_code"],
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_dns(lines, assume_year=None):
    """Parse DNS logs."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _DNS_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)

        msg = m["message"]
        source_ip = None
        action = None
        status = None
        
        # Extract client IP
        client_match = re.search(r'client (\d+\.\d+\.\d+\.\d+)', msg)
        if client_match:
            source_ip = client_match.group(1)
        
        if "query:" in msg:
            action = "query"
            status = "info"
        elif "cached" in msg:
            action = "cached"
            status = "success"

        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": "named",
            "pid": m["pid"],
            "source_ip": source_ip,
            "action": action,
            "status": status,
            "message": msg
        })
    return pd.DataFrame(rows)

def _parse_keyvalue(lines):
    rows = []
    for ln in lines:
        row = {"message": ln}
        for k, v in _KV_TOKEN_RE.findall(ln):
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            row[k.lower()] = v
        # IP fallback
        if "ip" not in row and "source_ip" not in row:
            ip = _IP_RE.search(ln)
            if ip: row["source_ip"] = ip.group(0)
        # special mapping for firewall-like kv lines
        # example: 2025-... firewall01 action=ALLOW proto=UDP src=192.168.1.1:12345 dst=1.2.3.4:53 bytes=... rule=...
        if "action" in row and row.get("action"):
            row["status"] = "success" if str(row["action"]).upper() in ("ALLOW","ESTABLISHED","ACCEPT") else row.get("status")
        # split src/dst host:port
        for side in ("src","dst"):
            val = row.get(side)
            if isinstance(val, str) and ":" in val:
                host, port = val.split(":", 1)
                if side == "src":
                    row["source_ip"] = host
                    row["src_port"] = port
                else:
                    row["dest_ip"] = host
                    row["dest_port"] = port
        # timestamp parse for ISO at start
        if "timestamp" not in row:
            # try detect leading ISO timestamp
            try:
                head = ln.split()[0]
                ts = pd.to_datetime(head, errors="coerce", utc=True)
                if pd.notna(ts):
                    row["timestamp"] = ts
            except Exception:
                pass
        rows.append(row)
    return pd.DataFrame(rows)

def _parse_config_change(lines):
    rows = []
    for ln in lines:
        m = _CONFIG_CHANGE_RE.match(ln)
        if not m:
            # Fallback: try generic ISO syslog to at least keep timestamp/host/program/message
            ms = _SYSLOG_ISO_RE.match(ln)
            if ms:
                ts = pd.to_datetime(f"{ms['date']} {ms['time']}", utc=True, errors="coerce")
                rows.append({
                    "timestamp": ts,
                    "host": ms["host"],
                    "program": ms["program"],
                    "message": ms["message"]
                })
            else:
                rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        rows.append({
            "timestamp": ts,
            "program": "configd",
            "action": m["action"].replace(" ", "_"),
            "status": "success",
            "configuration": m["configuration"],
            "actor": m["actor"],
            "change_id": int(m["change_id"]),
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_edr_network(lines):
    rows = []
    for ln in lines:
        m = _EDR_NET_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        rows.append({
            "timestamp": ts,
            "program": "sysmon",
            "process": m["image"],
            "dest_ip": m["dst_ip"],
            "dest_port": int(m["dst_port"]),
            "protocol": m["proto"].upper(),
            "action": "connect",
            "status": "success",
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_netflow(lines):
    rows = []
    for ln in lines:
        m = _NETFLOW_RE.match(ln)
        if not m:
            # Fallback: keep row with parsed timestamp from leading ISO datetime
            try:
                parts = ln.split()
                ts = pd.to_datetime(" ".join(parts[:2]), utc=True, errors="coerce")
            except Exception:
                ts = pd.NaT
            rows.append({"timestamp": ts, "program": "netflow", "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        rows.append({
            "timestamp": ts,
            "program": "netflow",
            "source_ip": m["src_ip"],
            "src_port": int(m["src_port"]),
            "dest_ip": m["dst_ip"],
            "dest_port": int(m["dst_port"]),
            "protocol": m["proto"].upper(),
            "bytes": int(m["bytes"]),
            "packets": int(m["pkts"]),
            "action": m["action"].lower(),
            "status": "success" if m["action"].lower() in ("permit","allow","accept") else "blocked",
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_modsecurity(lines):
    rows = []
    for ln in lines:
        m = _MODSEC_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        rows.append({
            "timestamp": ts,
            "program": "modsecurity",
            "client_ip": m["client"],
            "uri": m["uri"],
            "rule_id": int(m["rule_id"]) if m.groupdict().get("rule_id") else None,
            "action": "waf_alert",
            "status": "alert",
            "message": m["msg"],
            "full_message": ln
        })
    return pd.DataFrame(rows)

def _parse_ids_alert_simple(lines):
    rows = []
    for ln in lines:
        m = _IDS_ALERT_SIMPLE_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        rows.append({
            "timestamp": ts,
            "program": "suricata",
            "source_ip": m["src_ip"],
            "dest_ip": m["dst_ip"],
            "protocol": m["proto"].upper(),
            "action": "alert",
            "status": "info",
            "signature": m["signature"],
            "severity": m["severity"],
            "message": ln
        })
    return pd.DataFrame(rows)

def _parse_vpcflow(lines):
    rows = []
    for ln in lines:
        m = _VPCFLOW_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        ts = pd.to_datetime(f"{m['date']} {m['time']}", utc=True, errors="coerce")
        act = m["action"].upper()
        rows.append({
            "timestamp": ts,
            "program": "vpcflow",
            "source_ip": m["src_ip"],
            "dest_ip": m["dst_ip"],
            "dest_port": int(m["dst_port"]),
            "protocol": m["proto"],
            "action": act.lower(),
            "status": "success" if act == "ACCEPT" else "blocked",
            "bytes": int(m["bytes"]),
            "message": ln
        })
    return pd.DataFrame(rows)

def _maybe_parse_zeek_dns_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Zeek DNS CSV format:
      log_index,index,message,source_ip,timestamp,username,action,status
    """
    required = {"message", "source_ip", "timestamp"}
    if not required.issubset(set(df_in.columns)):
        return df_in

    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Extract domain and query type from message
    df["domain"] = None
    df["query_type"] = None
    df["action"] = "query"
    df["status"] = "success"
    
    for idx, row in df.iterrows():
        msg = str(row.get("message", ""))
        if "query:" in msg:
            # Extract domain: "query: telemetry.example.com IN CNAME"
            domain_match = re.search(r'query:\s+(\S+)\s+IN\s+(\w+)', msg)
            if domain_match:
                df.at[idx, "domain"] = domain_match.group(1)
                df.at[idx, "query_type"] = domain_match.group(2)
            
            # Check for errors
            if "+E" in msg:
                df.at[idx, "action"] = "query_error"
                df.at[idx, "status"] = "failed"
    
    # Set program
    df["program"] = "zeek_dns"
    
    # Ensure required columns exist
    for want in ["host", "username", "action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "source_ip", "username", 
        "action", "status", "domain", "query_type", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_apache_extended_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Extended Apache CSV format (with message column):
      timestamp,host,process,pid,severity,facility,message,department
    Extract Apache fields from message column (combined log format).
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # This parser specifically handles Apache logs - must have 'httpd' process
    processes = df_in["process"].dropna().astype(str).unique()
    if not any(str(p).lower() == "httpd" for p in processes):
        return df_in  # Not an Apache log
    
    # Quick validation: first message should look like Apache combined log format
    # Should contain IP, username, and HTTP request pattern
    first_msg = str(df_in.iloc[0].get("message", ""))
    if not ("HTTP/" in first_msg and "[" in first_msg and "]" in first_msg):
        return df_in  # Doesn't look like Apache format
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Parse Apache combined log format from message column
    # Format: 10.29.75.171 - quangdev [27/Oct/2025:09:15:00 +0000] "GET /artifacts/pkg-1.2.3.tgz HTTP/1.1" 206 101085 "-" "Mozilla/5.0 ... Device/quangdev-dev2 Dept/engineering" vhost=ci-runner01.company.local
    
    def parse_apache_message(msg: str) -> dict:
        result = {
            "source_ip": None,
            "username": None,
            "method": None,
            "path": None,
            "protocol": None,
            "http_status": None,
            "bytes_sent": None,
            "referrer": None,
            "user_agent": None,
            "vhost": None,
            "device": None,
            "dept": None,
            "action": None,
            "status": None
        }
        
        try:
            msg_str = str(msg)
            
            # Extract IP - username - timestamp
            import re
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+(\S+)\s+', msg_str)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
                user = ip_match.group(2)
                if user != "-":
                    result["username"] = user
            
            # Extract request: "GET /path HTTP/1.1"
            req_match = re.search(r'"([A-Z]+)\s+(\S+)\s+(HTTP/[\d.]+)"', msg_str)
            if req_match:
                result["method"] = req_match.group(1)
                result["path"] = req_match.group(2)
                result["protocol"] = req_match.group(3)
            
            # Extract status code and bytes
            status_match = re.search(r'"\s+(\d{3})\s+(\d+|-)\s+"', msg_str)
            if status_match:
                result["http_status"] = int(status_match.group(1))
                bytes_val = status_match.group(2)
                if bytes_val != "-":
                    result["bytes_sent"] = int(bytes_val)
            
            # Extract referrer (first quoted string after bytes)
            ref_match = re.search(r'"\s+\d{3}\s+[\d|-]+\s+"([^"]*)"', msg_str)
            if ref_match:
                ref = ref_match.group(1)
                if ref != "-":
                    result["referrer"] = ref
            
            # Extract user-agent (second quoted string)
            ua_match = re.search(r'"([^"]*)"(?:\s+vhost=|\s*$)', msg_str)
            if ua_match:
                result["user_agent"] = ua_match.group(1)
                
                # Extract Device and Dept from user-agent
                if "Device/" in result["user_agent"]:
                    try:
                        device_part = result["user_agent"].split("Device/")[1].split()[0]
                        result["device"] = device_part
                    except Exception:
                        pass
                
                if "Dept/" in result["user_agent"]:
                    try:
                        dept_part = result["user_agent"].split("Dept/")[1].split()[0]
                        result["dept"] = dept_part
                    except Exception:
                        pass
            
            # Extract vhost
            vhost_match = re.search(r'vhost=(\S+)(?:\s|$)', msg_str)
            if vhost_match:
                result["vhost"] = vhost_match.group(1)
            
            # Determine action and status from HTTP status code
            if result["http_status"]:
                status_code = result["http_status"]
                if 200 <= status_code < 300:
                    result["action"] = "access"
                    result["status"] = "success"
                elif 300 <= status_code < 400:
                    result["action"] = "redirect"
                    result["status"] = "success"
                elif 400 <= status_code < 500:
                    result["action"] = "client_error"
                    result["status"] = "failed"
                elif 500 <= status_code < 600:
                    result["action"] = "server_error"
                    result["status"] = "failed"
        except Exception:
            pass
        
        return result
    
    # Parse message column
    parsed_list = df["message"].apply(parse_apache_message)
    
    df["program"] = "apache"
    df["source_ip"] = parsed_list.apply(lambda x: x.get("source_ip"))
    df["username"] = parsed_list.apply(lambda x: x.get("username"))
    df["method"] = parsed_list.apply(lambda x: x.get("method"))
    df["path"] = parsed_list.apply(lambda x: x.get("path"))
    df["protocol"] = parsed_list.apply(lambda x: x.get("protocol"))
    df["http_status"] = parsed_list.apply(lambda x: x.get("http_status"))
    df["bytes_sent"] = parsed_list.apply(lambda x: x.get("bytes_sent"))
    df["referrer"] = parsed_list.apply(lambda x: x.get("referrer"))
    df["user_agent"] = parsed_list.apply(lambda x: x.get("user_agent"))
    df["vhost"] = parsed_list.apply(lambda x: x.get("vhost"))
    df["device"] = parsed_list.apply(lambda x: x.get("device"))
    df["dept"] = parsed_list.apply(lambda x: x.get("dept"))
    df["action"] = parsed_list.apply(lambda x: x.get("action"))
    df["status"] = parsed_list.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "severity", "username", "source_ip",
        "method", "path", "protocol", "http_status", "bytes_sent", "referrer",
        "user_agent", "vhost", "device", "dept", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_apache_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Apache Access Log CSV format (both classic and enhanced):
      Classic: timestamp,remote_addr,method,path,protocol,http_status,bytes_sent,referrer,user_agent
      Enhanced: adds host,username,vhost,device,dept,attack_type
    
    NOTE: This parser is for the classic format. Extended format with 'message' column
    is handled by _maybe_parse_apache_extended_csv
    """
    required = {"timestamp", "remote_addr"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # Skip if this is the extended format (message column + httpd process)
    if "message" in df_in.columns and "process" in df_in.columns:
        processes = df_in["process"].dropna().astype(str).unique()
        if "httpd" in [str(p).lower() for p in processes]:
            return df_in  # This is extended format, skip to let _maybe_parse_apache_extended_csv handle it

    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Map columns
    df["source_ip"] = df["remote_addr"]
    df["program"] = "apache"
    
    # Ensure username column exists
    if "username" not in df.columns:
        df["username"] = df.get("user", None)
    if "username" not in df.columns:
        df["username"] = "-"
    
    # Extract Device, Dept, Attack from user_agent if not already present
    if "user_agent" in df.columns and "device" not in df.columns:
        df["device"] = df["user_agent"].apply(
            lambda x: x.split("Device/")[1].split()[0] if isinstance(x, str) and "Device/" in x else None
        )
    if "user_agent" in df.columns and "dept" not in df.columns:
        df["dept"] = df["user_agent"].apply(
            lambda x: x.split("Dept/")[1].split()[0] if isinstance(x, str) and "Dept/" in x else None
        )
    if "user_agent" in df.columns and "attack_type" not in df.columns:
        df["attack_type"] = df["user_agent"].apply(
            lambda x: x.split("Attack/")[1].split()[0] if isinstance(x, str) and "Attack/" in x else None
        )
    
    # Determine action based on status code
    if "http_status" in df.columns:
        df["action"] = df["http_status"].apply(lambda x: 
            "access" if 200 <= int(x) < 300 else
            "redirect" if 300 <= int(x) < 400 else
            "client_error" if 400 <= int(x) < 500 else
            "server_error" if 500 <= int(x) < 600 else
            "access"
        )
        df["status"] = df["http_status"].apply(lambda x:
            "success" if 200 <= int(x) < 400 else
            "failed" if 400 <= int(x) < 600 else
            "unknown"
        )
    else:
        df["action"] = "access"
        df["status"] = "success"
    
    # Ensure required columns exist
    for want in ["host", "username", "action", "status", "program"]:
        if want not in df.columns:
            df[want] = None if want != "program" else "apache"
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "source_ip", "username",
        "action", "status", "method", "path", "protocol", 
        "http_status", "bytes_sent", "referrer", "user_agent",
        "vhost", "device", "dept", "attack_type", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_suricata_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Suricata IDS CSV format:
      timestamp,src_ip,dst_ip,src_port,dst_port,protocol,classification,priority,sid,message
    """
    required = {"timestamp", "src_ip", "dst_ip"}
    if not required.issubset(set(df_in.columns)):
        return df_in

    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Map columns
    df["source_ip"] = df["src_ip"]
    df["dest_ip"] = df["dst_ip"]
    df["program"] = "suricata"
    
    # Determine action based on classification
    if "classification" in df.columns:
        df["action"] = df["classification"].str.lower().apply(lambda x:
            "attack" if "attempted" in x or "attack" in x else
            "policy_violation" if "policy" in x else
            "malware" if "malware" in x else
            "alert"
        )
        df["status"] = df["classification"].str.lower().apply(lambda x:
            "blocked" if "attempted" in x or "attack" in x or "malware" in x else
            "alert" if "policy" in x else
            "info"
        )
    else:
        df["action"] = "alert"
        df["status"] = "info"
    
    # Ensure required columns exist
    for want in ["host", "username", "action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "source_ip", "dest_ip", "username",
        "action", "status", "src_port", "dst_port", "protocol",
        "classification", "priority", "sid", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_squid_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Squid Proxy CSV format:
      timestamp,client_ip,method,url,http_status,bytes_sent,duration,user,content_type
    """
    required = {"timestamp", "client_ip"}
    if not required.issubset(set(df_in.columns)):
        return df_in

    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Map columns
    df["source_ip"] = df["client_ip"]
    df["program"] = "squid"
    
    # Extract domain from URL
    if "url" in df.columns:
        df["domain"] = df["url"].apply(lambda x: 
            urlparse(x).netloc if x and (x.startswith("http://") or x.startswith("https://")) else None
        )
    
    # Determine action based on result code or status
    if "result_code" in df.columns:
        df["action"] = df["result_code"].apply(lambda x:
            "cache_miss" if "MISS" in str(x) else
            "cache_hit" if "HIT" in str(x) else
            "access_denied" if "DENIED" in str(x) else
            "proxy_access"
        )
        df["status"] = df["result_code"].apply(lambda x:
            "success" if "MISS" in str(x) or "HIT" in str(x) else
            "blocked" if "DENIED" in str(x) else
            "success"
        )
    else:
        df["action"] = "proxy_access"
        df["status"] = "success"
    
    # Ensure required columns exist
    for want in ["host", "username", "action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "source_ip", "username",
        "action", "status", "method", "url", "domain", "http_status",
        "bytes_sent", "duration", "user", "content_type", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_openssh_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Nhận diện CSV OpenSSH dạng:
      LineId,Date,Day,Time,Component,Pid,Content,EventId,EventTemplate
      1,Dec,10,06:55:46,LabSZ,24200,reverse mapping ... ,E27,reverse mapping ...

    - Date: tên tháng viết tắt (Jan..Dec)
    - Day: ngày (số)
    - Time: HH:MM:SS
    - Component: thường là host/module
    - Content: thông điệp log
    - EventId: có thể có tiền tố chữ, ví dụ "E27" → trích số 27 nếu muốn số
    """
    required = {"LineId", "Date", "Day", "Time", "Component", "Content"}
    if not required.issubset(set(df_in.columns)):
        return df_in

    df = df_in.copy()
    year = datetime.utcnow().year

    # Ghép timestamp từ Date(mon abbrev) + Day + Time
    ts_list = []
    for mon, day, tim in zip(df["Date"], df["Day"], df["Time"]):
        try:
            ts_str = f"{year} {str(mon).strip()} {int(day):02d} {str(tim).strip()}"
            ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
        except Exception:
            ts = pd.NaT
        ts_list.append(ts)
    df["timestamp"] = ts_list

    # Chuẩn hoá cột và kiểu dữ liệu thường dùng
    df["program"] = df["Component"].astype(str)
    df["host"] = df.get("Component")
    df["pid"] = pd.to_numeric(df.get("Pid"), errors="coerce") if "Pid" in df.columns else None
    df["message"] = df["Content"].astype(str)

    # EventId: trích số nếu có, đồng thời giữ bản gốc (nếu cần)
    if "EventId" in df.columns:
        df["event_id_raw"] = df["EventId"].astype(str)
        df["event_id"] = (
            df["event_id_raw"].str.extract(r"(\d+)", expand=False).astype("Int64")
        )

    if "EventTemplate" in df.columns:
        df["event_template"] = df["EventTemplate"].astype(str)

    # Đảm bảo timezone UTC tz-aware
    try:
        if getattr(df["timestamp"].dt, "tz", None) is None:
            df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
        else:
            df["timestamp"] = df["timestamp"].dt.tz_convert("UTC")
    except Exception:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Điền các cột chuẩn khác nếu thiếu
    for want in ["source_ip", "username", "action", "status"]:
        if want not in df.columns:
            df[want] = None

    # Sắp xếp theo thời gian
    df = df.sort_values("timestamp").reset_index(drop=True)

    keep_cols = [
        "timestamp", "host", "program", "pid", "event_id", "event_id_raw", "event_template",
        "username", "source_ip", "action", "status", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_linux_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Nhận diện CSV dạng Linux syslog đã chuẩn hoá:
      LineId, Month, Date, Time, Level, Component, PID, Content, EventId, EventTemplate

    - Month: tên tháng viết tắt (Jan..Dec)
    - Date: ngày (số)
    - Time: HH:MM:SS
    - Level: host / level (vd: combo)
    - Component: module (vd: sshd(pam_unix))
    - PID: process id
    - Content: thông điệp log
    - EventId: có thể là "E27" → trích số 27 nếu muốn số
    - EventTemplate: mẫu log (có placeholder <*>)
    """
    required = {"Month", "Date", "Time", "Component", "Content"}
    if not required.issubset(set(df_in.columns)):
        return df_in

    df = df_in.copy()
    year = datetime.utcnow().year

    # Ghép timestamp từ Month + Date + Time
    ts_list = []
    for mon, day, tim in zip(df["Month"], df["Date"], df["Time"]):
        try:
            ts_str = f"{year} {str(mon).strip()} {int(day):02d} {str(tim).strip()}"
            ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)
        except Exception:
            ts = pd.NaT
        ts_list.append(ts)
    df["timestamp"] = ts_list

    # Chuẩn hoá cột và kiểu dữ liệu
    df["host"] = df["Level"].astype(str) if "Level" in df.columns else None
    df["program"] = df["Component"].astype(str)
    df["pid"] = pd.to_numeric(df.get("PID"), errors="coerce") if "PID" in df.columns else None
    df["message"] = df["Content"].astype(str)

    # EventId: trích số nếu có
    if "EventId" in df.columns:
        df["event_id_raw"] = df["EventId"].astype(str)
        df["event_id"] = (
            df["event_id_raw"].str.extract(r"(\d+)", expand=False).astype("Int64")
        )

    if "EventTemplate" in df.columns:
        df["event_template"] = df["EventTemplate"].astype(str)

    # Đảm bảo timezone UTC tz-aware
    try:
        if getattr(df["timestamp"].dt, "tz", None) is None:
            df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
        else:
            df["timestamp"] = df["timestamp"].dt.tz_convert("UTC")
    except Exception:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Điền các cột chuẩn khác nếu thiếu
    for want in ["source_ip", "username", "action", "status"]:
        if want not in df.columns:
            df[want] = None

    # Sắp xếp theo thời gian
    df = df.sort_values("timestamp").reset_index(drop=True)

    keep_cols = [
        "timestamp", "host", "program", "pid",
        "event_id", "event_id_raw", "event_template",
        "username", "source_ip", "action", "status",
        "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # chuẩn hoá tên cột cơ bản (ví dụ alias → chuẩn)
    cols = {c.lower(): c for c in df.columns}
    if "time" in cols and "timestamp" not in cols:
        df = df.rename(columns={cols["time"]: "timestamp"})
    if "msg" in cols and "message" not in cols:
        df = df.rename(columns={cols["msg"]: "message"})

    # parse timestamp
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=False)
    else:
        base = pd.Timestamp.now(tz="UTC").floor("s")
        df["timestamp"] = [base + pd.Timedelta(seconds=i) for i in range(len(df))]

    # ép timezone → UTC (tz-aware)
    try:
        # nếu chưa có tz: gán UTC; nếu có tz: convert → UTC
        if getattr(df["timestamp"].dt, "tz", None) is None:
            df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
        else:
            df["timestamp"] = df["timestamp"].dt.tz_convert("UTC")
    except Exception:
        # phòng hờ: coerce lại về UTC
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # một số cột hay dùng
    for want in ["source_ip", "username", "action", "status", "message"]:
        if want not in df.columns:
            df[want] = None

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df

# lọc theo khoảng thời gian ISO8601 =====
def _filter_by_time(df: pd.DataFrame, start_iso: str | None = None, end_iso: str | None = None) -> pd.DataFrame:
    if df.empty:
        return df
    out = df.dropna(subset=["timestamp"]).copy()
    if start_iso:
        s = pd.to_datetime(start_iso, utc=True, errors="coerce")
        if pd.notna(s):
            out = out[out["timestamp"] >= s]
    if end_iso:
        e = pd.to_datetime(end_iso, utc=True, errors="coerce")
        if pd.notna(e):
            out = out[out["timestamp"] < e]
    return out

def preprocess_any(file_obj, filename=None, start_iso=None, end_iso=None):
    name = (filename or "").lower()

    # --- structured: CSV / JSON / NDJSON ---
    if name.endswith(".csv") or name.endswith(".json") or name.endswith(".ndjson"):
        raw = file_obj.read()
        try:
            file_obj.seek(0)
        except Exception:
            pass
        text = raw.decode("utf-8", errors="ignore")

        if name.endswith(".csv"):
            # Đọc CSV với cấu hình an toàn; fallback nhiều tầng khi gặp lỗi quoting
            try:
                df_raw = pd.read_csv(
                    BytesIO(raw),
                    sep=",",
                    engine="python",
                    quotechar='"',
                    escapechar='\\',
                    on_bad_lines='skip',
                    skip_blank_lines=True
                )
            except Exception as e1:
                try:
                    # Thử strict quoting=csv.QUOTE_MINIMAL (pandas không expose; dùng python engine)
                    df_raw = pd.read_csv(BytesIO(raw), sep=",", engine="python", on_bad_lines='skip')
                except Exception as e2:
                    try:
                        # Làm sạch: bỏ ký tự BOM, strip và loại bỏ ";;" cuối dòng rồi đọc lại
                        text_clean = raw.decode('utf-8', errors='ignore').replace('\ufeff', '')
                        cleaned_lines = []
                        for line in text_clean.splitlines():
                            ln = line.rstrip()
                            if ln.endswith(';;'):
                                ln = ln[:-2]
                            cleaned_lines.append(ln)
                        df_raw = pd.read_csv(StringIO("\n".join(cleaned_lines)), sep=",", engine="python", on_bad_lines='skip')
                    except Exception:
                        # Cuối cùng: autodetect
                        df_raw = pd.read_csv(BytesIO(raw), sep=None, engine="python", on_bad_lines='skip')

            # Chuẩn hóa header: loại bỏ BOM và khoảng trắng đầu/cuối
            try:
                df_raw = df_raw.rename(columns=lambda c: str(c).replace('\ufeff', '').strip())
            except Exception:
                pass
        else:
            # JSON: mảng | object | NDJSON
            try:
                obj = json.loads(text)
                if isinstance(obj, list):
                    df_raw = pd.json_normalize(obj)
                elif isinstance(obj, dict):
                    df_raw = pd.json_normalize([obj])
                else:
                    # không nhận diện được → NDJSON
                    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
                    df_raw = pd.json_normalize(rows)
            except Exception:
                # NDJSON fallback
                rows = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        rows.append({"message": line})
                df_raw = pd.json_normalize(rows)
        
        # Network-focused CSV parsers
        df_raw = _maybe_parse_zeek_dns_csv(df_raw)
        df_raw = _maybe_parse_apache_extended_csv(df_raw)
        df_raw = _maybe_parse_dhcp_extended_csv(df_raw)
        df_raw = _maybe_parse_router_csv(df_raw)
        df_raw = _maybe_parse_edr_extended_csv(df_raw)
        df_raw = _maybe_parse_firewall_csv(df_raw)
        df_raw = _maybe_parse_dns_extended_csv(df_raw)
        df_raw = _maybe_parse_syslog_csv(df_raw)
        df_raw = _maybe_parse_winevent_csv(df_raw)
        df_raw = _maybe_parse_suricata_csv(df_raw)
        df_raw = _maybe_parse_squid_csv(df_raw)
        df_raw = _maybe_parse_openssh_csv(df_raw)
        df_raw = _maybe_parse_linux_csv(df_raw)
        df_raw = _maybe_parse_windows_security_csv(df_raw)

        df = _normalize_columns(df_raw)
        
        # Check which rows have NaT timestamps before dropping
        df = df.dropna(subset=["timestamp"])
        df = _filter_by_time(df, start_iso=start_iso, end_iso=end_iso)

    # --- unstructured: TXT/LOG (giữ nguyên phần bạn đã có) ---
    else:
        text = _as_text(file_obj)
        text, lines = _decode_text_and_lines(text)

        head = lines[:60]
        hit_suricata = sum(1 for ln in head if _SURICATA_RE.match(ln))
        hit_zeek_dns = sum(1 for ln in head if _ZEEK_DNS_RE.match(ln))
        hit_apache = sum(1 for ln in head if _APACHE_ACCESS_RE.match(ln))
        hit_squid = sum(1 for ln in head if _SQUID_RE.match(ln))
        hit_openssh = sum(1 for ln in head if _OPENSSH_RE.match(ln))
        hit_firewall = sum(1 for ln in head if _FIREWALL_KV_RE.match(ln) or _FIREWALL_IPTABLES_RE.match(ln) or _FIREWALL_ISO_RE.match(ln))
        hit_dhcp = sum(1 for ln in head if _DHCP_RE.match(ln))
        hit_dns = sum(1 for ln in head if _DNS_RE.match(ln))
        hit_linux = sum(1 for ln in head if _LINUX_RE.match(ln))
        hit_syslog = sum(1 for ln in head if _SYSLOG_RE.match(ln))
        hit_syslog_iso = sum(1 for ln in head if _SYSLOG_ISO_RE.match(ln))
        hit_configchg = sum(1 for ln in head if _CONFIG_CHANGE_RE.match(ln))
        hit_edrnet = sum(1 for ln in head if _EDR_NET_RE.match(ln))
        hit_netflow = sum(1 for ln in head if _NETFLOW_RE.match(ln))
        hit_modsec = sum(1 for ln in head if _MODSEC_RE.match(ln))
        hit_ids_simple = sum(1 for ln in head if _IDS_ALERT_SIMPLE_RE.match(ln))
        hit_vpcflow = sum(1 for ln in head if _VPCFLOW_RE.match(ln))
        hit_winevent = sum(1 for ln in head if _WINEVENT_RE.match(ln))
        hit_dns_query = sum(1 for ln in head if _DNS_QUERY_RE.match(ln))
        hit_edr_sysmon = sum(1 for ln in head if _EDR_SYSMON_RE.match(ln))
        hit_router_ios = sum(1 for ln in head if _ROUTER_IOS_RE.match(ln))

        import sys
        threshold = max(3, len(head)//4)
        if len(head) > 10 and any("named" in ln for ln in head[:5]):
            print(f"DEBUG: threshold={threshold} hit_dns_query={hit_dns_query} hit_syslog_iso={hit_syslog_iso} hit_syslog={hit_syslog} hit_dns={hit_dns}", file=sys.stderr)
            # Check which will match first
            for parser_name, hit_val in [("syslog_iso", hit_syslog_iso), ("dns_query", hit_dns_query), ("syslog", hit_syslog)]:
                if hit_val >= threshold:
                    print(f"   -> Will match: {parser_name} ({hit_val} >= {threshold})", file=sys.stderr)
                    break

        # Priority order: IDS alerts first, then specialized network logs, then general syslog
        if hit_suricata >= max(3, len(head)//4):
            df_raw = _parse_suricata(lines)
        elif hit_ids_simple >= max(3, len(head)//4):
            df_raw = _parse_ids_alert_simple(lines)
        elif hit_zeek_dns >= max(3, len(head)//4):
            df_raw = _parse_zeek_dns(lines)
        elif hit_apache >= max(3, len(head)//4):
            df_raw = _parse_apache_access(lines)
        elif hit_squid >= max(3, len(head)//4):
            df_raw = _parse_squid(lines)
        elif hit_modsec >= max(3, len(head)//4):
            df_raw = _parse_modsecurity(lines)
        elif hit_vpcflow >= max(3, len(head)//4):
            df_raw = _parse_vpcflow(lines)
        elif hit_netflow >= max(3, len(head)//4):
            df_raw = _parse_netflow(lines)
        elif hit_edr_sysmon >= max(3, len(head)//4):
            df_raw = _parse_edr_sysmon_log(lines)
        elif hit_router_ios >= max(3, len(head)//4):
            df_raw = _parse_router_ios_log(lines)
        elif hit_edrnet >= max(3, len(head)//4):
            df_raw = _parse_edr_network(lines)
        elif hit_winevent >= max(3, len(head)//4):
            df_raw = _parse_winevent_log(lines)
        elif hit_openssh >= max(3, len(head)//4):
            df_raw = _parse_openssh(lines)
        elif hit_firewall >= max(3, len(head)//4):
            df_raw = _parse_firewall(lines)
        elif hit_dhcp >= max(3, len(head)//4):
            df_raw = _parse_dhcp(lines)
        elif hit_dns_query >= max(3, len(head)//4):
            df_raw = _parse_dns_query_log(lines)
        elif hit_dns >= max(3, len(head)//4):
            df_raw = _parse_dns(lines)
        elif hit_linux >= max(3, len(head)//4):
            df_raw = _parse_linux_network(lines)
        elif hit_configchg >= max(3, len(head)//4):
            df_raw = _parse_config_change(lines)
        elif hit_syslog_iso >= max(3, len(head)//4):
            df_raw = _parse_syslog_iso(lines)
        elif hit_syslog >= max(3, len(head)//4):
            df_raw = _parse_syslog(lines)
        else:
            df_raw = _parse_keyvalue(lines)

        df = _normalize_columns(df_raw)
        df = df.dropna(subset=["timestamp"])
        df = _filter_by_time(df, start_iso=start_iso, end_iso=end_iso)

    # --- lọc thời gian + tạo log_text + events_per_minute (giữ nguyên như bạn đang có) ---
    def _fmt(row):
        parts = [
            f"{row['timestamp']}",
            f"IP:{row.get('source_ip','')}",
            f"User:{row.get('username','')}",
            f"Action:{row.get('action','')}",
            f"Status:{row.get('status','')}",
            f"Message:{row.get('message','')}",
        ]
        for extra in ["method","path","http_status","program","host"]:
            if extra in row and pd.notna(row[extra]): parts.append(f"{extra}:{row[extra]}")
        return " - ".join(parts)

    logs_text = df.apply(_fmt, axis=1).tolist()
    df_idx = df.set_index("timestamp").sort_index()
    events_per_minute = df_idx.resample("1min").size().reset_index(name="events_per_minute")
    df = df.reset_index()

    return logs_text, df, events_per_minute

def _decode_text_and_lines(text: str):
    raw_lines = text.splitlines()
    lines = _merge_multiline(raw_lines)
    lines = [ln.strip() for ln in lines if ln and ln.strip()]
    return text, lines

# Firewall log (Palo Alto/Juniper/Cisco style - syslog + key-value format)
# e.g. "Oct 27 09:05:00 fw-core01 firewall[1767]: action=ALLOW user=huyle device=huyle-dev1 src=10.26.173.208 dst=10.10.10.30 dst_host=ci.company.local dport=443 proto=TCP bytes=795172 rule=ci_https"
_FIREWALL_KV_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'firewall\[(?P<pid>\d+)\]:\s'
    r'(?P<message>.*)$'
)

# Old iptables format (kept for backward compatibility)
# e.g. "Dec 10 06:55:46 LabSZ kernel: [12345.678] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1"
_FIREWALL_IPTABLES_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'kernel:\s\[(?P<timestamp>\d+\.\d+)\]\s'
    r'(?P<message>.*)$'
)

# ISO format firewall logs with T separator
# e.g. "2025-10-27T10:15:20 fw01 kernel: DROP IN=eth0 OUT= SRC=10.233.64.205 DST=10.187.20.161 PROTO=TCP SPT=37505 DPT=22 SYN"
_FIREWALL_ISO_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'kernel:\s+'
    r'(?P<message>.*)$'
)

def _maybe_parse_firewall_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Firewall CSV format (Palo Alto/Juniper/Cisco style):
      timestamp,host,process,pid,severity,facility,message,department
    Extract fields from message column (key=value pairs).
    """
    required = {"timestamp", "host", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # CRITICAL: Skip if this looks like Apache, Syslog, DHCP, or Windows Event
    # These have specific process values we should not process
    if "process" in df_in.columns:
        processes = df_in["process"].dropna().astype(str).str.lower().unique()
        non_fw_processes = {"httpd", "sshd", "sudo", "cron", "kernel", "systemd", "named", "dhcpd", "winevent", "sysmon", "ios"}
        if any(p in non_fw_processes for p in processes):
            return df_in  # Not firewall - skip completely
    
    # Also skip if program column already indicates this has been parsed
    if "program" in df_in.columns:
        programs = df_in["program"].dropna().astype(str).str.lower().unique()
        if any(p in {"dhcp", "apache", "syslog", "httpd", "winevent", "sysmon", "router_ios"} for p in programs):
            return df_in  # Already parsed by specific handler
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Extract key-value pairs from message column
    def extract_kv_from_message(msg: str) -> dict:
        kv = {}
        try:
            for k, v in _KV_TOKEN_RE.findall(str(msg)):
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                kv[k.lower()] = v
        except Exception:
            pass
        return kv
    
    # Extract fields from message
    kv_list = df["message"].apply(extract_kv_from_message)
    
    df["program"] = "firewall"
    df["username"] = kv_list.apply(lambda x: x.get("user"))
    df["device"] = kv_list.apply(lambda x: x.get("device"))
    df["source_ip"] = kv_list.apply(lambda x: x.get("src"))
    df["src_port"] = kv_list.apply(lambda x: x.get("sport"))
    df["dest_ip"] = kv_list.apply(lambda x: x.get("dst"))
    df["dest_port"] = kv_list.apply(lambda x: x.get("dport"))
    df["dst_host"] = kv_list.apply(lambda x: x.get("dst_host"))
    df["protocol"] = kv_list.apply(lambda x: x.get("proto"))
    df["bytes_sent"] = kv_list.apply(lambda x: x.get("bytes"))
    df["rule"] = kv_list.apply(lambda x: x.get("rule"))
    
    # Determine action and status
    action_raw = kv_list.apply(lambda x: x.get("action", "").lower())
    df["action"] = action_raw
    df["status"] = action_raw.apply(
        lambda x: "success" if x in ("allow", "accept") 
        else "blocked" if x in ("deny", "drop", "reject") 
        else None
    )
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "severity", "username", "device",
        "source_ip", "src_port", "dest_ip", "dest_port", "dst_host", "protocol",
        "bytes_sent", "rule", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_syslog_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Linux Syslog CSV format:
      timestamp,host,process,pid,severity,facility,message,department
    Extract username, action, status from message column.
    SKIP if process='WinEvent' (handled by WinEvent parser instead).
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # SKIP if this is a Windows Event log (process='WinEvent')
    processes = df_in["process"].dropna().astype(str).unique()
    if any(str(p).lower() == "winevent" for p in processes):
        return df_in  # Let WinEvent parser handle it
    
    # SKIP if this is a DNS log (process='named')
    if any(str(p).lower() == "named" for p in processes):
        return df_in  # Let DNS parser handle it
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Extract fields from message
    def extract_syslog_message(row) -> dict:
        message = str(row.get("message", ""))
        program = str(row.get("process", ""))
        return _extract_syslog_fields(message, program)
    
    syslog_fields = df.apply(extract_syslog_message, axis=1)
    
    df["program"] = df["process"].astype(str)
    df["username"] = syslog_fields.apply(lambda x: x.get("username"))
    df["source_ip"] = syslog_fields.apply(lambda x: x.get("source_ip"))
    df["action"] = syslog_fields.apply(lambda x: x.get("action"))
    df["status"] = syslog_fields.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    # Set program to "syslog" for log type detection
    df["program"] = "syslog"
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "pid", "severity", "facility",
        "username", "source_ip", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_dhcp_extended_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Extended DHCP CSV format (with message column):
      timestamp,host,process,pid,severity,facility,message,department
    Extract DHCP fields from message column (DHCP protocol messages).
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # This parser specifically handles DHCP logs - must have 'dhcpd' process
    processes = df_in["process"].dropna().astype(str).unique()
    if not any(str(p).lower() == "dhcpd" for p in processes):
        return df_in  # Not a DHCP log
    
    # Quick validation: first message should contain DHCP keywords
    first_msg = str(df_in.iloc[0].get("message", ""))
    dhcp_keywords = ["DHCPACK", "DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPRELEASE", "DHCPINFORM"]
    if not any(kw in first_msg for kw in dhcp_keywords):
        return df_in  # Doesn't look like DHCP format
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Parse DHCP message format
    # Examples:
    # "DHCPACK on 10.26.42.89 to 02:e0:6e:c8:00:d3 (khanhng-dev3) via eth0: user=khanhng lease=8h"
    # "DHCPDISCOVER from 02:11:ef:1d:77:75 (khanhng-dev4) via eth0: user=khanhng"
    # "DHCPINFORM from 10.47.0.90 via vlan30: user=huydev device=huydev-dev5 mac=02:e8:e0:66:a8:8a"
    
    def parse_dhcp_message(msg: str) -> dict:
        result = {
            "username": None,
            "device": None,
            "mac": None,
            "ip_address": None,
            "interface": None,
            "action": None,
            "status": None
        }
        
        try:
            msg_str = str(msg)
            
            # Extract action (DHCPACK, DHCPDISCOVER, etc.)
            dhcp_actions = ["DHCPACK", "DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPRELEASE", "DHCPINFORM"]
            for action in dhcp_actions:
                if action in msg_str:
                    result["action"] = action.lower()
                    result["status"] = "success"  # All DHCP messages are successful protocol exchanges
                    break
            
            # Extract IP address
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', msg_str)
            if ip_match:
                result["ip_address"] = ip_match.group(1)
            
            # Extract MAC address
            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', msg_str)
            if mac_match:
                result["mac"] = mac_match.group(1)
            
            # Extract interface (via eth0, via vlan10, etc.)
            interface_match = re.search(r'via\s+(\S+)(?:\s|:|$)', msg_str)
            if interface_match:
                result["interface"] = interface_match.group(1)
            
            # Extract device name from parentheses: (khanhng-dev3) or (khanhng-dev4)
            device_match = re.search(r'\(([^)]+)\)', msg_str)
            if device_match:
                device_candidate = device_match.group(1)
                # Validate it looks like a device name (contains "dev" or common patterns)
                if "dev" in device_candidate.lower() or "-" in device_candidate:
                    result["device"] = device_candidate
            
            # Extract user from message (key=value format)
            # Look for "user=username" pattern
            user_match = re.search(r'user=(\S+?)(?:\s|$|:)', msg_str)
            if user_match:
                result["username"] = user_match.group(1)
            
            # Extract device
            device_match = re.search(r'device=(\S+?)(?:\s|$|[)])', msg_str)
            if device_match:
                result["device"] = device_match.group(1).rstrip(')')
            
        except Exception:
            pass
        
        return result
    
    # Parse message column
    parsed_list = df["message"].apply(parse_dhcp_message)
    
    df["program"] = "dhcp"
    df["username"] = parsed_list.apply(lambda x: x.get("username"))
    df["device"] = parsed_list.apply(lambda x: x.get("device"))
    df["mac_address"] = parsed_list.apply(lambda x: x.get("mac"))
    df["ip_address"] = parsed_list.apply(lambda x: x.get("ip_address"))
    df["interface"] = parsed_list.apply(lambda x: x.get("interface"))
    df["action"] = parsed_list.apply(lambda x: x.get("action"))
    df["status"] = parsed_list.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "severity", "username", "device", 
        "mac_address", "ip_address", "interface", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

# Windows Event Log (WinEvent) format - ISO date + syslog-like
# e.g. "2025-10-27 09:25:00 WinEvent: EventID=4634 Provider=Security An account was logged off: SubjectUserName=quangdev IpAddress=10.243.246.222"
_WINEVENT_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'WinEvent:\s+(?P<message>.*)$'
)

# DNS log (named) - syslog format with DNS query info
# e.g. "Oct 27 09:00:00 dns-eng01 named[2158]: client 10.244.80.115#54186 (nexus.company.local): query: nexus.company.local TXT IN +E (client user=minhtq device=minhtq-dev2) rcode=NOERROR answers=3"
def _parse_winevent_log(lines):
    """Parse Windows Event Log format."""
    rows = []
    for ln in lines:
        m = _WINEVENT_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{m['date']} {m['time']}"
        ts = pd.to_datetime(ts_str, utc=True, errors="coerce")

        msg = m["message"]
        
        # Extract fields from message
        event_id = None
        provider = None
        username = None
        source_ip = None
        device = None
        action = None
        status = None

        # Extract EventID
        eventid_match = re.search(r'EventID=(\d+)', msg)
        if eventid_match:
            event_id = int(eventid_match.group(1))

        # Extract Provider
        provider_match = re.search(r'Provider=(\S+)', msg)
        if provider_match:
            provider = provider_match.group(1)

        # Extract SubjectUserName (the actual user)
        user_match = re.search(r'SubjectUserName=(\S+)', msg)
        if user_match:
            username = user_match.group(1)

        # Extract IpAddress
        ip_match = re.search(r'IpAddress=(\d+\.\d+\.\d+\.\d+)', msg)
        if ip_match:
            source_ip = ip_match.group(1)

        # Extract Device
        device_match = re.search(r'Device=(\S+)', msg)
        if device_match:
            device = device_match.group(1)

        # Map EventID to action/status
        if event_id == 4624:  # Logon success
            action = "login"
            status = "success"
        elif event_id == 4625:  # Logon failure
            action = "login"
            status = "failed"
        elif event_id == 4634:  # Logoff
            action = "logoff"
            status = "success"
        elif event_id == 4672:  # Special privileges assigned
            action = "privilege_escalation"
            status = "success"
        elif event_id == 4688:  # Process creation
            action = "process_create"
            status = "success"
        elif event_id == 4798:  # Group enumeration
            action = "group_enum"
            status = "success"
        elif event_id == 5379:  # Credential read
            action = "credential_read"
            status = "success"
        elif event_id == 7045:  # Service install
            action = "service_install"
            status = "success"
        elif event_id == 1102:  # Audit log cleared
            action = "audit_log_cleared"
            status = "success"
        else:
            action = "event"
            status = "info"

        rows.append({
            "timestamp": ts,
            "host": device,  # Use device as host for consistency
            "program": "winevent",
            "event_id": event_id,
            "provider": provider,
            "username": username,
            "source_ip": source_ip,
            "device": device,
            "action": action,
            "status": status,
            "message": msg
        })
    return pd.DataFrame(rows)

def _maybe_parse_winevent_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Windows Event Log CSV format (with message column):
      timestamp,host,process,pid,severity,facility,message,department
    Extract Windows Event fields from message column.
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # This parser specifically handles Windows Event logs - check for WinEvent process
    processes = df_in["process"].dropna().astype(str).unique()
    if not any(str(p).lower() == "winevent" for p in processes):
        return df_in  # Not a Windows Event log
    
    # Quick validation: first message should contain EventID
    first_msg = str(df_in.iloc[0].get("message", ""))
    if "EventID=" not in first_msg:
        return df_in  # Doesn't look like WinEvent format
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Parse Windows Event message format
    def parse_winevent_message(msg: str) -> dict:
        result = {
            "event_id": None,
            "provider": None,
            "username": None,
            "source_ip": None,
            "device": None,
            "action": None,
            "status": None
        }
        
        try:
            msg_str = str(msg)
            
            # Extract EventID
            eventid_match = re.search(r'EventID=(\d+)', msg_str)
            if eventid_match:
                result["event_id"] = int(eventid_match.group(1))
            
            # Extract Provider
            provider_match = re.search(r'Provider=(\S+)', msg_str)
            if provider_match:
                result["provider"] = provider_match.group(1)
            
            # Extract SubjectUserName
            user_match = re.search(r'SubjectUserName=(\S+)', msg_str)
            if user_match:
                result["username"] = user_match.group(1)
            
            # Extract IpAddress
            ip_match = re.search(r'IpAddress=(\d+\.\d+\.\d+\.\d+)', msg_str)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
            
            # Extract Device
            device_match = re.search(r'Device=(\S+)', msg_str)
            if device_match:
                result["device"] = device_match.group(1)
            
            # Map EventID to action/status
            event_id = result["event_id"]
            if event_id == 4624:
                result["action"] = "login"
                result["status"] = "success"
            elif event_id == 4625:
                result["action"] = "login"
                result["status"] = "failed"
            elif event_id == 4634:
                result["action"] = "logoff"
                result["status"] = "success"
            elif event_id == 4672:
                result["action"] = "privilege_escalation"
                result["status"] = "success"
            elif event_id == 4688:
                result["action"] = "process_create"
                result["status"] = "success"
            else:
                result["action"] = "event"
                result["status"] = "info"
        
        except Exception:
            pass
        
        return result
    
    # Parse message column
    parsed_list = df["message"].apply(parse_winevent_message)
    
    df["program"] = "winevent"
    df["event_id"] = parsed_list.apply(lambda x: x.get("event_id"))
    df["provider"] = parsed_list.apply(lambda x: x.get("provider"))
    df["username"] = parsed_list.apply(lambda x: x.get("username"))
    df["source_ip"] = parsed_list.apply(lambda x: x.get("source_ip"))
    df["device"] = parsed_list.apply(lambda x: x.get("device"))
    df["action"] = parsed_list.apply(lambda x: x.get("action"))
    df["status"] = parsed_list.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "event_id", "provider", "severity",
        "username", "source_ip", "device", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _maybe_parse_dns_extended_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Extended DNS CSV format (with message column):
      timestamp,host,process,pid,severity,facility,message,department
    Extract DNS fields from message column.
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # This parser specifically handles DNS logs - must have 'named' process
    processes = df_in["process"].dropna().astype(str).unique()
    if not any(str(p).lower() == "named" for p in processes):
        return df_in  # Not a DNS log
    
    # Quick validation: first message should contain DNS keywords
    first_msg = str(df_in.iloc[0].get("message", ""))
    if "query:" not in first_msg.lower() and "client" not in first_msg.lower():
        return df_in  # Doesn't look like DNS format
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Parse DNS message format
    # Examples:
    # "client 10.244.80.115#54186 (nexus.company.local): query: nexus.company.local TXT IN +E (client user=minhtq device=minhtq-dev2) rcode=NOERROR answers=3"
    # "resolver: info: Marking files.company.local as lame; user=huydev device=huydev-dev2 client=10.218.64.186"
    
    def parse_dns_message(msg: str) -> dict:
        result = {
            "username": None,
            "device": None,
            "source_ip": None,
            "domain": None,
            "query_type": None,
            "rcode": None,
            "action": None,
            "status": None
        }
        
        try:
            msg_str = str(msg)
            
            # Extract source IP (client IP)
            ip_match = re.search(r'client\s+(\d+\.\d+\.\d+\.\d+)', msg_str)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
            
            # Extract domain (inside parentheses before colon)
            domain_match = re.search(r'\(([^)]+)\):\s+query:', msg_str)
            if domain_match:
                result["domain"] = domain_match.group(1)
            
            # Extract query type (A, AAAA, MX, TXT, etc.)
            qtype_match = re.search(r'query:\s+\S+\s+(\w+)\s+IN', msg_str)
            if qtype_match:
                result["query_type"] = qtype_match.group(1)
            
            # Extract rcode (NOERROR, NXDOMAIN, etc.)
            rcode_match = re.search(r'rcode=(\w+)', msg_str)
            if rcode_match:
                result["rcode"] = rcode_match.group(1)
            
            # Extract user
            user_match = re.search(r'user=(\S+?)(?:\s|$)', msg_str)
            if user_match:
                result["username"] = user_match.group(1)
            
            # Extract device
            device_match = re.search(r'device=(\S+?)(?:\s|$|[)])', msg_str)
            if device_match:
                result["device"] = device_match.group(1).rstrip(')')
            
            # Determine action and status
            if "query:" in msg_str:
                result["action"] = "query"
                if result["rcode"] == "NOERROR":
                    result["status"] = "success"
                elif result["rcode"] == "NXDOMAIN":
                    result["status"] = "failed"
                else:
                    result["status"] = "info"
            elif "lame" in msg_str.lower():
                result["action"] = "lame_server"
                result["status"] = "alert"
            else:
                result["action"] = "dns_event"
                result["status"] = "info"
        
        except Exception:
            pass
        
        return result
    
    # Parse message column
    parsed_list = df["message"].apply(parse_dns_message)
    
    df["program"] = "named"
    df["username"] = parsed_list.apply(lambda x: x.get("username"))
    df["device"] = parsed_list.apply(lambda x: x.get("device"))
    df["source_ip"] = parsed_list.apply(lambda x: x.get("source_ip"))
    df["domain"] = parsed_list.apply(lambda x: x.get("domain"))
    df["query_type"] = parsed_list.apply(lambda x: x.get("query_type"))
    df["rcode"] = parsed_list.apply(lambda x: x.get("rcode"))
    df["action"] = parsed_list.apply(lambda x: x.get("action"))
    df["status"] = parsed_list.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "severity", "username", "device",
        "source_ip", "domain", "query_type", "rcode", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _parse_dns_query_log(lines, assume_year=None):
    """Parse DNS Query logs with embedded user/device info."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _DNS_QUERY_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{year} {m['mon']} {int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", errors="coerce", utc=True)

        msg = m["message"]
        
        # Extract fields from message
        source_ip = None
        username = None
        device = None
        domain = None
        query_type = None
        rcode = None
        action = None
        status = None

        # Extract source IP (client IP)
        ip_match = re.search(r'client\s+(\d+\.\d+\.\d+\.\d+)', msg)
        if ip_match:
            source_ip = ip_match.group(1)

        # Extract domain (inside parentheses before colon)
        domain_match = re.search(r'\(([^)]+)\):\s+query:', msg)
        if domain_match:
            domain = domain_match.group(1)

        # Extract query type (A, AAAA, MX, TXT, etc.)
        qtype_match = re.search(r'query:\s+\S+\s+(\w+)\s+IN', msg)
        if qtype_match:
            query_type = qtype_match.group(1)

        # Extract rcode (NOERROR, NXDOMAIN, etc.)
        rcode_match = re.search(r'rcode=(\w+)', msg)
        if rcode_match:
            rcode = rcode_match.group(1)

        # Extract user
        user_match = re.search(r'user=(\S+?)(?:\s|$|[)])', msg)
        if user_match:
            username = user_match.group(1).rstrip(')')
        
        # Extract device
        device_match = re.search(r'device=(\S+?)(?:\s|$|[)])', msg)
        if device_match:
            device = device_match.group(1).rstrip(')')

        # Determine action and status
        if "query:" in msg:
            action = "query"
            if rcode == "NOERROR":
                status = "success"
            elif rcode == "NXDOMAIN":
                status = "failed"
            else:
                status = "info"
        elif "lame" in msg.lower():
            action = "lame_server"
            status = "alert"
        else:
            action = "dns_event"
            status = "info"

        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": "named",
            "username": username,
            "device": device,
            "source_ip": source_ip,
            "domain": domain,
            "query_type": query_type,
            "rcode": rcode,
            "action": action,
            "status": status,
            "message": msg
        })
    
    df = pd.DataFrame(rows)
    
    # Add group column (needed for baseline training and group_members.json)
    # For LOG files, group will come from the curl "group" parameter via app.py
    # We set a placeholder here, it gets overridden during training
    if "group" not in df.columns:
        df["group"] = "Engineering"  # Default group for LOG files
    
    return df

# DNS log (named) - syslog format with DNS query info
_DNS_QUERY_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'named\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# Router/IOS - Classic syslog format (Cisco IOS)
# e.g. "Oct 27 09:10:49 rtr-branch-s2 ios[18737]: %BGP-5-ADJCHANGE: ..."
_ROUTER_IOS_RE = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s'
    r'(?P<host>\S+)\s'
    r'ios\[(?P<pid>\d+)\]:\s(?P<message>.*)$'
)

# EDR/Sysmon - ISO timestamp format with key=value fields
# e.g. "2025-10-27 09:20:00 Sysmon: EventID=3 User=huydev Device=huydev-dev1 SrcIp=10.149.15.24 ..."
_EDR_SYSMON_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+Sysmon:\s+(?P<message>.*)$'
)

def _maybe_parse_router_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Router/IOS CSV format:
      timestamp,host,process,pid,severity,facility,message,department
    Extract fields from message column.
    """
    required = {"timestamp", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # Check if this looks like Router logs (process='ios' and message has router patterns)
    if "process" in df_in.columns:
        has_ios = (df_in["process"].astype(str).str.lower() == "ios").any()
        if not has_ios:
            return df_in
    
    # Check if message contains router keywords
    msg_sample = df_in["message"].astype(str).str.cat(sep=" ").lower()
    if not any(kw in msg_sample for kw in ["bgp-", "ospf-", "login_success", "logout", "configured from vty", "%sys-", "nat-6"]):
        return df_in
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Extract fields from message
    def extract_router_fields(msg):
        result = {
            "username": None,
            "device": None,
            "source_ip": None,
            "action": None,
            "status": None
        }
        
        msg_str = str(msg)
        
        # Extract username patterns
        # Pattern 1: "by minhtq (10.149.214.57)" or "by user khanhng"
        user_match = re.search(r'by\s+(?:user\s+)?(\S+?)(?:\s|\(|$)', msg_str)
        if user_match:
            result["username"] = user_match.group(1).rstrip(')')
        
        # Pattern 2: "[user:tnghia]"
        if not result["username"]:
            user_match = re.search(r'\[user:(\S+?)\]', msg_str)
            if user_match:
                result["username"] = user_match.group(1).rstrip(')')
        
        # Extract device patterns
        # Pattern 1: "using device minhtq-dev6" or "device=tnghia-dev1"
        dev_match = re.search(r'(?:using\s+)?device[=\s]+(\S+?)(?:\s|$)', msg_str)
        if dev_match:
            result["device"] = dev_match.group(1).rstrip(')')
        
        # Extract source IP patterns
        # Pattern 1: "from 10.64.227.219 by user"
        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg_str)
        if ip_match:
            result["source_ip"] = ip_match.group(1)
        
        # Pattern 2: "[Source:10.14.72.73]"
        if not result["source_ip"]:
            ip_match = re.search(r'\[Source:(\d+\.\d+\.\d+\.\d+)\]', msg_str)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
        
        # Pattern 3: "Login from 10.48.5.25 by user"
        if not result["source_ip"]:
            ip_match = re.search(r'Login\s+from\s+(\d+\.\d+\.\d+\.\d+)', msg_str)
            if ip_match:
                result["source_ip"] = ip_match.group(1)
        
        # Map action based on keywords
        msg_lower = msg_str.lower()
        if "login" in msg_lower and "success" in msg_lower:
            result["action"] = "login"
            result["status"] = "success"
        elif "logout" in msg_lower:
            result["action"] = "logout"
            result["status"] = "success"
        elif "configured" in msg_lower:
            result["action"] = "config_change"
            result["status"] = "success"
        elif "adjchange" in msg_lower or "adjchg" in msg_lower:
            result["action"] = "bgp_ospf_event"
            result["status"] = "warning"
        elif "nat-6" in msg_lower:
            result["action"] = "nat_portmap"
            result["status"] = "info"
        elif "link" in msg_lower or "lineproto" in msg_lower:
            result["action"] = "interface_event"
            result["status"] = "info"
        else:
            result["action"] = "router_event"
            result["status"] = "info"
        
        return pd.Series(result)
    
    kv_list = df["message"].apply(extract_router_fields)
    
    df["program"] = "router_ios"
    df["username"] = kv_list["username"] if "username" in kv_list.columns else None
    df["device"] = kv_list["device"] if "device" in kv_list.columns else None
    df["source_ip"] = kv_list["source_ip"] if "source_ip" in kv_list.columns else None
    df["action"] = kv_list["action"] if "action" in kv_list.columns else None
    df["status"] = kv_list["status"] if "status" in kv_list.columns else None
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "username", "device",
        "source_ip", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _parse_router_ios_log(lines, assume_year=None):
    """Parse Router/IOS logs with embedded user/device info."""
    rows = []
    year = assume_year or datetime.utcnow().year
    
    for ln in lines:
        m = _ROUTER_IOS_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue
        
        # Convert month name to number
        month_map = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                     "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
        month = month_map.get(m["mon"], 1)
        
        ts_str = f"{year}-{month:02d}-{int(m['day']):02d} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y-%m-%d %H:%M:%S", errors="coerce", utc=True)
        
        msg = m["message"]
        
        # Extract fields from message
        username = None
        device = None
        source_ip = None
        action = None
        status = None
        
        # Extract username patterns
        user_match = re.search(r'by\s+(?:user\s+)?(\S+?)(?:\s|\(|$)', msg)
        if user_match:
            username = user_match.group(1).rstrip(')')
        
        if not username:
            user_match = re.search(r'\[user:(\S+?)\]', msg)
            if user_match:
                username = user_match.group(1).rstrip(')')
        
        # Extract device patterns
        dev_match = re.search(r'(?:using\s+)?device[=\s]+(\S+?)(?:\s|$)', msg)
        if dev_match:
            device = dev_match.group(1).rstrip(')')
        
        # Extract source IP patterns
        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
        if ip_match:
            source_ip = ip_match.group(1)
        
        if not source_ip:
            ip_match = re.search(r'\[Source:(\d+\.\d+\.\d+\.\d+)\]', msg)
            if ip_match:
                source_ip = ip_match.group(1)
        
        if not source_ip:
            ip_match = re.search(r'Login\s+from\s+(\d+\.\d+\.\d+\.\d+)', msg)
            if ip_match:
                source_ip = ip_match.group(1)
        
        # Map action based on keywords
        msg_lower = msg.lower()
        if "login" in msg_lower and "success" in msg_lower:
            action = "login"
            status = "success"
        elif "logout" in msg_lower:
            action = "logout"
            status = "success"
        elif "configured" in msg_lower:
            action = "config_change"
            status = "success"
        elif "adjchange" in msg_lower or "adjchg" in msg_lower:
            action = "bgp_ospf_event"
            status = "warning"
        elif "nat-6" in msg_lower:
            action = "nat_portmap"
            status = "info"
        elif "link" in msg_lower or "lineproto" in msg_lower:
            action = "interface_event"
            status = "info"
        else:
            action = "router_event"
            status = "info"
        
        rows.append({
            "timestamp": ts,
            "host": m["host"],
            "program": "router_ios",
            "username": username,
            "device": device,
            "source_ip": source_ip,
            "action": action,
            "status": status,
            "message": msg,
            "group": "Engineering"  # Default group for LOG files
        })
    
    df = pd.DataFrame(rows)
    
    # Ensure group column exists
    if "group" not in df.columns:
        df["group"] = "Engineering"
    
    return df

def _maybe_parse_edr_extended_csv(df_in: pd.DataFrame) -> pd.DataFrame:
    """
    Parse Extended EDR/Sysmon CSV format (with message column):
      timestamp,host,process,pid,severity,facility,message,department
    Extract EDR fields from message column (EventID, User, Device, IPs, etc).
    """
    required = {"timestamp", "host", "process", "message"}
    if not required.issubset(set(df_in.columns)):
        return df_in
    
    # This parser specifically handles EDR/Sysmon logs - must have 'sysmon' process
    processes = df_in["process"].dropna().astype(str).unique()
    if not any(str(p).lower() == "sysmon" for p in processes):
        return df_in  # Not an EDR log
    
    # Quick validation: first message should contain "Sysmon:" and "EventID="
    first_msg = str(df_in.iloc[0].get("message", ""))
    if "Sysmon:" not in first_msg or "EventID=" not in first_msg:
        return df_in  # Doesn't look like EDR format
    
    df = df_in.copy()
    
    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    
    # Parse EDR message format
    # Example: "2025-10-27 09:20:00 Sysmon: EventID=3 User=huydev Device=huydev-dev1 SrcIp=10.149.15.24 Image=C:\...\msedge.exe DestinationIp=10.10.10.20 DestinationPort=22 Protocol=TCP Note="baseline""
    
    def parse_edr_message(msg: str) -> dict:
        result = {
            "event_id": None,
            "username": None,
            "device": None,
            "source_ip": None,
            "destination_ip": None,
            "destination_port": None,
            "protocol": None,
            "image": None,
            "action": None,
            "status": None
        }
        
        try:
            msg_str = str(msg)
            
            # Extract EventID
            eid_match = re.search(r'EventID=(\d+)', msg_str)
            if eid_match:
                result["event_id"] = int(eid_match.group(1))
            
            # Extract username
            user_match = re.search(r'User=(\S+?)(?:\s|$)', msg_str)
            if user_match:
                result["username"] = user_match.group(1).rstrip(')')
            
            # Extract device
            device_match = re.search(r'Device=(\S+?)(?:\s|$)', msg_str)
            if device_match:
                result["device"] = device_match.group(1).rstrip(')')
            
            # Extract source IP
            srcip_match = re.search(r'SrcIp=(\d+\.\d+\.\d+\.\d+)', msg_str)
            if srcip_match:
                result["source_ip"] = srcip_match.group(1)
            
            # Extract destination IP
            dstip_match = re.search(r'DestinationIp=(\d+\.\d+\.\d+\.\d+)', msg_str)
            if dstip_match:
                result["destination_ip"] = dstip_match.group(1)
            
            # Extract destination port
            port_match = re.search(r'DestinationPort=(\d+)', msg_str)
            if port_match:
                result["destination_port"] = int(port_match.group(1))
            
            # Extract protocol
            proto_match = re.search(r'Protocol=(\w+)', msg_str)
            if proto_match:
                result["protocol"] = proto_match.group(1)
            
            # Extract image/process path
            image_match = re.search(r'Image=([^\s]+?)(?:\s|$)', msg_str)
            if image_match:
                result["image"] = image_match.group(1).strip('"')
            
            # Map EventID to action/status
            if result["event_id"] == 3:  # Network connection
                result["action"] = "network_connect"
                result["status"] = "success"
            else:
                result["action"] = f"event_{result['event_id']}"
                result["status"] = "info"
        
        except Exception:
            pass
        
        return result
    
    # Parse message column
    parsed_list = df["message"].apply(parse_edr_message)
    
    df["program"] = "sysmon"
    df["event_id"] = parsed_list.apply(lambda x: x.get("event_id"))
    df["username"] = parsed_list.apply(lambda x: x.get("username"))
    df["device"] = parsed_list.apply(lambda x: x.get("device"))
    df["source_ip"] = parsed_list.apply(lambda x: x.get("source_ip"))
    df["destination_ip"] = parsed_list.apply(lambda x: x.get("destination_ip"))
    df["destination_port"] = parsed_list.apply(lambda x: x.get("destination_port"))
    df["protocol"] = parsed_list.apply(lambda x: x.get("protocol"))
    df["image"] = parsed_list.apply(lambda x: x.get("image"))
    df["action"] = parsed_list.apply(lambda x: x.get("action"))
    df["status"] = parsed_list.apply(lambda x: x.get("status"))
    
    # Map department to group if present
    if "department" in df.columns:
        df["group"] = df["department"].astype(str)
    
    # Ensure required columns exist
    for want in ["action", "status"]:
        if want not in df.columns:
            df[want] = None
    
    df = df.sort_values("timestamp").reset_index(drop=True)
    
    keep_cols = [
        "timestamp", "host", "program", "event_id", "username", "device",
        "source_ip", "destination_ip", "destination_port", "protocol", 
        "image", "action", "status", "group", "message"
    ]
    keep_cols = [c for c in keep_cols if c in df.columns]
    return df[keep_cols]

def _parse_edr_sysmon_log(lines, assume_year=None):
    """Parse EDR/Sysmon logs with embedded user/device info."""
    rows = []
    year = assume_year or datetime.utcnow().year
    for ln in lines:
        m = _EDR_SYSMON_RE.match(ln)
        if not m:
            rows.append({"timestamp": pd.NaT, "message": ln})
            continue

        ts_str = f"{m['date']} {m['time']}"
        ts = pd.to_datetime(ts_str, format="%Y-%m-%d %H:%M:%S", errors="coerce", utc=True)

        msg = m["message"]
        
        # Extract fields from message
        event_id = None
        username = None
        device = None
        source_ip = None
        destination_ip = None
        destination_port = None
        protocol = None
        image = None
        action = None
        status = None

        # Extract EventID
        eid_match = re.search(r'EventID=(\d+)', msg)
        if eid_match:
            event_id = int(eid_match.group(1))

        # Extract username
        user_match = re.search(r'User=(\S+?)(?:\s|$)', msg)
        if user_match:
            username = user_match.group(1).rstrip(')')

        # Extract device
        device_match = re.search(r'Device=(\S+?)(?:\s|$)', msg)
        if device_match:
            device = device_match.group(1).rstrip(')')

        # Extract source IP
        srcip_match = re.search(r'SrcIp=(\d+\.\d+\.\d+\.\d+)', msg)
        if srcip_match:
            source_ip = srcip_match.group(1)

        # Extract destination IP
        dstip_match = re.search(r'DestinationIp=(\d+\.\d+\.\d+\.\d+)', msg)
        if dstip_match:
            destination_ip = dstip_match.group(1)

        # Extract destination port
        port_match = re.search(r'DestinationPort=(\d+)', msg)
        if port_match:
            destination_port = int(port_match.group(1))

        # Extract protocol
        proto_match = re.search(r'Protocol=(\w+)', msg)
        if proto_match:
            protocol = proto_match.group(1)

        # Extract image/process path
        image_match = re.search(r'Image=([^\s]+?)(?:\s|$)', msg)
        if image_match:
            image = image_match.group(1).strip('"')

        # Map EventID to action/status
        if event_id == 3:  # Network connection
            action = "network_connect"
            status = "success"
        else:
            action = f"event_{event_id}" if event_id else "edr_event"
            status = "info"

        rows.append({
            "timestamp": ts,
            "host": device or "unknown",
            "program": "sysmon",
            "event_id": event_id,
            "username": username,
            "device": device,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "image": image,
            "action": action,
            "status": status,
            "message": msg
        })
    
    df = pd.DataFrame(rows)
    
    # Add group column (needed for baseline training and group_members.json)
    if "group" not in df.columns:
        df["group"] = "Engineering"  # Default group for LOG files
    
    return df
