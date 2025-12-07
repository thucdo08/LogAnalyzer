import os
import json
import re
from typing import List, Dict, Any, Tuple

import numpy as np
import pandas as pd
from datetime import timezone


def _to_dt_utc(df: pd.DataFrame) -> pd.DataFrame:
    if "timestamp" not in df.columns:
        raise ValueError("Missing 'timestamp' column")
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.dropna(subset=["timestamp"]).reset_index(drop=True)
    return out


def _load_json_df(path: str) -> pd.DataFrame:
    try:
        if os.path.exists(path):
            return pd.read_json(path, orient="records")
    except Exception:
        pass
    return pd.DataFrame()


def _load_baseline_tables(base_dir: str) -> Dict[str, Any]:
    """
    Load previously trained baselines from config/baselines/*
    Returns dict with user_stats, device_stats, group_stats, global_stats.
    """
    out: Dict[str, Any] = {}
    out["user_stats"] = _load_json_df(os.path.join(base_dir, "user_stats.json"))
    out["device_stats"] = _load_json_df(os.path.join(base_dir, "device_stats.json"))
    out["group_stats"] = _load_json_df(os.path.join(base_dir, "group_stats.json"))
    # global baseline is a list of snapshots; take last if exists
    gb_path = os.path.join(base_dir, "global_baseline.json")
    try:
        if os.path.exists(gb_path):
            with open(gb_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and data:
                    out["global_stats"] = data[-1]
                elif isinstance(data, dict):
                    out["global_stats"] = data
                else:
                    out["global_stats"] = {}
        else:
            out["global_stats"] = {}
    except Exception:
        out["global_stats"] = {}
    return out


def _safe_z(current: float, mean: float, std: float) -> float:
    if std is None or std == 0 or np.isnan(std):
        return 0.0
    return (float(current) - float(mean)) / float(std)


def _fmt_local_vn(ts: pd.Timestamp) -> str:
    try:
        t = pd.to_datetime(ts, errors="coerce", utc=True)
        if pd.isna(t):
            return str(ts)
        local = t.tz_convert("Asia/Ho_Chi_Minh")
        # Example: 02:15 AM, Thứ Ba, 23/09/2025
        weekday = ["Thứ Hai","Thứ Ba","Thứ Tư","Thứ Năm","Thứ Sáu","Thứ Bảy","Chủ Nhật"][local.weekday()]
        return f"{local.strftime('%I:%M %p')}, {weekday}, {local.strftime('%d/%m/%Y')}"
    except Exception:
        return str(ts)


def _count_user_downloads(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build per-user total download counts within the provided dataframe window.
    Heuristic: action=='download' or message contains 'download|tải xuống'.
    Returns DataFrame: username, files_downloaded
    """
    tmp = df.copy()
    is_download = (
        tmp.get("action", pd.Series(index=tmp.index)).astype(str).str.contains("download", case=False, na=False)
        | tmp.get("message", pd.Series(index=tmp.index)).astype(str).str.contains("download|tải xuống", case=False, na=False)
    )
    tmp = tmp[is_download]
    if tmp.empty:
        return pd.DataFrame(columns=["username", "files_downloaded"]) 
    tmp["username"] = tmp.get("username", pd.Series(index=tmp.index)).fillna("<unknown>").astype(str)
    agg = tmp.groupby("username").size().reset_index(name="files_downloaded")
    return agg


def _user_activity_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-user aggregate features aligned with what baseline provides: events, unique_src_ips,
    login_fail, ssh_events, http_4xx, http_5xx within the window.
    """
    tmp = df.copy()
    tmp["username"] = tmp.get("username", pd.Series(index=tmp.index)).fillna("<unknown>").astype(str)
    prog = tmp.get("program", pd.Series(index=tmp.index)).astype(str)
    http_status = pd.to_numeric(tmp.get("http_status", pd.Series(index=tmp.index)), errors="coerce")
    act = tmp.get("action", pd.Series(index=tmp.index)).astype(str).str.lower()
    status = tmp.get("status", pd.Series(index=tmp.index)).astype(str).str.lower()

    def _count_ssh(g: pd.DataFrame) -> int:
        return int(g.get("program", pd.Series(index=g.index)).astype(str).str.contains("ssh", case=False, na=False).sum())

    def _count_http_4xx(g: pd.DataFrame) -> int:
        hs = pd.to_numeric(g.get("http_status", pd.Series(index=g.index)), errors="coerce")
        return int(hs.between(400, 499).sum())

    def _count_http_5xx(g: pd.DataFrame) -> int:
        hs = pd.to_numeric(g.get("http_status", pd.Series(index=g.index)), errors="coerce")
        return int(hs.between(500, 599).sum())

    grp = tmp.groupby("username", dropna=False)
    feat = pd.DataFrame({
        "events": grp.size(),
        "unique_src_ips": grp["source_ip"].nunique(dropna=True) if "source_ip" in tmp.columns else 0,
        "login_fail": grp.apply(lambda g: int(((g.get("action", pd.Series(index=g.index)).astype(str).str.lower()=="login") & (g.get("status", pd.Series(index=g.index)).astype(str).str.lower()=="failed")).sum())),
        "ssh_events": grp.apply(_count_ssh),
        "http_4xx": grp.apply(_count_http_4xx),
        "http_5xx": grp.apply(_count_http_5xx),
    }).reset_index()
    for c in ["events","unique_src_ips","login_fail","ssh_events","http_4xx","http_5xx"]:
        if c in feat.columns:
            feat[c] = pd.to_numeric(feat[c], errors="coerce").fillna(0).astype(int)
    return feat


# Baseline-based detection (no hardcoded patterns - comparison with baseline instead)

def _resolve_unknown_user(df: pd.DataFrame, unknown_user: str) -> str:
    """
    If username is unknown, try to resolve from sudo logs in the same dataset.
    E.g., if we see postgres logs with no user but also see 'sudo: linhfin : COMMAND=/usr/bin/pg_dump',
    we know linhfin executed the postgres operations.
    """
    if unknown_user and str(unknown_user).strip() != "(unknown)":
        return unknown_user
    
    # Check for sudo logs that might give us the real user
    if "action" in df.columns and "username" in df.columns:
        sudo_logs = df[(df["action"].astype(str).str.lower() == "sudo") & (df["username"].notna())]
        if len(sudo_logs) > 0:
            # Get most common sudo user (most likely the actor)
            users = sudo_logs["username"].value_counts()
            if len(users) > 0:
                real_user = users.index[0]
                return f"{unknown_user}(via {real_user})"  # Mark origin
    
    return unknown_user

def _detect_dhcp_scope_conflicts(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect if same MAC address (device) gets IPs from different DHCP servers or subnets.
    This indicates potential scope conflict or rogue DHCP server.
    """
    alerts = []
    
    if "mac_address" not in df.columns or "host" not in df.columns:
        return alerts
    
    try:
        # Group by MAC address (unique device identifier)
        for mac, group in df[df["mac_address"].notna()].groupby("mac_address"):
            group = group.copy()
            
            # Count unique DHCP servers and subnets
            unique_servers = group["host"].nunique()
            unique_subnets = set()
            
            # Extract subnet from IP address
            for _, row in group.iterrows():
                ip = row.get("ip_address")
                if ip and isinstance(ip, str):
                    try:
                        subnet = ".".join(ip.split(".")[:3])  # First 3 octets
                        unique_subnets.add(subnet)
                    except Exception:
                        pass
            
            # Multiple servers OR multiple subnets = scope conflict (suspicious!)
            if unique_servers >= 2 or len(unique_subnets) >= 2:
                # Get user associated with this MAC
                users = group["username"].dropna().astype(str).unique()
                user_str = users[0] if len(users) > 0 else f"Device-{mac[:8]}"
                
                servers_list = group["host"].unique().tolist()
                subnets_list = sorted(list(unique_subnets))
                
                alert_text = f"Thiết bị MAC {mac} nhận IP từ {unique_servers} DHCP servers khác nhau ({', '.join(servers_list)}) trong {len(unique_subnets)} subnets ({', '.join(subnets_list)}). Điều này có thể chỉ ra xung đột phạm vi DHCP hoặc máy chủ rogue."
                
                alerts.append({
                    "type": "dhcp_scope_conflict",
                    "subject": user_str,
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "text": alert_text,
                    "evidence": {
                        "mac_address": mac,
                        "servers": servers_list,
                        "subnets": subnets_list,
                        "server_count": int(unique_servers),
                        "subnet_count": int(len(unique_subnets)),
                    },
                    "prompt_ctx": {
                        "user": user_str,
                        "group": None,
                        "behavior": {"type": "dhcp_scope_conflict", "servers": unique_servers, "subnets": len(unique_subnets)},
                        "time": None,
                        "baseline": {},
                        "extras": {"reason": "MAC appears in multiple DHCP server responses"},
                    },
                })
    except Exception as e:
        pass  # Silently skip if error
    
    return alerts

def _detect_dhcp_rogue_server(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect rapid DHCP ACKs which may indicate rogue DHCP server, NAK storm, or address exhaustion attack.
    Normal DHCP: 1-2 ACKs per minute
    Abnormal: >10 ACKs per minute
    """
    alerts = []
    
    if "action" not in df.columns or "timestamp" not in df.columns:
        return alerts
    
    try:
        # Filter to ACK events only
        ack_df = df[df["action"] == "ack"].copy()
        if len(ack_df) < 5:
            return alerts
        
        # Ensure timestamp is datetime
        ack_df["timestamp"] = pd.to_datetime(ack_df["timestamp"], errors="coerce", utc=True)
        ack_df = ack_df.dropna(subset=["timestamp"])
        
        if len(ack_df) == 0:
            return alerts
        
        # Count ACKs per minute
        ack_df["minute"] = ack_df["timestamp"].dt.floor("1min")
        ack_rates = ack_df.groupby("minute").size()
        
        # Check for abnormal rates (>10 per minute is suspicious)
        suspicious_minutes = ack_rates[ack_rates > 10]
        
        if len(suspicious_minutes) > 0:
            max_rate = int(ack_rates.max())
            suspicious_count = len(suspicious_minutes)
            
            alert_text = f"Phát hiện tỷ lệ DHCP ACK bất thường: {max_rate} ACKs/phút (so với cơ sở 1-2/phút). Điều này có thể chỉ ra máy chủ rogue, cuộc tấn công NAK storm, hoặc cạn kiệt địa chỉ."
            
            alerts.append({
                "type": "dhcp_rogue_server_indication",
                "subject": "DHCP Network",
                "severity": "CRITICAL",
                "score": 8.5,
                "text": alert_text,
                "evidence": {
                    "max_acks_per_minute": int(max_rate),
                    "normal_baseline_min": 1,
                    "normal_baseline_max": 2,
                    "suspicious_minute_count": int(suspicious_count),
                    "total_acks": int(len(ack_df)),
                },
                "prompt_ctx": {
                    "user": None,
                    "group": None,
                    "behavior": {"type": "dhcp_abnormal_rate", "rate": max_rate},
                    "time": None,
                    "baseline": {"expected_acks_per_min": "1-2"},
                    "extras": {"reason": "High frequency of DHCP ACK responses"},
                },
            })
    except Exception as e:
        pass  # Silently skip if error
    
    return alerts

def _detect_dhcp_user_device_mismatch(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect if same device name is used by multiple users in short timeframe.
    This may indicate device hijacking, unauthorized access, or testing.
    """
    alerts = []
    
    if "device" not in df.columns or "username" not in df.columns:
        return alerts
    
    try:
        # Group by device name (e.g., "khanhng-dev3")
        for device, group in df[df["device"].notna()].groupby("device"):
            group = group.copy()
            
            # Count unique users on this device
            unique_users = group["username"].dropna().astype(str).unique()
            
            # If 3+ different users on same device = suspicious (device hijacking or shared testing)
            if len(unique_users) >= 3:
                time_span = group["timestamp"].max() - group["timestamp"].min()
                time_minutes = int(time_span.total_seconds() / 60) if pd.notna(time_span) else 0
                
                users_list = sorted(list(unique_users))
                
                alert_text = f"Thiết bị '{device}' được sử dụng bởi {len(unique_users)} người dùng khác nhau trong {time_minutes} phút ({', '.join(users_list)}). Có thể chỉ ra cướp quyền điều khiển thiết bị hoặc chia sẻ trái phép."
                
                alerts.append({
                    "type": "dhcp_device_user_mismatch",
                    "subject": device,
                    "severity": "WARNING",
                    "score": 6.5,
                    "text": alert_text,
                    "evidence": {
                        "device": device,
                        "user_count": int(len(unique_users)),
                        "users": users_list,
                        "time_span_minutes": int(time_minutes),
                    },
                    "prompt_ctx": {
                        "user": users_list[0] if len(users_list) > 0 else None,
                        "group": None,
                        "behavior": {"type": "device_user_mismatch", "users": len(unique_users)},
                        "time": None,
                        "baseline": {"expected_users_per_device": 1},
                        "extras": {"reason": "Multiple users sharing same device in short time"},
                    },
                })
    except Exception as e:
        pass  # Silently skip if error
    
    return alerts

def _detect_apache_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect Apache/web-based attacks (credential stuffing, path probing, SQLi, exfiltration, webshell)."""
    alerts = []
    
    # Detect Apache logs by checking for Apache-specific columns (http_status, path, vhost)
    # instead of relying on program column which may be missing
    apache_indicators = ["http_status", "path", "vhost"]
    has_apache_cols = any(col in df.columns for col in apache_indicators)
    
    # Also check if program column exists and is "apache"
    has_apache_program = "program" in df.columns and df["program"].eq("apache").any()
    
    if not has_apache_cols and not has_apache_program:
        return alerts
    
    try:
        # Filter to Apache logs: either program=="apache" OR has Apache-specific columns
        if has_apache_program:
            apache_df = df[df["program"] == "apache"].copy()
        else:
            # Use all rows that have Apache-specific columns
            apache_df = df.copy()
        
        if apache_df.empty:
            return alerts
        
        # Extract path from message if not available
        if "path" not in apache_df.columns and "message" in apache_df.columns:
            def extract_path(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                # Extract path from: "GET /path HTTP/1.1" or "POST /path?query HTTP/1.1"
                match = re.search(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s?]+)', msg)
                return match.group(1) if match else None
            apache_df["path"] = apache_df["message"].apply(extract_path)
        
        # Use status column (may be named "status" or "http_status")
        status_col = "http_status" if "http_status" in apache_df.columns else "status"
        
        # Extract status from message if status column is empty or missing
        if status_col not in apache_df.columns or apache_df[status_col].isna().all():
            if "message" in apache_df.columns:
                def extract_status(msg):
                    if pd.isna(msg) or not isinstance(msg, str):
                        return None
                    # Extract status from: "GET /path HTTP/1.1" 200 12345
                    match = re.search(r'"\s+(\d+)\s+', msg)
                    return match.group(1) if match else None
                apache_df[status_col] = apache_df["message"].apply(extract_status)
        
        # 1. Detect Credential Stuffing (many 401 failures from same IP)
        if status_col in apache_df.columns and "source_ip" in apache_df.columns:
            apache_df["status_code"] = pd.to_numeric(apache_df[status_col], errors="coerce")
            auth_failures = apache_df[apache_df["status_code"] == 401]
            if len(auth_failures) > 20:
                unique_ips = auth_failures["source_ip"].nunique()
                unique_users = auth_failures["username"].nunique() if "username" in auth_failures.columns else 0
                alert_text = f"Credential stuffing detected: {len(auth_failures)} authentication failures from {unique_ips} IPs targeting {unique_users} users"
                alerts.append({
                    "type": "apache_credential_stuffing",
                    "subject": "Web Security",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "text": alert_text,
                    "evidence": {"auth_failures": int(len(auth_failures)), "unique_ips": int(unique_ips), "unique_users": int(unique_users)},
                    "prompt_ctx": {"behavior": {"type": "apache_credential_stuffing"}},
                })
        
        # 2. Detect Path Probing (many unique paths from same IP)
        if "path" in apache_df.columns and "source_ip" in apache_df.columns:
            ip_paths = apache_df.groupby("source_ip")["path"].nunique()
            probe_ips = ip_paths[ip_paths > 15]
            if len(probe_ips) > 0:
                max_paths = probe_ips.max()
                alert_text = f"Path probing detected: {len(probe_ips)} IPs probing {int(max_paths)} unique paths"
                alerts.append({
                    "type": "apache_path_probing",
                    "subject": "Web Security",
                    "severity": "WARNING",
                    "score": 7.0,
                    "text": alert_text,
                    "evidence": {"probe_ips": int(len(probe_ips)), "max_paths": int(max_paths)},
                    "prompt_ctx": {"behavior": {"type": "apache_path_probing"}},
                })
        
        # 3. Detect SQL Injection (SQLi patterns in path/query)
        if "path" in apache_df.columns or "message" in apache_df.columns:
            sqli_patterns = [r"union.*select", r"or\s+1\s*=\s*1", r"'.*or.*'", r"--", r";.*drop", r"exec\("]
            path_col = apache_df["path"] if "path" in apache_df.columns else apache_df["message"]
            sqli_attempts = path_col.str.contains("|".join(sqli_patterns), case=False, regex=True, na=False)
            sqli_count = sqli_attempts.sum()
            if sqli_count > 5:
                unique_ips = apache_df[sqli_attempts]["source_ip"].nunique() if "source_ip" in apache_df.columns else 0
                alert_text = f"SQL injection attempts detected: {int(sqli_count)} SQLi patterns from {int(unique_ips)} IPs"
                alerts.append({
                    "type": "apache_sqli_attempt",
                    "subject": "Web Security",
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "text": alert_text,
                    "evidence": {"sqli_attempts": int(sqli_count), "unique_ips": int(unique_ips)},
                    "prompt_ctx": {"behavior": {"type": "apache_sqli"}},
                })
        
        # Extract bytes_sent from message if not available
        if "bytes_sent" not in apache_df.columns and "message" in apache_df.columns:
            def extract_bytes(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                # Extract bytes from: "404 867" (status bytes)
                # Format: "GET /path HTTP/1.1" 200 12345
                match = re.search(r'"\s+\d+\s+(\d+)', msg)
                return match.group(1) if match else None
            apache_df["bytes_sent"] = apache_df["message"].apply(extract_bytes)
        
        # 4. Detect Data Exfiltration (large export/download files)
        if "path" in apache_df.columns and "bytes_sent" in apache_df.columns:
            export_patterns = [r"/export/", r"/download/", r"\.csv", r"\.zip", r"\.sql", r"/backup"]
            export_requests = apache_df[apache_df["path"].str.contains("|".join(export_patterns), case=False, regex=True, na=False)]
            apache_df["bytes_num"] = pd.to_numeric(apache_df["bytes_sent"], errors="coerce")
            large_exports = export_requests[export_requests["bytes_num"] > 200000]
            if len(large_exports) > 3:
                total_mb = large_exports["bytes_num"].sum() / 1024 / 1024
                unique_users = large_exports["username"].nunique() if "username" in large_exports.columns else 0
                alert_text = f"Data exfiltration via web: {len(large_exports)} large exports ({int(total_mb)}MB) by {int(unique_users)} users"
                alerts.append({
                    "type": "apache_export_exfil",
                    "subject": "Web Security",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "text": alert_text,
                    "evidence": {"large_exports": int(len(large_exports)), "total_mb": int(total_mb), "unique_users": int(unique_users)},
                    "prompt_ctx": {"behavior": {"type": "apache_exfiltration"}},
                })
        
        # 5. Detect Webshell Activity (suspicious paths: .php, admin/, config)
        if "path" in apache_df.columns:
            webshell_patterns = [r"phpinfo\.php", r"wp-login\.php", r"\.env", r"config\.php~", r"backup\.zip", r"server-status", r"\.git/config"]
            webshell_requests = apache_df[apache_df["path"].str.contains("|".join(webshell_patterns), case=False, regex=True, na=False)]
            if len(webshell_requests) > 10:
                unique_ips = webshell_requests["source_ip"].nunique() if "source_ip" in webshell_requests.columns else 0
                alert_text = f"Webshell/backdoor probing: {len(webshell_requests)} suspicious requests from {int(unique_ips)} IPs"
                alerts.append({
                    "type": "apache_webshell_probe",
                    "subject": "Web Security",
                    "severity": "CRITICAL",
                    "score": 8.5,
                    "text": alert_text,
                    "evidence": {"webshell_requests": int(len(webshell_requests)), "unique_ips": int(unique_ips)},
                    "prompt_ctx": {"behavior": {"type": "apache_webshell"}},
                })
    
    except Exception:
        pass
    
    return alerts

def _detect_firewall_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect firewall-based attacks (deny burst, exfiltration, port scan, policy evasion, rogue).
    
    Enhanced to detect:
    - Traditional firewall logs (program == "firewall")
    - UFW logs (program == "kernel" with "[UFW BLOCK]" or "[UFW ALLOW]" in message)
    """
    alerts = []
    
    # DEBUG: Check input dataframe
    import sys
    print(f"\n[DEBUG] _detect_firewall_anomalies called with {len(df)} rows", file=sys.stderr)
    print(f"[DEBUG] Columns: {df.columns.tolist()}", file=sys.stderr)
    
    # Check for both traditional firewall logs AND UFW logs
    has_firewall = "program" in df.columns and df["program"].eq("firewall").any()
    has_ufw = "message" in df.columns and df["message"].astype(str).str.contains(r"\[UFW (BLOCK|ALLOW)\]", case=False, na=False).any()
    
    print(f"[DEBUG] has_firewall={has_firewall}, has_ufw={has_ufw}", file=sys.stderr)
    
    # DEBUG: Check sample messages
    if "message" in df.columns:
        sample_messages = df["message"].head(5).tolist()
        print(f"[DEBUG] Sample messages:", file=sys.stderr)
        for i, msg in enumerate(sample_messages):
            print(f"  [{i}] {str(msg)[:150]}", file=sys.stderr)
    
    # DEBUG: Check if program column exists and its values
    if "program" in df.columns:
        programs = df["program"].unique().tolist()[:10]
        print(f"[DEBUG] Program values: {programs}", file=sys.stderr)
    
    if not has_firewall and not has_ufw:
        print(f"[DEBUG] No firewall or UFW logs found, returning empty alerts", file=sys.stderr)
        return alerts

    
    try:
        # Collect firewall-related logs
        fw_df = pd.DataFrame()
        
        # 1. Traditional firewall logs
        if has_firewall:
            fw_df = df[df["program"] == "firewall"].copy()
        
        # 2. UFW logs (kernel program with UFW patterns)
        if has_ufw:
            print(f"[DEBUG] Processing UFW logs...", file=sys.stderr)
            ufw_df = df[df["message"].astype(str).str.contains(r"\[UFW (BLOCK|ALLOW)\]", case=False, na=False)].copy()
            
            print(f"[DEBUG] Found {len(ufw_df)} UFW log entries", file=sys.stderr)
            
            # Parse UFW log fields from message
            # Example: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=113.161.72.15 DST=10.10.10.5 LEN=40 ... PROTO=TCP SPT=45678 DPT=21 ...
            if not ufw_df.empty:
                # Extract fields using regex
                ufw_df["ufw_action"] = ufw_df["message"].str.extract(r"\[UFW (BLOCK|ALLOW)\]", flags=re.IGNORECASE)[0].str.lower()
                ufw_df["source_ip"] = ufw_df["message"].str.extract(r"SRC=([0-9\.]+)")[0]
                ufw_df["dest_ip"] = ufw_df["message"].str.extract(r"DST=([0-9\.]+)")[0]
                ufw_df["dest_port"] = ufw_df["message"].str.extract(r"DPT=(\d+)")[0]
                ufw_df["protocol"] = ufw_df["message"].str.extract(r"PROTO=(\w+)")[0]
                
                # DEBUG: Show parsed fields
                print(f"[DEBUG] Parsed UFW fields:", file=sys.stderr)
                print(f"  - Actions: {ufw_df['ufw_action'].unique().tolist()}", file=sys.stderr)
                print(f"  - Source IPs: {ufw_df['source_ip'].unique().tolist()}", file=sys.stderr)
                print(f"  - Dest ports: {ufw_df['dest_port'].unique().tolist()}", file=sys.stderr)
                
                # Map UFW action to standard action column
                if "action" not in ufw_df.columns:
                    ufw_df["action"] = ufw_df["ufw_action"]
                
                # Merge with existing firewall logs if present
                if not fw_df.empty:
                    # Combine both datasets
                    fw_df = pd.concat([fw_df, ufw_df], ignore_index=True)
                else:
                    fw_df = ufw_df
        
        if fw_df.empty:
            return alerts
        
        # === UFW-SPECIFIC DETECTION: Port Scanning ===
        # Detect when same source IP scans multiple destination ports
        if "dest_port" in fw_df.columns and "source_ip" in fw_df.columns:
            fw_df["dest_port_num"] = pd.to_numeric(fw_df["dest_port"], errors="coerce")
            
            # Group by source IP and count unique ports scanned
            src_ports = fw_df[fw_df["dest_port_num"].notna()].groupby("source_ip")["dest_port_num"].agg(["nunique", "count", lambda x: sorted(x.unique().tolist())])
            src_ports.columns = ["unique_ports", "total_attempts", "ports_list"]
            
            # Port scan threshold: 5+ unique ports from same IP = suspicious
            scan_sources = src_ports[src_ports["unique_ports"] >= 5]
            
            if len(scan_sources) > 0:
                for src_ip, row in scan_sources.iterrows():
                    unique_ports = int(row["unique_ports"])
                    total_attempts = int(row["total_attempts"])
                    ports_list = row["ports_list"][:10]  # First 10 ports
                    
                    alert_text = f"Port scanning detected from {src_ip}: scanned {unique_ports} unique ports in {total_attempts} attempts. Ports: {ports_list}"
                    alerts.append({
                        "type": "firewall_portscan",
                        "subject": str(src_ip),
                        "severity": "CRITICAL" if unique_ports >= 10 else "WARNING",
                        "score": min(7.0 + (unique_ports / 10), 10.0),
                        "text": alert_text,
                        "evidence": {
                            "source_ip": str(src_ip),
                            "unique_ports": unique_ports,
                            "total_attempts": total_attempts,
                            "ports_scanned": [int(p) for p in ports_list if pd.notna(p)]
                        },
                        "prompt_ctx": {"behavior": {"type": "firewall_portscan", "source_ip": str(src_ip), "ports": unique_ports}},
                    })
        
        # === UFW-SPECIFIC DETECTION: Deny/Block Bursts ===
        # Detect high volume of blocked connections
        if "action" in fw_df.columns or "ufw_action" in fw_df.columns:
            action_col = "ufw_action" if "ufw_action" in fw_df.columns else "action"
            
            # Count BLOCK/DENY events
            deny_mask = fw_df[action_col].astype(str).str.lower().isin(["block", "deny"])
            deny_count = deny_mask.sum()
            
            if deny_count >= 5:  # Lowered threshold for UFW (was 30 for traditional firewall)
                denied_df = fw_df[deny_mask]
                unique_sources = denied_df["source_ip"].nunique() if "source_ip" in denied_df.columns else 0
                unique_dests = denied_df["dest_ip"].nunique() if "dest_ip" in denied_df.columns else 0
                
                # Get top source IPs
                top_sources = []
                if "source_ip" in denied_df.columns:
                    top_sources = denied_df["source_ip"].value_counts().head(3).index.tolist()
                
                alert_text = f"Firewall DENY/BLOCK burst detected: {int(deny_count)} blocked connections from {int(unique_sources)} source IPs to {int(unique_dests)} destinations. Top sources: {top_sources}"
                alerts.append({
                    "type": "firewall_deny_burst",
                    "subject": "Firewall Security",
                    "severity": "CRITICAL" if deny_count >= 20 else "WARNING",
                    "score": min(6.0 + (deny_count / 10), 10.0),
                    "text": alert_text,
                    "evidence": {
                        "deny_count": int(deny_count),
                        "unique_sources": int(unique_sources),
                        "unique_destinations": int(unique_dests),
                        "top_source_ips": [str(ip) for ip in top_sources]
                    },
                    "prompt_ctx": {"behavior": {"type": "firewall_deny_burst", "count": int(deny_count)}},
                })
        
        # === TRADITIONAL FIREWALL DETECTIONS (kept for backward compatibility) ===
        
        # 3. Detect Exfiltration (high bytes to external destinations)
        if "bytes_sent" in fw_df.columns and "dest_ip" in fw_df.columns:
            fw_df["bytes_num"] = pd.to_numeric(fw_df["bytes_sent"], errors="coerce")
            high_traffic = fw_df[fw_df["bytes_num"] > 200000]
            if len(high_traffic) > 5:
                total_bytes = high_traffic["bytes_num"].sum()
                unique_dests = high_traffic["dest_ip"].nunique()
                alert_text = f"Data exfiltration suspected: {len(high_traffic)} high-volume transfers ({int(total_bytes/1024/1024)}MB) to {unique_dests} destinations"
                alerts.append({
                    "type": "firewall_exfiltration",
                    "subject": "Firewall Security",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "text": alert_text,
                    "evidence": {"high_traffic_count": int(len(high_traffic)), "total_mb": int(total_bytes/1024/1024)},
                    "prompt_ctx": {"behavior": {"type": "firewall_exfiltration"}},
                })
        
        # 4. Detect Policy Evasion (unusual port/protocol combinations)
        if "dest_port" in fw_df.columns and "protocol" in fw_df.columns:
            # Check for suspicious port/protocol pairs
            fw_df["dest_port_num"] = pd.to_numeric(fw_df["dest_port"], errors="coerce")
            suspicious = fw_df[
                ((fw_df["dest_port_num"] != 22) & (fw_df["protocol"] == "TCP")) |
                ((fw_df["dest_port_num"] != 25) & (fw_df["protocol"] == "TCP"))
            ]
            if len(suspicious) > 10:
                alert_text = f"Policy evasion detected: {len(suspicious)} unusual protocol/port combinations"
                alerts.append({
                    "type": "firewall_policy_evasion",
                    "subject": "Firewall Security",
                    "severity": "WARNING",
                    "score": 6.5,
                    "text": alert_text,
                    "evidence": {"suspicious_count": int(len(suspicious))},
                    "prompt_ctx": {"behavior": {"type": "firewall_policy_evasion"}},
                })
        
        # 5. Detect Rogue Internal Activity (internal-to-internal with unusual rules)
        if "username" in fw_df.columns and "device" in fw_df.columns and "source_ip" in fw_df.columns:
            internal_flow = fw_df[fw_df["source_ip"].str.startswith(("10.", "172.", "192."), na=False)]
            if len(internal_flow) > 0:
                # Check for users accessing unusual admin destinations
                admin_dests = internal_flow[internal_flow["dest_ip"].str.contains("40\\.40\\.|40\\.30\\.", regex=True, na=False)]
                if len(admin_dests) > 20:
                    unique_users = admin_dests["username"].nunique()
                    alert_text = f"Rogue internal activity: {len(admin_dests)} suspicious admin destination accesses by {unique_users} users"
                    alerts.append({
                        "type": "firewall_rogue_internal",
                        "subject": "Firewall Security",
                        "severity": "CRITICAL",
                        "score": 8.0,
                        "text": alert_text,
                        "evidence": {"admin_accesses": int(len(admin_dests)), "unique_users": int(unique_users)},
                        "prompt_ctx": {"behavior": {"type": "firewall_rogue_internal"}},
                    })
    
    except Exception as e:
        import sys
        print(f"[DEBUG] Firewall anomaly detection error: {e}", file=sys.stderr)
        pass
    
    return alerts


def _detect_dns_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect DNS-based attacks (amplification, DGA, NXDOMAIN storm, tunneling)."""
    alerts = []
    
    if "program" not in df.columns or not df["program"].eq("dnsmasq").any():
        return alerts
    
    try:
        dns_df = df[df["program"] == "dnsmasq"].copy()
        if dns_df.empty:
            return alerts
        
        # 1. Detect LARGE_ANSWER / NSEC amplification (DNS amplification attack)
        large_answers = dns_df[dns_df["status"] == "large_answer"]
        if len(large_answers) > 5:
            unique_sources = large_answers["source_ip"].nunique()
            alert_text = f"DNS amplification suspicious: {len(large_answers)} LARGE_ANSWER/NSEC responses detected from {unique_sources} clients"
            alerts.append({
                "type": "dns_amplification_spike",
                "subject": "DNS Network",
                "severity": "CRITICAL",
                "score": 8.5,
                "text": alert_text,
                "evidence": {"large_answers": int(len(large_answers)), "unique_sources": int(unique_sources)},
                "prompt_ctx": {"behavior": {"type": "dns_amplification"}},
            })
        
        # 2. Detect NXDOMAIN flood
        nxdomains = dns_df[dns_df["status"] == "nxdomain"]
        if len(nxdomains) > 10:
            unique_sources = nxdomains["source_ip"].nunique()
            alert_text = f"DNS NXDOMAIN flood: {len(nxdomains)} NXDOMAIN responses from {unique_sources} sources"
            alerts.append({
                "type": "dns_nxdomain_flood",
                "subject": "DNS Network",
                "severity": "WARNING",
                "score": 6.5,
                "text": alert_text,
                "evidence": {"nxdomains": int(len(nxdomains)), "unique_sources": int(unique_sources)},
                "prompt_ctx": {"behavior": {"type": "dns_nxdomain_flood"}},
            })
        
        # 3. Detect suspicious domains (high entropy, common DGA patterns)
        if "domain" in dns_df.columns:
            domains = dns_df["domain"].dropna().astype(str).unique()
            suspicious_count = 0
            suspicious_domains = []
            for domain in domains[:50]:  # Check first 50 unique domains
                # Simple heuristic: random-looking domains (high entropy)
                if len(domain) > 20 or (len(domain) > 10 and not any(c in domain.lower() for c in "aeiou")):
                    suspicious_count += 1
                    suspicious_domains.append(domain)
            
            if suspicious_count >= 3:
                alert_text = f"Potential DGA/Suspicious domains detected: {suspicious_count} domains with unusual patterns"
                alerts.append({
                    "type": "dns_suspicious_domains",
                    "subject": "DNS Network",
                    "severity": "WARNING",
                    "score": 7.0,
                    "text": alert_text,
                    "evidence": {"suspicious_domain_count": suspicious_count, "examples": suspicious_domains[:3]},
                    "prompt_ctx": {"behavior": {"type": "dns_dga"}},
                })
        
        # 4. Detect DNS tunneling (data exfiltration via TXT records)
        if "domain" in dns_df.columns and "query_type" in dns_df.columns:
            txt_queries = dns_df[(dns_df["query_type"] == "TXT") & (dns_df["domain"].str.contains("_dns|exfil|tunnel", case=False, na=False))]
            if len(txt_queries) > 0:
                alert_text = f"DNS tunneling/exfiltration detected: {len(txt_queries)} TXT queries with suspicious patterns"
                alerts.append({
                    "type": "dns_tunneling_exfil",
                    "subject": "DNS Network",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "text": alert_text,
                    "evidence": {"txt_queries": int(len(txt_queries))},
                    "prompt_ctx": {"behavior": {"type": "dns_tunneling"}},
                })
    
    except Exception:
        pass
    
    return alerts

def generate_raw_anomalies(df: pd.DataFrame, baselines_dir: str) -> List[Dict[str, Any]]:
    """
    Step-2 generator: compare current window against stored baselines to produce human-readable alerts.
    Returns a list of dicts {type, subject, severity, score, text, evidence}
    
    This improved version handles mixed logs (normal + attack) by using multiple detection strategies:
    1. Pattern-based detection (high-confidence attacks)
    2. Statistical deviation from baseline
    3. Behavioral anomalies (spike detection)
    """
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return []
    df = _to_dt_utc(df)

    base = _load_baseline_tables(baselines_dir)
    us = base.get("user_stats")
    user_stats = us if isinstance(us, pd.DataFrame) else pd.DataFrame()
    if not user_stats.empty:
        # Normalize username dtype to string to avoid object/float merge conflicts
        if "username" in user_stats.columns:
            user_stats = user_stats.copy()
            user_stats["username"] = user_stats["username"].astype(str)
    gs = base.get("global_stats")
    global_stats = gs if isinstance(gs, dict) else {}

    alerts: List[Dict[str, Any]] = []

    # ===== SECTION 0: ENHANCED DETECTION FOR MIXED LOGS =====
    
    # 0A) SSH Brute Force Detection - detect rapid SSH attempts
    if "action" in df.columns and "status" in df.columns and "username" in df.columns:
        try:
            ssh_logs = df[df.get("program", pd.Series(index=df.index)).astype(str).str.contains("sshd", case=False, na=False) |
                         df.get("action", pd.Series(index=df.index)).astype(str).str.contains("login|logon", case=False, na=False)]
            if not ssh_logs.empty:
                # Group by source IP and count failures/attempts
                for src_ip, group in ssh_logs.groupby("source_ip"):
                    if pd.isna(src_ip) or str(src_ip).strip() == "":
                        continue
                    src_ip = str(src_ip)
                    
                    # Count failed logins
                    failed = group[group["status"].astype(str).str.lower().str.contains("fail|denied", na=False)]
                    total = len(group)
                    
                    if total >= 5 and len(failed) >= 3:  # at least 3 failures in 5+ attempts
                        failure_rate = len(failed) / total
                        if failure_rate >= 0.4:  # 40%+ failure rate
                            ctx = {
                                "user": None,
                                "group": None,
                                "behavior": {"type": "ssh_bruteforce", "source_ip": src_ip, "attempts": total, "failures": len(failed)},
                                "time": None,
                                "baseline": {"expected_failure_rate": 0.1},
                                "extras": {"reason": f"High SSH login failure rate from {src_ip}"},
                            }
                            alerts.append({
                                "type": "ssh_bruteforce_detected",
                                "subject": src_ip,
                                "severity": "CRITICAL" if failure_rate > 0.7 else "WARNING",
                                "score": min(failure_rate * 10, 10.0),
                                "text": f"SSH brute force detected from IP {src_ip}: {len(failed)}/{total} failed attempts ({failure_rate:.1%} failure rate).",
                                "evidence": {"source_ip": src_ip, "total_attempts": int(total), "failed_attempts": int(len(failed)), "failure_rate": float(failure_rate)},
                                "prompt_ctx": ctx,
                            })
        except Exception:
            pass
    
    # 0C) Data Exfiltration Detection - detect large file transfers
    if "message" in df.columns:
        try:
            detected_transfers = {}  # (username, bytes) -> bool to avoid duplicates
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", ""))  # Keep case for better matching
                hostname = str(row.get("hostname", "(unknown)")).strip()
                timestamp = row.get("timestamp")
                
                # Pattern 1: scp format like "huydev -> 203.0.113.55:/tmp/huydev.tar.gz bytes=879328811 status=OK"
                # Simplified: look for "bytes=XXXXXX" pattern after IP address
                scp_match = None
                bytes_val = 0
                username = None
                dest_ip = None
                
                bytes_match = re.search(r'bytes=(\d+)', msg)
                if bytes_match and ' -> ' in msg:
                    try:
                        bytes_val = int(bytes_match.group(1))
                        # Extract username and IP from pattern "user -> IP:"
                        arrow_match = re.search(r'([a-zA-Z0-9_\-]+)\s*->\s+([0-9\.]+):', msg)
                        if arrow_match:
                            username = arrow_match.group(1)
                            dest_ip = arrow_match.group(2)
                            scp_match = True
                    except Exception:
                        pass
                
                if scp_match:
                    # Flag any scp > 50MB (data exfiltration indicator)
                    if bytes_val and bytes_val > 50_000_000:
                        key = (username, "scp", bytes_val)
                        if key not in detected_transfers:
                            detected_transfers[key] = True
                            
                            ctx = {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "data_exfiltration", "bytes": bytes_val, "destination": dest_ip},
                                "time": _fmt_local_vn(timestamp),
                                "baseline": {"max_normal_transfer": "50MB"},
                                "extras": {"reason": f"Large SCP transfer detected: {bytes_val / 1_000_000:.1f}MB to {dest_ip}"},
                            }
                            alerts.append({
                                "type": "data_exfiltration_detected",
                                "subject": username,
                                "severity": "CRITICAL",
                                "score": min((bytes_val / 100_000_000) * 9.5, 10.0),
                                "text": f"[CRITICAL] DATA EXFILTRATION: User '{username}' transferred {bytes_val / 1_000_000:.1f}MB to {dest_ip}",
                                "evidence": {"user": username, "bytes": int(bytes_val), "destination": dest_ip, "method": "scp", "hostname": hostname},
                                "prompt_ctx": ctx,
                            })
                
                # Pattern 2: NETFILTER_PKT for large network transfers
                netfilter_match = re.search(r'NETFILTER_PKT\s+len=(\d+)\s+dst=([0-9\.]+)', msg)
                if netfilter_match:
                    bytes_val = int(netfilter_match.group(1))
                    dest_ip = netfilter_match.group(2)
                    # Flag if > 50MB
                    if bytes_val > 50_000_000:
                        username = str(row.get("username", hostname)).strip()
                        if not username:
                            username = hostname
                        
                        key = (username, "netfilter", bytes_val, dest_ip)
                        if key not in detected_transfers:
                            detected_transfers[key] = True
                            
                            ctx = {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "data_exfiltration", "bytes": bytes_val, "destination": dest_ip},
                                "time": _fmt_local_vn(timestamp),
                                "baseline": {"max_normal_transfer": "50MB"},
                                "extras": {"reason": f"Large network transfer detected: {bytes_val / 1_000_000:.1f}MB"},
                            }
                            alerts.append({
                                "type": "data_exfiltration_detected",
                                "subject": hostname,
                                "severity": "CRITICAL",
                                "score": min((bytes_val / 100_000_000) * 9.0, 10.0),
                                "text": f"[CRITICAL] DATA EXFILTRATION: Large network transfer {bytes_val / 1_000_000:.1f}MB from {hostname} to {dest_ip}",
                                "evidence": {"bytes": int(bytes_val), "destination": dest_ip, "source_host": hostname, "method": "network"},
                                "prompt_ctx": ctx,
                            })
        except Exception as e:
            import sys
            print(f"[DEBUG] Data exfiltration detection error: {e}", file=sys.stderr)
            pass
    
    # 0D) Privilege Escalation Detection - detect suspicious sudo usage
    if "action" in df.columns or "message" in df.columns:
        try:
            priv_escalation_patterns = [
                (r"sudo.*usermod.*sudo", "add_sudo_user", 8.0),
                (r"chmod\s+u\+s\s+/bin/bash", "suid_bash", 9.0),
                (r"visudo.*-f\s+/etc/sudoers", "sudoers_edit", 8.5),
                (r"chown\s+root.*bash", "bash_ownership_change", 8.0),
            ]
            
            detected_privesc = {}  # (username, pattern) -> bool to avoid duplicates
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", "")).lower()
                username = str(row.get("username", "(unknown)")).strip()
                if not username:
                    username = "(unknown)"
                timestamp = row.get("timestamp")
                
                for pattern, pattern_name, score in priv_escalation_patterns:
                    if re.search(pattern, msg, re.IGNORECASE):
                        key = (username, pattern_name)
                        if key in detected_privesc:
                            continue
                        detected_privesc[key] = True
                        
                        ctx = {
                            "user": username,
                            "group": None,
                            "behavior": {"type": "privilege_escalation", "method": pattern_name},
                            "time": _fmt_local_vn(timestamp),
                            "baseline": {},
                            "extras": {"reason": f"Privilege escalation attempt detected"},
                        }
                        alerts.append({
                            "type": "privilege_escalation_detected",
                            "subject": username,
                            "severity": "CRITICAL",
                            "score": score,
                            "text": f"Privilege escalation by {username}: {msg[:200]}",
                            "evidence": {"method": pattern_name, "message": msg[:300]},
                            "prompt_ctx": ctx,
                        })
        except Exception:
            pass
    
    # -1) Detect PERSISTENCE TECHNIQUES (before baseline detection)
    # These are high-confidence indicators of compromise
    if "message" in df.columns and "username" in df.columns:
        try:
            # Persistence patterns: crontab modification, reverse shells, rc.local, SSH key injection, etc
            persistence_patterns = [
                {
                    "name": "crontab_modification",
                    "pattern": r"crontab\s+[-l]*[;\s]*echo.*\|.*crontab\s+[-]?|crontab.*curl.*bash",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "description": "Crontab persistence - adding malicious cron job"
                },
                {
                    "name": "reverse_shell_bashrc",
                    "pattern": r"bash\s+-i\s*[>&]*\s*/dev/tcp/.*>>\s*~?/.bashrc|bash\s+-i\s+>?&?\s*/dev/tcp",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "description": "Reverse shell via ~/.bashrc - shell modification persistence"
                },
                {
                    "name": "rc_local_persistence",
                    "pattern": r"systemctl\s+enable\s+rc-local|/etc/rc\.local",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "description": "RC.local persistence - system startup modification"
                },
                {
                    "name": "ssh_key_injection",
                    "pattern": r"authorized_keys|~?/.ssh/[^ ]*",
                    "severity": "CRITICAL",
                    "score": 8.5,
                    "description": "SSH key manipulation - persistence via SSH"
                },
                {
                    "name": "curl_exec_pattern",
                    "pattern": r"curl\s+(?:-s)?\s*http[s]?://.*[|]\s*(?:bash|sh)",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "description": "Remote code execution via curl - downloading and executing remote script"
                },
                {
                    "name": "suspicious_persistence_msg",
                    "pattern": r"suspicious\s+persistence",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "description": "Log contains explicit 'suspicious persistence' indicator"
                }
            ]
            
            # Track already detected persistence to avoid duplicates
            detected_persistence = {}  # (username, pattern_name) -> bool
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", "")).lower()
                raw_username = row.get("username")
                
                # Convert None/NaN to "(unknown)"
                if raw_username is None or (isinstance(raw_username, float) and pd.isna(raw_username)):
                    username = "(unknown)"
                else:
                    username = str(raw_username).strip()
                    if not username:
                        username = "(unknown)"
                
                timestamp = row.get("timestamp")
                
                # Check each persistence pattern
                for pattern_def in persistence_patterns:
                    pattern_name = pattern_def["name"]
                    pattern_regex = pattern_def["pattern"]
                    
                    # Skip if already detected for this user+pattern combination
                    key = (username, pattern_name)
                    if key in detected_persistence:
                        continue
                    
                    # Check if message matches pattern
                    if re.search(pattern_regex, msg, re.IGNORECASE):
                        detected_persistence[key] = True
                        
                        ctx = {
                            "user": username,
                            "group": None,
                            "behavior": {
                                "type": "persistence_technique",
                                "technique": pattern_name,
                                "command": msg[:200],  # First 200 chars
                            },
                            "time": _fmt_local_vn(timestamp),
                            "baseline": {},
                            "extras": {"reason": pattern_def["description"]},
                        }
                        
                        # Try to extract group
                        try:
                            if "group" in df.columns:
                                g = df[df["username"].astype(str)==username]["group"].dropna().astype(str).unique()
                                if len(g):
                                    ctx["group"] = g[0]
                        except Exception:
                            pass
                        
                        alerts.append({
                            "type": "persistence_technique_detected",
                            "subject": username,
                            "severity": pattern_def["severity"],
                            "score": pattern_def["score"],
                            "text": f"🚨 PHÁT HIỆN: {pattern_def['description']} từ user '{username}': {msg[:150]}",
                            "evidence": {
                                "pattern": pattern_name,
                                "command": msg[:200],
                                "technique_description": pattern_def["description"],
                            },
                            "prompt_ctx": ctx,
                        })
        except Exception as e:
            pass

    # 0.5) Detect suspicious data access patterns using BASELINE comparison (NOT heuristic)
    if "message" in df.columns and "username" in df.columns:
        try:
            # Extract current data access features per user (same as baseline extraction)
            current_user_activity = {}  # user -> {db_queries, suspicious_ops, timestamps}
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", "")).lower()
                raw_username = row.get("username")
                # Convert None/NaN to "(unknown)"
                if raw_username is None or (isinstance(raw_username, float) and pd.isna(raw_username)):
                    username = "(unknown)"
                else:
                    username = str(raw_username).strip()
                    if not username:
                        username = "(unknown)"
                
                timestamp = row.get("timestamp")
                
                if username not in current_user_activity:
                    current_user_activity[username] = {
                        "db_queries": 0,
                        "suspicious_ops": 0,
                        "timestamps": []
                    }
                
                # Create explicit masks to avoid double-counting
                # Suspicious mask: pg_dump, COPY TO, ALTER ROLE, GRANT, etc (admin operations)
                susp_mask = re.search(r"(pg_dump|mysqldump|COPY\s+TO|ALTER\s+ROLE|GRANT|REVOKE|DROP\s+\w+)", 
                                     msg, re.IGNORECASE)
                
                # Query mask: SELECT/INSERT/UPDATE/DELETE but EXCLUDE if suspicious operation
                query_mask = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|export|backup)\b", msg, re.IGNORECASE)
                
                # 1) Count NORMAL DB queries (only if NOT suspicious operation)
                if query_mask and not susp_mask:
                    current_user_activity[username]["db_queries"] += 1
                
                # 2) Count suspicious operations (EXCLUSIVE - not counted in queries)
                if susp_mask:
                    current_user_activity[username]["suspicious_ops"] += 1
                
                current_user_activity[username]["timestamps"].append(timestamp)
            
            # Compare against baseline using Z-score
            if not user_stats.empty:
                for user, activity in current_user_activity.items():
                    # Resolve unknown user from sudo logs if possible
                    display_user = _resolve_unknown_user(df, user)
                    
                    # Try to match known user for baseline comparison
                    lookup_user = user
                    if str(user).strip() == "(unknown)":
                        # Try to resolve to a known user
                        resolved = _resolve_unknown_user(df, user)
                        if resolved != user:  # Successfully resolved
                            # Extract the real user from "unknown(via linhfin)" format
                            if "(via " in resolved:
                                real_user = resolved.split("(via ")[1].rstrip(")")
                                lookup_user = real_user
                    
                    user_row = user_stats[user_stats["username"].astype(str) == str(lookup_user)]
                    
                    if user_row.empty:
                        # Unknown user detected - will be handled by section 0
                        continue
                    
                    # Extract baseline mean and std for data access features
                    db_queries_mean = user_row.get("db_queries_mean", pd.Series([0.0]))[0] or 0.0
                    db_queries_std = user_row.get("db_queries_std", pd.Series([0.1]))[0] or 0.1
                    suspicious_ops_mean = user_row.get("suspicious_ops_mean", pd.Series([0.0]))[0] or 0.0
                    suspicious_ops_std = user_row.get("suspicious_ops_std", pd.Series([0.1]))[0] or 0.1
                    
                    current_queries = activity["db_queries"]
                    current_suspicious = activity["suspicious_ops"]
                    
                    # Calculate Z-scores with robust std dev (avoid extreme values when baseline std ≈ 0)
                    # Use floor of 1.0 for std dev to prevent division inflation
                    safe_db_std = max(db_queries_std, 1.0)
                    safe_susp_std = max(suspicious_ops_std, 1.0)
                    
                    z_queries = (current_queries - db_queries_mean) / safe_db_std
                    z_suspicious = (current_suspicious - suspicious_ops_mean) / safe_susp_std
                    
                    # NORMALIZE Z-scores: clamp extreme values but preserve rank
                    # Prevent Z=100 by clamping at 8.0 (statistical significant threshold)
                    z_queries_norm = min(max(z_queries, 0), 8.0)  # Clamp to 0-8 range
                    z_suspicious_norm = min(max(z_suspicious, 0), 8.0)
                    
                    # Detect anomaly: Z-score >= 3.0 AND above baseline
                    anomaly_detected = False
                    anomaly_score = 0.0
                    reason_parts = []
                    
                    triggers_count = 0  # Count how many anomaly triggers
                    
                    if z_queries >= 3.0 and current_queries > db_queries_mean:
                        anomaly_detected = True
                        triggers_count += 1
                        anomaly_score += z_queries_norm * 0.8  # Don't weight too high initially
                        reason_parts.append(f"Database queries tăng đột ngột: {current_queries} (baseline: {db_queries_mean:.1f}±{db_queries_std:.1f}, Z={z_queries_norm:.2f})")
                    
                    if z_suspicious >= 3.0 and current_suspicious > suspicious_ops_mean:
                        anomaly_detected = True
                        triggers_count += 1
                        anomaly_score += z_suspicious_norm * 1.2  # Weight suspicious ops higher (1.2x)
                        reason_parts.append(f"Suspicious operations: {current_suspicious} (baseline: {suspicious_ops_mean:.1f}±{suspicious_ops_std:.1f}, Z={z_suspicious_norm:.2f})")
                    
                    if anomaly_detected:
                        ctx = {
                            "user": user,
                            "group": None,
                            "behavior": {
                                "type": "anomalous_data_access",
                                "db_queries_current": current_queries,
                                "db_queries_baseline": db_queries_mean,
                                "suspicious_ops_current": current_suspicious,
                                "suspicious_ops_baseline": suspicious_ops_mean,
                            },
                            "time": None,
                            "baseline": {
                                "db_queries_mean": db_queries_mean,
                                "db_queries_std": db_queries_std,
                                "suspicious_ops_mean": suspicious_ops_mean,
                                "suspicious_ops_std": suspicious_ops_std,
                            },
                            "extras": {"reason": "; ".join(reason_parts)},
                        }
                        
                        # UNIFIED Score → Severity Mapping
                        # Calculate final score: 1.25x multiplier prevents under-scoring
                        base_score = min(max(anomaly_score, 0.0), 10.0)
                        
                        # Apply trigger-based boost
                        if triggers_count == 2:
                            # Dual triggers = more severe (boost by 1.3x)
                            final_score = min(base_score * 1.3, 10.0)  # Dual trigger boost
                        else:
                            # Single trigger (no boost)
                            final_score = min(base_score * 1.0, 10.0)
                        
                        # Ensure minimum for any detected anomaly
                        final_score = max(final_score, 4.0)
                        
                        # Map score to severity (UNIFIED)
                        # Note: Use only CRITICAL, WARNING, INFO for consistency with frontend
                        if final_score >= 8.0:
                            severity = "CRITICAL"
                        elif final_score >= 6.0:
                            severity = "CRITICAL"  # HIGH mapped to CRITICAL for consistency
                        elif final_score >= 4.0:
                            severity = "WARNING"
                        else:
                            severity = "INFO"
                        
                        alerts.append({
                            "type": "anomalous_data_access",
                            "subject": display_user,
                            "severity": severity,
                            "score": final_score,
                            "text": f"Phát hiện hoạt động truy cập dữ liệu bất thường từ user '{display_user}': {'; '.join(reason_parts)}",
                            "evidence": {
                                "user": display_user,
                                "db_queries": int(current_queries),
                                "db_queries_baseline": float(db_queries_mean),
                                "suspicious_ops": int(current_suspicious),
                                "suspicious_ops_baseline": float(suspicious_ops_mean),
                                "z_queries": float(z_queries),
                                "z_suspicious": float(z_suspicious),
                                "anomaly_score": anomaly_score,
                                "final_score": final_score,
                            },
                            "prompt_ctx": ctx,
                        })
        except Exception as e:
            pass
    
    # 0) Detect new/unknown users (not in baseline)
    if not user_stats.empty and "username" in df.columns:
        known_users = set(user_stats["username"].astype(str).unique())
        current_users = set(df["username"].dropna().astype(str).unique())
        new_users = current_users - known_users - {"nan", "None", ""}
        for nu in new_users:
            user_events = len(df[df["username"].astype(str) == nu])
            if user_events >= 3:  # at least 3 events to reduce noise
                ctx = {
                    "user": nu,
                    "group": None,
                    "behavior": {"type": "new_user", "events": user_events},
                    "time": None,
                    "baseline": {},
                    "extras": {"reason": "User chưa có trong baseline"},
                }
                try:
                    g = df[df["username"].astype(str)==nu]["group"].dropna().astype(str).unique()
                    if len(g):
                        ctx["group"] = g[0]
                except Exception:
                    pass
                alerts.append({
                    "type": "new_user",
                    "subject": nu,
                    "severity": "WARNING",
                    "score": 4.0,
                    "text": f"User mới {nu} xuất hiện với {user_events} sự kiện, chưa có trong baseline.",
                    "evidence": {"events": int(user_events)},
                    "prompt_ctx": ctx,
                })

    # 0F) Web Authentication Failures - detect multiple failed HTTP auth attempts
    if "http_status" in df.columns and "action" in df.columns and "username" in df.columns:
        try:
            # HTTP auth failures: 401, 403
            http_logs = df[df.get("action", pd.Series(index=df.index)).astype(str).str.contains("access|get|post|put|delete", case=False, na=False)]
            if not http_logs.empty:
                for username, group in http_logs.groupby("username"):
                    username = str(username).strip()
                    if not username or username in ["(unknown)", "nan", ""]:
                        continue
                    
                    http_status = pd.to_numeric(group["http_status"], errors="coerce")
                    auth_failures = http_status[http_status.isin([401, 403])]
                    total_requests = len(group)
                    
                    if total_requests >= 5 and len(auth_failures) >= 3:
                        failure_rate = len(auth_failures) / total_requests
                        if failure_rate >= 0.3:  # 30%+ auth failure rate
                            ctx = {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "web_auth_failure", "failures": len(auth_failures), "total": total_requests},
                                "time": None,
                                "baseline": {"expected_auth_failure_rate": 0.05},
                                "extras": {"reason": f"Elevated HTTP authentication failure rate"},
                            }
                            alerts.append({
                                "type": "web_auth_failure_spike",
                                "subject": username,
                                "severity": "WARNING" if failure_rate < 0.5 else "CRITICAL",
                                "score": min(failure_rate * 8, 10.0),
                                "text": f"User {username} experienced {len(auth_failures)}/{total_requests} HTTP auth failures ({failure_rate:.1%} rate).",
                                "evidence": {"failures": int(len(auth_failures)), "total_requests": int(total_requests), "failure_rate": float(failure_rate)},
                                "prompt_ctx": ctx,
                            })
        except Exception:
            pass
    
    # 0G) Sensitive Database Access Detection - detect abnormal database operations
    if "message" in df.columns and "username" in df.columns:
        try:
            db_access_patterns = [
                (r"pg_dump|mysqldump", "database_dump", 7.0),
                (r"SELECT\s+\*\s+FROM\s+\w*user", "user_table_access", 6.0),
                (r"ALTER\s+ROLE|ALTER\s+USER", "user_modification", 7.0),
                (r"DROP\s+TABLE|DROP\s+DATABASE", "destructive_operation", 9.0),
            ]
            
            db_alerts = {}  # (username, pattern) -> bool
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", "")).lower()
                username = str(row.get("username", "(unknown)")).strip()
                if not username:
                    username = "(unknown)"
                timestamp = row.get("timestamp")
                
                for pattern, pattern_name, score in db_access_patterns:
                    if re.search(pattern, msg, re.IGNORECASE):
                        key = (username, pattern_name)
                        if key in db_alerts:
                            continue
                        db_alerts[key] = True
                        
                        ctx = {
                            "user": username,
                            "group": None,
                            "behavior": {"type": "database_access", "operation": pattern_name},
                            "time": _fmt_local_vn(timestamp),
                            "baseline": {},
                            "extras": {"reason": f"Sensitive database operation detected"},
                        }
                        alerts.append({
                            "type": "sensitive_db_access_detected",
                            "subject": username,
                            "severity": "CRITICAL" if score >= 8 else "WARNING",
                            "score": score,
                            "text": f"Sensitive database operation by {username}: {msg[:200]}",
                            "evidence": {"operation": pattern_name, "message": msg[:300]},
                            "prompt_ctx": ctx,
                        })
        except Exception:
            pass

    # 1) User download spike (Z-score against daily baseline if available)
    dl = _count_user_downloads(df)
    if not dl.empty and not user_stats.empty:
        # Ensure left side username is string
        if "username" in dl.columns:
            dl = dl.copy()
            dl["username"] = dl["username"].astype(str)
        # try to find per-user daily mean/std approximations from baseline columns if exist
        # fall back to overall events_mean/std if specific download stats absent
        mean_col = None
        std_col = None
        for m, s in [("files_downloaded_mean","files_downloaded_std"), ("events_mean","events_std")]:
            if m in user_stats.columns and s in user_stats.columns:
                mean_col, std_col = m, s
                break
        if mean_col is None:
            # try flatten multi-indexed names like 'events_mean'
            mean_candidates = [c for c in user_stats.columns if c.endswith("_mean")]
            std_candidates = [c for c in user_stats.columns if c.endswith("_std")]
            if ("events_mean" in mean_candidates) and ("events_std" in std_candidates):
                mean_col, std_col = "events_mean", "events_std"

        if mean_col and std_col and "username" in user_stats.columns:
            merged = dl.merge(user_stats[["username", mean_col, std_col]], on="username", how="left")
            for row in merged.itertuples(index=False):
                u = getattr(row, "username")
                cur = getattr(row, "files_downloaded")
                mu = getattr(row, mean_col) if hasattr(row, mean_col) else None
                sd = getattr(row, std_col) if hasattr(row, std_col) else None
                z = _safe_z(cur, mu if mu is not None else 0.0, sd if sd is not None else 0.0)
                if z >= 3.0 and cur >= 5:
                    # build prompt-ready context
                    ctx = {
                        "user": u,
                        "group": None,
                        "behavior": {
                            "type": "download",
                            "files": int(cur),
                            "bytes": None,
                            "resource": None,
                        },
                        "time": None,
                        "baseline": {
                            "user_daily_download_mean": float(mu or 0),
                            "user_daily_download_std": float(sd or 0),
                            "working_hours": None,
                        },
                        "extras": {},
                    }
                    # Try enrich group from current df
                    try:
                        g = (
                            df[df.get("username").astype(str)==str(u)]["group"].dropna().astype(str).unique()
                            if "group" in df.columns else []
                        )
                        if len(g):
                            ctx["group"] = g[0]
                    except Exception:
                        pass
                    # working hours if available in baseline (p10/p90 hours)
                    try:
                        if "p10" in user_stats.columns and "p90" in user_stats.columns:
                            row_u = user_stats[user_stats["username"].astype(str)==str(u)].head(1)
                            if not row_u.empty:
                                p10 = row_u.iloc[0].get("p10")
                                p90 = row_u.iloc[0].get("p90")
                                if pd.notna(p10) and pd.notna(p90):
                                    ctx["baseline"]["working_hours"] = f"{int(p10)}h–{int(p90)}h"
                    except Exception:
                        pass
                    alerts.append({
                        "type": "user_download_spike",
                        "subject": u,
                        "severity": "WARNING" if z < 5 else "CRITICAL",
                        "score": float(z),
                        "text": f"User {u} đã tải xuống {cur} file trong khoảng thời gian phân tích. Trung bình lịch sử là {mu:.0f}±{sd:.0f} (Z={z:.2f}).",
                        "evidence": {"current": int(cur), "mean": float(mu or 0), "std": float(sd or 0)},
                        "prompt_ctx": ctx,
                    })

    # 2) User activity deviation (events, ip diversity) using z-score
    ua = _user_activity_features(df)
    if not ua.empty and not user_stats.empty:
        if "username" in ua.columns:
            ua = ua.copy()
            ua["username"] = ua["username"].astype(str)
        cols = [
            ("events", "events_mean", "events_std", "Số sự kiện"),
            ("unique_src_ips", "unique_src_ips_mean", "unique_src_ips_std", "Số IP nguồn khác nhau"),
            ("login_fail", "login_fail_mean", "login_fail_std", "Số lần đăng nhập thất bại"),
        ]
        for val_col, m_col, s_col, vi_label in cols:
            if (val_col in ua.columns) and (m_col in user_stats.columns) and (s_col in user_stats.columns):
                merged = ua[["username", val_col]].merge(user_stats[["username", m_col, s_col]], on="username", how="left")
                for row in merged.itertuples(index=False):
                    u = getattr(row, "username")
                    cur = getattr(row, val_col)
                    mu = getattr(row, m_col)
                    sd = getattr(row, s_col)
                    z = _safe_z(cur, mu if mu is not None else 0.0, sd if sd is not None else 0.0)
                    
                    # Improved detection logic:
                    # 1. If std > 0: use Z-score >= 3.0 AND current > mean
                    # 2. If std == 0: use simple threshold (current > mean + 20% or > 1.5x mean)
                    has_variance = (sd is not None and sd > 0)
                    if has_variance:
                        anomaly_detected = z >= 3.0 and cur > (mu or 0)
                    else:
                        # No variance in baseline - use simple percentage threshold
                        baseline_val = mu or 0
                        anomaly_detected = (cur > baseline_val * 1.5) and (cur >= max(3, baseline_val))
                    
                    if anomaly_detected:
                        ctx = {
                            "user": u,
                            "group": None,
                            "behavior": {
                                "type": val_col,
                                "value": int(cur),
                            },
                            "time": None,
                            "baseline": {
                                "mean": float(mu or 0),
                                "std": float(sd or 0),
                            },
                            "extras": {},
                        }
                        try:
                            g = (
                                df[df.get("username").astype(str)==str(u)]["group"].dropna().astype(str).unique()
                                if "group" in df.columns else []
                            )
                            if len(g):
                                ctx["group"] = g[0]
                        except Exception:
                            pass
                        
                        # Adjust score based on variance
                        if has_variance:
                            score = float(z)
                        else:
                            # If no variance, use ratio-based score
                            ratio = (cur / (mu or 1)) if (mu or 0) > 0 else 1
                            score = min(ratio * 2, 10.0)  # Cap at 10
                        
                        alerts.append({
                            "type": f"user_{val_col}_spike",
                            "subject": u,
                            "severity": "WARNING" if score < 5 else "CRITICAL",
                            "score": score,
                            "text": f"{vi_label} của user {u} tăng đột biến: {cur} so với trung bình {mu:.0f}±{sd:.0f}.",
                            "evidence": {"current": int(cur), "mean": float(mu or 0), "std": float(sd or 0)},
                            "prompt_ctx": ctx,
                        })

    # 2.5) Firewall/Network - Detect blocked/denied actions spike
    if "action" in df.columns and "status" in df.columns:
        try:
            # Group by source_ip, then username, then host - to find which entity has high blocked rate
            group_keys = []
            if "source_ip" in df.columns:
                group_keys.append("source_ip")
            if "username" in df.columns:
                group_keys.append("username")
            if "host" in df.columns:
                group_keys.append("host")
            
            # If we have grouping keys, analyze per entity
            if group_keys:
                # Use source_ip as primary key (most important for firewall)
                primary_key = "source_ip" if "source_ip" in df.columns else (
                    "username" if "username" in df.columns else "host"
                )
                
                seen_subjects = set()  # Track to avoid duplicates
                
                for entity, group in df.groupby(primary_key):
                    entity = str(entity) if pd.notna(entity) else "(unknown)"
                    
                    # Skip if already alerted for this entity
                    if entity in seen_subjects:
                        continue
                    
                    # Check blocked ratio for this entity
                    blocked_mask = group["status"].astype(str).str.lower().isin(["blocked", "failure", "failed", "denied", "dropped"])
                    blocked_count = blocked_mask.sum()
                    total_count = len(group)
                    
                    if total_count > 0:
                        blocked_ratio = blocked_count / total_count
                        
                        # If >50% of actions blocked from this entity, it's suspicious
                        if blocked_ratio > 0.5 and blocked_count >= 5:
                            seen_subjects.add(entity)
                            
                            # Try to get more context
                            username = group["username"].dropna().unique()
                            host = group["host"].dropna().unique()
                            dest_ip = group.get("dest_ip", pd.Series()).dropna().unique() if "dest_ip" in group.columns else []
                            
                            user_str = f"User: {username[0]}" if len(username) > 0 else ""
                            host_str = f"Host: {host[0]}" if len(host) > 0 else ""
                            target_str = f"Target: {dest_ip[0]}" if len(dest_ip) > 0 else ""
                            
                            context_parts = [p for p in [user_str, host_str, target_str] if p]
                            context_info = " | ".join(context_parts) if context_parts else ""
                            
                            ctx = {
                                "user": str(username[0]) if len(username) > 0 else None,
                                "group": None,
                                "behavior": {"type": "blocked_actions_spike", "ratio": float(blocked_ratio), "count": int(blocked_count), "source": entity},
                                "time": None,
                                "baseline": {"expected_ratio": 0.2},
                                "extras": {"reason": f"High ratio of blocked/denied actions from {entity}"},
                            }
                            
                            alerts.append({
                                "type": "blocked_actions_spike",
                                "subject": entity,  # ← Changed: now shows IP, username, or host instead of "window"
                                "severity": "CRITICAL" if blocked_ratio > 0.8 else "WARNING",
                                "score": min(blocked_ratio * 10, 10.0),
                                "text": f"Phát hiện {blocked_count}/{total_count} hành động bị chặn ({blocked_ratio:.1%}) từ {primary_key}={entity}. {f'Chi tiết: {context_info}' if context_info else ''} Điều này có thể cho thấy cuộc tấn công hoặc cấu hình sai.",
                                "evidence": {"blocked_count": int(blocked_count), "total_count": int(total_count), "ratio": float(blocked_ratio), "source": entity, "context": context_info},
                                "prompt_ctx": ctx,
                            })
            else:
                # Fallback: no grouping keys available, use global window detection
                blocked_mask = df["status"].astype(str).str.lower().isin(["blocked", "failure", "failed", "denied", "dropped"])
                blocked_count = blocked_mask.sum()
                total_count = len(df)
                
                if total_count > 0:
                    blocked_ratio = blocked_count / total_count
                    
                    if blocked_ratio > 0.5 and blocked_count >= 5:
                        ctx = {
                            "user": None,
                            "group": None,
                            "behavior": {"type": "blocked_actions_spike", "ratio": float(blocked_ratio), "count": int(blocked_count)},
                            "time": None,
                            "baseline": {"expected_ratio": 0.2},
                            "extras": {"reason": f"High ratio of blocked/denied actions"},
                        }
                        alerts.append({
                            "type": "blocked_actions_spike",
                            "subject": f"(global)",  # Only use "global" if no grouping available
                            "severity": "CRITICAL" if blocked_ratio > 0.8 else "WARNING",
                            "score": min(blocked_ratio * 10, 10.0),
                            "text": f"Phát hiện {blocked_count}/{total_count} hành động bị chặn ({blocked_ratio:.1%}). Điều này có thể cho thấy cuộc tấn công hoặc cấu hình sai.",
                            "evidence": {"blocked_count": int(blocked_count), "total_count": int(total_count), "ratio": float(blocked_ratio)},
                            "prompt_ctx": ctx,
                        })
        except Exception:
            pass
    
    # 2.6) Firewall/Network - Detect port scanning patterns
    if "dest_port" in df.columns and "source_ip" in df.columns and "status" in df.columns:
        try:
            blocked_df = df[df["status"].astype(str).str.lower().isin(["blocked", "denied"])]
            if len(blocked_df) >= 5:
                # Group by source IP and check for multi-port scanning attempts
                for src_ip, group in blocked_df.groupby("source_ip"):
                    if len(group) >= 5:
                        ports = pd.to_numeric(group["dest_port"], errors="coerce").dropna().unique()
                        if len(ports) >= 3:
                            # Port scanning detected if:
                            # 1. Multiple ports (>= 3) from same IP - indicates sweep
                            # 2. OR ports are somewhat sequential (some ordered pattern)
                            sorted_ports = sorted(ports)
                            
                            # Check two patterns:
                            # A) Sequential: all diffs <= 5 (tight scanning)
                            # B) Sparse but methodical: >50% diffs <= 100 (common port ranges)
                            diffs = [sorted_ports[i+1] - sorted_ports[i] for i in range(len(sorted_ports)-1)]
                            sequential_diffs = sum(1 for d in diffs if d <= 5)
                            moderate_diffs = sum(1 for d in diffs if d <= 100)
                            
                            is_sequential = all(d <= 5 for d in diffs)
                            is_methodical = len(diffs) > 0 and (sequential_diffs >= len(diffs) * 0.3 or moderate_diffs >= len(diffs) * 0.7)
                            is_port_scan = is_sequential or is_methodical or (len(ports) >= 4)
                            
                            if is_port_scan:
                                username = group["username"].dropna().unique()
                                
                                # Determine scan pattern description
                                if is_sequential:
                                    scan_type = "sequential port scanning"
                                elif len(ports) >= 4 and moderate_diffs >= len(diffs) * 0.7:
                                    scan_type = "methodical port scanning"
                                else:
                                    scan_type = "multi-port probing"
                                
                                ctx = {
                                    "user": str(username[0]) if len(username) > 0 else None,
                                    "group": None,
                                    "behavior": {"type": "port_scan", "source_ip": src_ip, "ports_attempted": int(len(ports))},
                                    "time": None,
                                    "baseline": {},
                                    "extras": {"reason": f"{scan_type} detected"},
                                }
                                alerts.append({
                                    "type": "port_scan_detected",
                                    "subject": src_ip,
                                    "severity": "CRITICAL",
                                    "score": 8.0,
                                    "text": f"Phát hiện port scanning từ IP {src_ip}: {len(ports)} cổng bị chặn ({scan_type}).",
                                    "evidence": {"source_ip": src_ip, "ports_attempted": int(len(ports)), "port_list": sorted_ports.tolist()},
                                    "prompt_ctx": ctx,
                                })
        except Exception:
            pass
    
    # 3) Global burst by moving average on events per minute
    df_idx = df.set_index("timestamp").sort_index()
    epm = df_idx.resample("1min").size().astype(float)
    if len(epm) >= 10:
        roll = epm.rolling(window=10, min_periods=5)
        ma = roll.mean()
        sd = roll.std(ddof=0)
        spikes = epm[(epm - ma) > 3 * sd]
        for ts, val in spikes.dropna().items():
            ctx = {
                "user": None,
                "group": None,
                "behavior": {"type": "burst", "events_per_min": int(val)},
                "time": _fmt_local_vn(ts),
                "baseline": {
                    "moving_avg": float(ma.loc[ts]) if pd.notna(ma.loc[ts]) else None,
                    "moving_std": float(sd.loc[ts]) if pd.notna(sd.loc[ts]) else None,
                },
                "extras": {},
            }
            alerts.append({
                "type": "global_burst",
                "subject": ts.isoformat(),
                "severity": "WARNING" if val < (global_stats.get("max_events_per_hour", 0) / 10.0) else "CRITICAL",
                "score": float(((val - (ma.loc[ts] or 0)) / (sd.loc[ts] or 1)) if not np.isnan(sd.loc[ts]) and sd.loc[ts] else 0.0),
                "text": f"Bùng nổ sự kiện tại {ts.isoformat()}: {int(val)} sự kiện/phút vượt trung bình động {ma.loc[ts]:.1f}±{sd.loc[ts]:.1f}.",
                "evidence": {"events_per_min": int(val)},
                "prompt_ctx": ctx,
            })

    # 4) Access from foreign country (based on source_country column if present)
    if "source_country" in df.columns and "username" in df.columns:
        foreign = df[~df["source_country"].astype(str).str.upper().isin(["VN", "VNM", "VIETNAM"])]
        if not foreign.empty:
            for u in foreign["username"].dropna().astype(str).unique():
                u_foreign = foreign[foreign["username"].astype(str) == u]
                countries = u_foreign["source_country"].dropna().astype(str).unique()
                if len(u_foreign) >= 2:  # at least 2 events
                    ctx = {
                        "user": u,
                        "group": None,
                        "behavior": {
                            "type": "foreign_access",
                            "countries": list(countries),
                            "events": len(u_foreign),
                        },
                        "time": None,
                        "baseline": {},
                        "extras": {},
                    }
                    try:
                        g = df[df["username"].astype(str)==u]["group"].dropna().astype(str).unique()
                        if len(g):
                            ctx["group"] = g[0]
                    except Exception:
                        pass
                    alerts.append({
                        "type": "foreign_country_access",
                        "subject": u,
                        "severity": "WARNING" if len(u_foreign) < 5 else "CRITICAL",
                        "score": 4.0 + min(len(u_foreign) * 0.2, 2.0),
                        "text": f"User {u} truy cập từ quốc gia nước ngoài: {', '.join(countries)} ({len(u_foreign)} sự kiện).",
                        "evidence": {"countries": list(countries), "events": int(len(u_foreign))},
                        "prompt_ctx": ctx,
                    })

    # 5) Access outside working hours (0-6h, 22-24h local time)
    if "timestamp" in df.columns and "username" in df.columns:
        try:
            df_tmp = df.copy()
            df_tmp["local_hour"] = pd.to_datetime(df_tmp["timestamp"], utc=True).dt.tz_convert("Asia/Ho_Chi_Minh").dt.hour
            outside = df_tmp[(df_tmp["local_hour"] < 6) | (df_tmp["local_hour"] >= 22)]
            if not outside.empty:
                for u in outside["username"].dropna().astype(str).unique():
                    u_outside = outside[outside["username"].astype(str) == u]
                    if len(u_outside) >= 3:
                        hours = u_outside["local_hour"].unique()
                        ctx = {
                            "user": u,
                            "group": None,
                            "behavior": {
                                "type": "off_hours_access",
                                "hours": sorted([int(h) for h in hours]),
                                "events": len(u_outside),
                            },
                            "time": None,
                            "baseline": {"working_hours": "6h-22h"},
                            "extras": {},
                        }
                        try:
                            g = df[df["username"].astype(str)==u]["group"].dropna().astype(str).unique()
                            if len(g):
                                ctx["group"] = g[0]
                        except Exception:
                            pass
                        alerts.append({
                            "type": "off_hours_access",
                            "subject": u,
                            "severity": "WARNING" if len(u_outside) < 10 else "CRITICAL",
                            "score": 4.0 + min(len(u_outside) * 0.1, 2.0),
                            "text": f"User {u} truy cập ngoài giờ làm việc ({len(u_outside)} sự kiện vào lúc {sorted([int(h) for h in hours])}h).",
                            "evidence": {"hours": sorted([int(h) for h in hours]), "events": int(len(u_outside))},
                            "prompt_ctx": ctx,
                        })
        except Exception:
            pass

    # 6) Suspicious login from public/foreign IP (requires enrich step)
    if "action" in df.columns:
        logins = df[df["action"].astype(str).str.lower().str.contains("login|logon", na=False)]
        if not logins.empty:
            # enrich columns that may exist: ip_scope, geoip_country
            for row in logins.itertuples(index=False):
                u = getattr(row, "username", None)
                ip = getattr(row, "source_ip", None)
                scope = getattr(row, "ip_scope", None)
                ctry = getattr(row, "geoip_country", None)
                if (scope == "public") and (ctry is not None) and (str(ctry).upper() not in ("VN", "VNM")):
                    ts = getattr(row, "timestamp", None)
                    ctx = {
                        "user": str(u) if u else None,
                        "group": None,
                        "behavior": {"type": "login", "from": "public_ip", "ip": ip, "country": ctry},
                        "time": _fmt_local_vn(ts) if ts is not None else None,
                        "baseline": {},
                        "extras": {},
                    }
                    try:
                        if "group" in df.columns and u is not None:
                            g = (
                                df[df.get("username").astype(str)==str(u)]["group"].dropna().astype(str).unique()
                            )
                            if len(g):
                                ctx["group"] = g[0]
                    except Exception:
                        pass
                    alerts.append({
                        "type": "login_foreign_ip",
                        "subject": str(u) if u else "<unknown>",
                        "severity": "WARNING",
                        "score": 3.0,
                        "text": f"User {u} đăng nhập từ IP công khai {ip} ở quốc gia {ctry}.",
                        "evidence": {"source_ip": ip, "geoip_country": ctry},
                        "prompt_ctx": ctx,
                    })

    # NEW: DHCP-specific attack detection (when DHCP logs detected)
    if "program" in df.columns and df["program"].eq("dhcpd").any():
        # Add scope conflict detection
        dhcp_scope_alerts = _detect_dhcp_scope_conflicts(df)
        alerts.extend(dhcp_scope_alerts)
        
        # Add rogue server / NAK storm detection
        dhcp_rogue_alerts = _detect_dhcp_rogue_server(df)
        alerts.extend(dhcp_rogue_alerts)
        
        # Add device user mismatch detection
        dhcp_mismatch_alerts = _detect_dhcp_user_device_mismatch(df)
        alerts.extend(dhcp_mismatch_alerts)
    
    # NEW: DNS-specific attack detection (when DNS/dnsmasq logs detected)
    if "program" in df.columns and df["program"].eq("dnsmasq").any():
        dns_alerts = _detect_dns_anomalies(df)
        alerts.extend(dns_alerts)
    
    
    # NEW: Firewall-specific attack detection (firewall OR UFW logs)
    # The detector now checks internally for both program=='firewall' and UFW patterns
    fw_alerts = _detect_firewall_anomalies(df)
    alerts.extend(fw_alerts)
    
    # NEW: Apache/Web-specific attack detection (when apache logs detected)
    # Detector checks for Apache-specific columns (http_status, path, vhost) internally
    apache_alerts = _detect_apache_anomalies(df)
    alerts.extend(apache_alerts)

    return alerts


def build_prompt_for_alert(alert: Dict[str, Any]) -> str:
    """
    Build a Vietnamese prompt for LLM step based on one raw alert.
    """
    t = alert.get("type", "anomaly")
    subj = alert.get("subject")
    text = alert.get("text")
    sev = alert.get("severity", "INFO")
    ev = alert.get("evidence", {})
    return (
        f"Bạn là chuyên gia SOC. Hãy phân tích cảnh báo sau và đánh giá rủi ro, đề xuất hành động.\n"
        f"Mức độ cảnh báo: {sev}.\n"
        f"Chủ thể: {subj}.\n"
        f"Mô tả: {text}.\n"
        f"Bằng chứng: {json.dumps(ev, ensure_ascii=False)}.\n"
        f"Trả lời bằng JSON gồm: summary, risks[], risk_level(Thấp/Trung bình/Cao/Cực kỳ nguy cấp), actions[]."
    )


