import os
import json
import re
from typing import List, Dict, Any, Tuple

import numpy as np
import pandas as pd
from datetime import timezone

# Import unified scoring system
from services import scoring


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


def _load_baseline_tables(base_dir: str, log_type: str = "generic") -> Dict[str, Any]:
    """
    Load previously trained baselines từ MongoDB (PRIMARY) hoặc config/baselines/* (FALLBACK).
    
    Args:
        base_dir: Path to config/baselines (for fallback)
        log_type: Loại log (generic, linuxsyslog, edr, etc.)
    
    Returns:
        dict với keys: user_stats, device_stats, group_stats, global_stats, user_models, device_models, group_models
    """
    out: Dict[str, Any] = {}
    
    # === TRY MONGODB FIRST ===
    try:
        from services.database import (
            load_user_stats, load_device_stats, load_group_stats, load_global_stats,
            load_user_models, load_device_models, load_group_models
        )
        
        print(f"[ANOMALY] Loading baselines from MongoDB for log_type={log_type}")
        out["user_stats"] = load_user_stats(log_type=log_type)
        out["device_stats"] = load_device_stats(log_type=log_type)
        out["group_stats"] = load_group_stats(log_type=log_type)
        out["global_stats"] = load_global_stats(log_type=log_type)
        out["user_models"] = load_user_models(log_type=log_type)
        out["device_models"] = load_device_models(log_type=log_type)
        out["group_models"] = load_group_models(log_type=log_type)
        
        # Check if MongoDB has data
        has_data = (not out["user_stats"].empty or 
                   not out["device_stats"].empty or 
                   bool(out["global_stats"]) or
                   bool(out["user_models"]))
        
        if has_data:
            print(f"[ANOMALY] ✓ Successfully loaded baselines from MongoDB")
            return out
        else:
            print(f"[ANOMALY] ⚠ MongoDB empty, falling back to file-based baselines")
    
    except Exception as e:
        print(f"[ANOMALY] ⚠ Failed to load from MongoDB: {e}, falling back to files")
    
    # === FALLBACK: LOAD FROM FILES ===
    print(f"[ANOMALY] Loading baselines from files: {base_dir}")
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
    
    # Load models from files
    import joblib
    try:
        um_path = os.path.join(base_dir, "user_models.joblib")
        out["user_models"] = joblib.load(um_path) if os.path.exists(um_path) else {}
    except Exception:
        out["user_models"] = {}
    
    try:
        dm_path = os.path.join(base_dir, "device_models.joblib")
        out["device_models"] = joblib.load(dm_path) if os.path.exists(dm_path) else {}
    except Exception:
        out["device_models"] = {}
    
    try:
        gm_path = os.path.join(base_dir, "group_models.joblib")
        out["group_models"] = joblib.load(gm_path) if os.path.exists(gm_path) else {}
    except Exception:
        out["group_models"] = {}
    
    print(f"[ANOMALY] ✓ Loaded baselines from files")
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


def _classify_ip(ip: str) -> tuple:
    """
    Classify IP as EXTERNAL or INTERNAL.
    Returns (label, is_external) where:
    - label is "EXTERNAL" for public IPs, "INTERNAL" for RFC1918 private IPs
    - is_external is True for public IPs
    
    This helps SOC analysts quickly identify data exfiltration to external destinations.
    
    Note: RFC 5737 TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
    treated as EXTERNAL because they represent external/attacker IPs in test log files.
    """
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        # RFC 5737 TEST-NET ranges - these are used in documentation/testing to represent
        # external/attacker IPs, so we should classify them as EXTERNAL despite being "reserved"
        # TEST-NET-1: 192.0.2.0/24, TEST-NET-2: 198.51.100.0/24, TEST-NET-3: 203.0.113.0/24
        test_net_ranges = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        
        for test_net in test_net_ranges:
            if ip_obj in test_net:
                return "EXTERNAL", True  # TEST-NET = external attacker in test scenarios
        
        # Standard classification
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return "INTERNAL", False
        elif ip_obj.is_reserved:
            # Other reserved ranges (not TEST-NET) - treat as unknown/internal
            return "RESERVED", False
        else:
            return "EXTERNAL", True
    except Exception:
        return "UNKNOWN", False




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
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dhcp_scope_conflict", [])
                
                alerts.append({
                    "type": "dhcp_scope_conflict",
                    "subject": user_str,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
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
            
            # Use unified scoring
            score_data = scoring.get_alert_metadata("dhcp_rogue_server", [])
            
            alerts.append({
                "type": "dhcp_rogue_server_indication",
                "subject": "DHCP Network",
                "severity": score_data["severity"],
                "score": score_data["score"],
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
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dhcp_user_device_mismatch", [])
                
                alerts.append({
                    "type": "dhcp_device_user_mismatch",
                    "subject": device,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
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

def _detect_dhcp_vlan_hopping(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect excessive VLAN/Interface changes (roaming) by same user.
    Indicates network scanning, port hopping, or physical movement between network segments.
    """
    alerts = []
    
    if "username" not in df.columns or "timestamp" not in df.columns:
        return alerts
    
    try:
        # Group by username and analyze VLAN/Interface changes
        for username, group in df[df["username"].notna()].groupby("username"):
            username = str(username)
            group = group.copy().sort_values("timestamp")
            
            # Track interface/VLAN changes
            interfaces = set()
            vlans = set()
            
            if "interface" in group.columns:
                interfaces = set(group["interface"].dropna().astype(str).unique())
            if "vlan" in group.columns:
                vlans = set(group["vlan"].dropna().astype(str).unique())
            
            # Detect excessive roaming: 3+ interfaces OR 3+ VLANs
            total_segments = len(interfaces) + len(vlans)
            
            if total_segments >= 5:  # Excessive roaming
                time_span = group["timestamp"].max() - group["timestamp"].min()
                time_minutes = int(time_span.total_seconds() / 60) if pd.notna(time_span) else 0
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dhcp_excessive_roaming", [])
                
                alerts.append({
                    "type": "dhcp_excessive_roaming",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": f"User {username}: Excessive network roaming - {len(interfaces)} interfaces, {len(vlans)} VLANs in {time_minutes} minutes",
                    "evidence": {
                        "interfaces": list(interfaces),
                        "vlans": list(vlans),
                        "total_dhcp_events": len(group),
                        "time_span_minutes": time_minutes,
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {"type": "vlan_hopping", "segments": total_segments},
                        "time": None,
                        "baseline": {},
                        "extras": {"reason": "Rapid VLAN/Interface changes may indicate network scanning"},
                    },
                })
    except Exception:
        pass
    
    return alerts


def _detect_dhcp_frequent_release(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect frequent DHCP RELEASE actions (manual IP release is uncommon for normal users).
    May indicate IP evasion, troubleshooting, or unstable network configuration.
    """
    alerts = []
    
    if "action" not in df.columns or "username" not in df.columns:
        return alerts
    
    try:
        # Filter RELEASE actions
        release_df = df[df["action"].astype(str).str.lower() == "release"].copy()
        
        if release_df.empty:
            return alerts
        
        # Group by username
        for username, group in release_df.groupby("username"):
            username = str(username)
            release_count = len(group)
            
            # 3+ releases is unusual for normal users
            if release_count >= 3:
                time_span = group["timestamp"].max() - group["timestamp"].min()
                time_minutes = int(time_span.total_seconds() / 60) if pd.notna(time_span) else 0
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dhcp_frequent_release", [])
                
                alerts.append({
                    "type": "dhcp_frequent_release",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": f"User {username}: Frequent IP release - {release_count} DHCPRELEASE in {time_minutes} minutes",
                    "evidence": {
                        "release_count": release_count,
                        "time_span_minutes": time_minutes,
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {"type": "frequent_ip_release", "count": release_count},
                        "time": None,
                        "baseline": {"expected_releases": "0-1 per day"},
                        "extras": {"reason": "Manual IP release may indicate IP evasion or network issues"},
                    },
                })
    except Exception:
        pass
    
    return alerts


def _detect_firewall_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect firewall-based attacks with IP-to-user attribution.
    
    Detections:
    - Deny/Block burst (connection flood)
    - Data exfiltration (high-volume outbound transfers)
    - Port scanning patterns
    - Policy evasion (suspicious allow patterns)
    
    Returns alerts with proper subject attribution (username instead of IP when possible).
    """
    alerts = []
    
    # Helper: Map source IP to username
    def get_user_from_ip(ip):
        """Try to resolve IP to username from same DataFrame."""
        if pd.isna(ip) or str(ip).strip() == "":
            return "(unknown)"
        
        ip_str = str(ip)
        
        # Try to find username associated with this IP in current logs
        if "username" in df.columns and "source_ip" in df.columns:
            matches = df[df["source_ip"].astype(str) == ip_str]["username"].dropna()
            if len(matches) > 0:
                # Return most common username for this IP
                username = matches.value_counts().index[0]
                if username and str(username).strip():
                    return str(username)
        
        # Fallback: Use IP as identifier
        return ip_str
    
    # Detect firewall logs by checking for firewall-specific columns or program names
    firewall_indicators = ["action", "status", "source_ip", "dest_ip"]
    has_firewall_cols = all(col in df.columns for col in firewall_indicators)
    
    if not has_firewall_cols:
        return alerts
    
    # Also check program column for explicit firewall identification
    is_firewall_log = False
    if "program" in df.columns:
        firewall_programs = df["program"].astype(str).str.contains("firewall|ufw|iptables", case=False, na=False).any()
        is_firewall_log = firewall_programs
    
    # Alternative: Check for firewall-specific action/status values
    if not is_firewall_log and "status" in df.columns:
        firewall_statuses = df["status"].astype(str).str.lower().isin(["blocked", "denied", "allowed", "accepted"]).any()
        is_firewall_log = firewall_statuses
    
    if not is_firewall_log:
        return alerts
    
    try:
        # ===== DETECTION 1: DENY/BLOCK BURST =====
        # Rapid series of connection denials/blocks (3 strategies)
        # Check BOTH status AND action columns for blocked/denied patterns
        
        # Track detected events to avoid duplicates
        detected_deny_bursts = set()  # Track (source_ip, dest_ip) or target_host to deduplicate
        
        if "dest_port" in df.columns and "source_ip" in df.columns:
            blocked_df = pd.DataFrame()
            
            if "status" in df.columns:
                status_blocked = df[df["status"].astype(str).str.lower().isin(["blocked", "denied", "drop", "deny"])].copy()
                blocked_df = pd.concat([blocked_df, status_blocked], ignore_index=True)
            
            if "action" in df.columns:
                action_blocked = df[df["action"].astype(str).str.upper().isin(["DENY", "BLOCK", "DROP", "BLOCKED", "DENIED"])].copy()
                blocked_df = pd.concat([blocked_df, action_blocked], ignore_index=True)
            
            if not blocked_df.empty:
                blocked_df = blocked_df.drop_duplicates()
            
            # === STRATEGY 1: Per-IP Detection (Primary) ===
            # High DENY count from single source IP
            if not blocked_df.empty:
                for src_ip, group in blocked_df.groupby("source_ip"):
                    blocked_count = len(group)
                    
                    if blocked_count >= 5:  # REDUCED from 20 to 5 for better detection
                        dest_ips = group["dest_ip"].dropna().unique() if "dest_ip" in group.columns else []
                        username = get_user_from_ip(src_ip)
                        score_data = scoring.get_alert_metadata("firewall_deny_burst", [])
                        
                        # Mark as detected
                        detected_deny_bursts.add(f"per_ip:{src_ip}")
                        
                        alerts.append({
                            "type": "firewall_deny_burst",
                            "subject": username,
                            "severity": score_data["severity"],
                            "score": score_data["score"],
                            "text": f"Firewall DENY/BLOCK burst detected: {blocked_count} blocked connections from {username} (IP: {src_ip}) to {len(dest_ips)} destination(s).",
                            "evidence": {
                                "source_ip": str(src_ip),
                                "username": username,
                                "blocked_count": int(blocked_count),
                                "destinations": [str(d) for d in dest_ips[:10]],
                                "dest_count": int(len(dest_ips)),
                                "detection_method": "per_ip",
                            },
                            "prompt_ctx": {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "deny_burst", "count": blocked_count},
                                "time": None,
                                "baseline": {"expected_denies": 2},
                                "extras": {"reason": "High volume of blocked connections may indicate DoS or scanning"},
                            },
                        })
            
            # === STRATEGY 2: Time Window Detection (Secondary - skip if per_ip already detected) ===
            # Detect burst: >10 DENY events in any 1-minute window
            if "timestamp" in blocked_df.columns and len(blocked_df) >= 10:
                try:
                    # Ensure timestamp is datetime
                    blocked_df_time = blocked_df.copy()
                    blocked_df_time["timestamp"] = pd.to_datetime(blocked_df_time["timestamp"], errors="coerce", utc=True)
                    blocked_df_time = blocked_df_time.dropna(subset=["timestamp"])
                    
                    if not blocked_df_time.empty:
                        # Count DENY events per minute
                        blocked_df_time = blocked_df_time.set_index("timestamp").sort_index()
                        deny_per_minute = blocked_df_time.resample("1min").size()
                        
                        # Check for bursts: >10 denies/minute
                        burst_minutes = deny_per_minute[deny_per_minute >= 10]
                        
                        if len(burst_minutes) > 0:
                            max_rate = int(deny_per_minute.max())
                            total_in_burst = int(burst_minutes.sum())
                            
                            # Get all IPs involved in the burst
                            burst_ips = blocked_df_time[
                                blocked_df_time.index.to_series().dt.floor("1min").isin(burst_minutes.index)
                            ]["source_ip"].dropna().unique()
                            
                            # Check if any of these IPs were already detected by per_ip strategy
                            already_detected = any(f"per_ip:{ip}" in detected_deny_bursts for ip in burst_ips)
                            
                            if not already_detected:
                                # Get all targets
                                burst_targets = blocked_df_time[
                                    blocked_df_time.index.to_series().dt.floor("1min").isin(burst_minutes.index)
                                ]["dest_ip"].dropna().unique()
                                
                                score_data = scoring.get_alert_metadata("firewall_deny_burst", [])
                                
                                # Mark as detected
                                detected_deny_bursts.add(f"time_window:{','.join(str(ip) for ip in burst_ips[:3])}")
                                
                                alerts.append({
                                    "type": "firewall_deny_burst",
                                    "subject": f"Multiple Users ({len(burst_ips)})",
                                    "severity": score_data["severity"],
                                    "score": score_data["score"],
                                    "text": f"DENY burst attack detected: {total_in_burst} blocked connections ({max_rate} per minute peak) from {len(burst_ips)} source(s) to {len(burst_targets)} target(s).",
                                    "evidence": {
                                        "total_denied": total_in_burst,
                                        "max_rate_per_minute": max_rate,
                                        "source_count": int(len(burst_ips)),
                                        "source_ips": [str(ip) for ip in burst_ips[:10]],
                                        "target_count": int(len(burst_targets)),
                                        "targets": [str(ip) for ip in burst_targets[:5]],
                                        "detection_method": "time_window",
                                    },
                                    "prompt_ctx": {
                                        "user": None,
                                        "group": None,
                                        "behavior": {"type": "deny_burst_temporal", "rate": max_rate, "total": total_in_burst},
                                        "time": None,
                                        "baseline": {"expected_denies_per_minute": 2},
                                        "extras": {"reason": "Rapid burst of DENY events indicates active attack"},
                                    },
                                })
                except Exception:
                    pass  # Skip time window detection if error
            
            # === STRATEGY 3: Pattern Detection - Distributed attack (Secondary - skip if already detected) ===
            # Multiple source IPs targeting same destination
            if "dest_ip" in blocked_df.columns and "dst_host" in blocked_df.columns:
                try:
                    for dest, group in blocked_df.groupby("dest_ip"):
                        unique_sources = group["source_ip"].dropna().unique()
                        
                        # Threshold: 5+ different source IPs attacking same target
                        if len(unique_sources) >= 5:
                            dest_host = group["dst_host"].iloc[0] if "dst_host" in group.columns else dest
                            total_attempts = len(group)
                            dest_ports = group["dest_port"].dropna().unique() if "dest_port" in group.columns else []
                            
                            # Check if this target or any sources already detected
                            target_key = f"target:{dest_host}"
                            already_detected_sources = any(f"per_ip:{ip}" in detected_deny_bursts for ip in unique_sources)
                            already_detected_target = target_key in detected_deny_bursts
                            
                            if not already_detected_sources and not already_detected_target:
                                score_data = scoring.get_alert_metadata("firewall_deny_burst", [])
                                
                                # Mark as detected
                                detected_deny_bursts.add(target_key)
                                
                                alerts.append({
                                    "type": "firewall_deny_burst",
                                    "subject": f"Target: {dest_host}",
                                    "severity": score_data["severity"],
                                    "score": score_data["score"],
                                    "text": f"Distributed DENY attack: {total_attempts} blocked connections from {len(unique_sources)} different source(s) targeting {dest_host}:{dest_ports[0] if len(dest_ports) > 0 else 'unknown'}.",
                                    "evidence": {
                                        "target_ip": str(dest),
                                        "target_host": str(dest_host),
                                        "target_ports": [int(p) for p in dest_ports if pd.notna(p)][:5],
                                        "total_attempts": int(total_attempts),
                                        "source_count": int(len(unique_sources)),
                                        "source_ips": [str(ip) for ip in unique_sources[:10]],
                                        "detection_method": "pattern_distributed",
                                    },
                                    "prompt_ctx": {
                                        "user": None,
                                        "group": None,
                                        "behavior": {"type": "distributed_deny_attack", "sources": len(unique_sources), "attempts": total_attempts},
                                        "time": None,
                                        "baseline": {"expected_sources_per_target": 2},
                                        "extras": {"reason": "Multiple sources attacking same target indicates coordinated attack"},
                                    },
                                })
                except Exception:
                    pass  # Skip pattern detection if error
        
        # ===== DETECTION 2: DATA EXFILTRATION =====
        # Large outbound data transfers
        # Check BOTH status AND action columns for allowed patterns
        allowed_df = pd.DataFrame()
        
        if "bytes" in df.columns and "dest_ip" in df.columns:
            if "status" in df.columns:
                status_allowed = df[df["status"].astype(str).str.lower().isin(["allowed", "accepted", "permit", "allow"])].copy()
                allowed_df = pd.concat([allowed_df, status_allowed], ignore_index=True)
            
            if "action" in df.columns:
                action_allowed = df[df["action"].astype(str).str.upper().isin(["ALLOW", "ACCEPT", "PERMIT", "ALLOWED"])].copy()
                allowed_df = pd.concat([allowed_df, action_allowed], ignore_index=True)
            
            # Remove duplicates and ensure bytes column exists
            if not allowed_df.empty and "bytes" in allowed_df.columns:
                allowed_df = allowed_df.drop_duplicates()
                # Convert bytes to numeric
                allowed_df["bytes_num"] = pd.to_numeric(allowed_df["bytes"], errors="coerce")
                allowed_df = allowed_df[allowed_df["bytes_num"] > 0]
                
                if not allowed_df.empty:
                    # Group by source IP and sum bytes
                    for src_ip, group in allowed_df.groupby("source_ip"):
                        total_bytes = group["bytes_num"].sum()
                        transfer_count = len(group)
                        dest_ips = group["dest_ip"].dropna().unique()
                        
                        # Threshold: 10MB+ transferred
                        if total_bytes >= 10 * 1024 * 1024 and transfer_count >= 5:
                            username = get_user_from_ip(src_ip)
                            total_mb = total_bytes / (1024 * 1024)
                            
                            # Use unified scoring
                            score_data = scoring.get_alert_metadata("firewall_exfiltration", [])
                            
                            alerts.append({
                                "type": "firewall_exfiltration",
                                "subject": username,
                                "severity": score_data["severity"],
                                "score": score_data["score"],
                                "text": f"Data exfiltration suspected: {username} (IP: {src_ip}) transferred {total_mb:.1f}MB to {len(dest_ips)} destination(s) ({transfer_count} transfers).",
                                "evidence": {
                                    "source_ip": str(src_ip),
                                    "username": username,
                                    "total_bytes": int(total_bytes),
                                    "total_mb": round(total_mb, 1),
                                    "transfer_count": int(transfer_count),
                                    "destinations": [str(d) for d in dest_ips[:10]],
                                },
                                "prompt_ctx": {
                                    "user": username,
                                    "group": None,
                                    "behavior": {"type": "data_exfiltration", "bytes": total_bytes, "transfers": transfer_count},
                                    "time": None,
                                    "baseline": {"max_normal_transfer": "5MB"},
                                    "extras": {"reason": "High-volume outbound transfers may indicate data theft"},
                                },
                            })
        
        # ===== DETECTION 3: PORT SCANNING =====
        # Multiple destination ports from same source IP
        # Check BOTH status AND action columns for blocked/denied patterns
        if "dest_port" in df.columns and "source_ip" in df.columns:
            blocked_df_scan = pd.DataFrame()
            
            if "status" in df.columns:
                status_blocked = df[df["status"].astype(str).str.lower().isin(["blocked", "denied", "drop", "deny"])].copy()
                blocked_df_scan = pd.concat([blocked_df_scan, status_blocked], ignore_index=True)
            
            if "action" in df.columns:
                action_blocked = df[df["action"].astype(str).str.upper().isin(["DENY", "BLOCK", "DROP", "BLOCKED", "DENIED"])].copy()
                blocked_df_scan = pd.concat([blocked_df_scan, action_blocked], ignore_index=True)
            
            if not blocked_df_scan.empty:
                blocked_df_scan = blocked_df_scan.drop_duplicates()
            
            if not blocked_df_scan.empty and "dest_port" in blocked_df_scan.columns:
                for src_ip, group in blocked_df_scan.groupby("source_ip"):
                    ports = pd.to_numeric(group["dest_port"], errors="coerce").dropna().unique()
                    
                    # Threshold: 5+ unique ports
                    if len(ports) >= 5 and len(group) >= 5:
                        username = get_user_from_ip(src_ip)
                        
                        # Use unified scoring
                        score_data = scoring.get_alert_metadata("firewall_port_scan", [])
                        
                        alerts.append({
                            "type": "firewall_port_scan",
                            "subject": username,
                            "severity": score_data["severity"],
                            "score": score_data["score"],
                            "text": f"Port scanning detected: {username} (IP: {src_ip}) attempted connections to {len(ports)} different ports.",
                            "evidence": {
                                "source_ip": str(src_ip),
                                "username": username,
                                "port_count": int(len(ports)),
                                "ports": [int(p) for p in sorted(ports)[:20]],
                                "attempt_count": int(len(group)),
                            },
                            "prompt_ctx": {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "port_scan", "ports": len(ports)},
                                "time": None,
                                "baseline": {"max_normal_ports": 2},
                                "extras": {"reason": "Multiple port access attempts indicate scanning activity"},
                            },
                        })
        
        # ===== DETECTION 4: POLICY EVASION =====
        # Unusual successful connections that bypass normal deny patterns
        # Check BOTH status AND action columns for allowed patterns
        allowed_df_policy = pd.DataFrame()
        
        if "dest_port" in df.columns:
            if "status" in df.columns:
                status_allowed = df[df["status"].astype(str).str.lower().isin(["allowed", "accepted", "permit", "allow"])].copy()
                allowed_df_policy = pd.concat([allowed_df_policy, status_allowed], ignore_index=True)
            
            if "action" in df.columns:
                action_allowed = df[df["action"].astype(str).str.upper().isin(["ALLOW", "ACCEPT", "PERMIT", "ALLOWED"])].copy()
                allowed_df_policy = pd.concat([allowed_df_policy, action_allowed], ignore_index=True)
            
            if not allowed_df_policy.empty:
                allowed_df_policy = allowed_df_policy.drop_duplicates()
            
            if not allowed_df_policy.empty:
                # Look for connections to sensitive ports (e.g., 22, 23, 3389, 445)
                sensitive_ports = [22, 23, 3389, 445, 1433, 3306, 5432]
                allowed_df_policy["port_num"] = pd.to_numeric(allowed_df_policy["dest_port"], errors="coerce")
                sensitive_df = allowed_df_policy[allowed_df_policy["port_num"].isin(sensitive_ports)]
                
                if not sensitive_df.empty:
                    # Group by source IP
                    for src_ip, group in sensitive_df.groupby("source_ip"):
                        sensitive_count = len(group)
                        ports_accessed = group["port_num"].dropna().unique()
                        
                        # Threshold: 3+ connections to sensitive ports
                        if sensitive_count >= 3:
                            username = get_user_from_ip(src_ip)
                            
                            # Use unified scoring
                            score_data = scoring.get_alert_metadata("firewall_policy_evasion", [])
                            
                            alerts.append({
                                "type": "firewall_policy_evasion",
                                "subject": username,
                                "severity": score_data["severity"],
                                "score": score_data["score"],
                                "text": f"Policy evasion suspected: {username} (IP: {src_ip}) accessed {len(ports_accessed)} sensitive service(s) ({sensitive_count} connections).",
                                "evidence": {
                                    "source_ip": str(src_ip),
                                    "username": username,
                                    "sensitive_ports": [int(p) for p in ports_accessed],
                                    "connection_count": int(sensitive_count),
                                },
                                "prompt_ctx": {
                                    "user": username,
                                    "group": None,
                                    "behavior": {"type": "policy_evasion", "ports": [int(p) for p in ports_accessed]},
                                    "time": None,
                                    "baseline": {"allowed_sensitive_ports": []},
                                    "extras": {"reason": "Access to sensitive services may bypass security policies"},
                                },
                            })
    
    except Exception as e:
        # Silently skip on error
        pass
    
    # ===== DETECTION 5: DATA EXFILTRATION =====
    # Detect abnormally large data transfers to external IPs
    try:
        # Helper function to detect external (non-RFC1918) IPs
        def is_external_ip(ip_str):
            """Check if IP is external (not RFC1918 private IP)."""
            if not ip_str or pd.isna(ip_str):
                return False
            try:
                ip_str = str(ip_str).strip()
                parts = ip_str.split('.')
                if len(parts) != 4:
                    return False
                octets = [int(p) for p in parts]
                
                # RFC1918 private ranges
                if octets[0] == 10:
                    return False
                if octets[0] == 172 and 16 <= octets[1] <= 31:
                    return False
                if octets[0] == 192 and octets[1] == 168:
                    return False
                if octets[0] == 127:  # Loopback
                    return False
                
                return True
            except Exception:
                return False
        
        # Filter to ALLOW actions with bytes_sent field and external destinations
        if "action" in df.columns and ("bytes_sent" in df.columns or "bytes" in df.columns):
            allowed_df_exfil = df[df["action"].astype(str).str.upper().isin(["ALLOW", "ALLOWED", "ACCEPT", "PASS"])].copy()
            
            if not allowed_df_exfil.empty:
                # Use bytes_sent or bytes column
                bytes_col = "bytes_sent" if "bytes_sent" in allowed_df_exfil.columns else "bytes"
                
                if bytes_col in allowed_df_exfil.columns:
                    # Convert bytes to numeric
                    allowed_df_exfil["bytes_num"] = pd.to_numeric(allowed_df_exfil[bytes_col], errors="coerce")
                    
                    # Filter to external destinations only
                    if "dest_ip" in allowed_df_exfil.columns:
                        allowed_df_exfil["is_external"] = allowed_df_exfil["dest_ip"].apply(is_external_ip)
                        external_df = allowed_df_exfil[allowed_df_exfil["is_external"] == True].copy()
                        
                        if not external_df.empty and "bytes_num" in external_df.columns:
                            # Strategy 1: Absolute threshold - single connection >10 MB
                            EXFIL_BYTE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
                            large_transfers = external_df[external_df["bytes_num"] > EXFIL_BYTE_THRESHOLD]
                            
                            for _, row in large_transfers.iterrows():
                                bytes_val = row["bytes_num"]
                                src_ip = row.get("source_ip", "unknown")
                                dest_ip = row.get("dest_ip", "unknown")
                                dest_host = row.get("dst_host", dest_ip)
                                username = get_user_from_ip(src_ip)
                                
                                bytes_mb = bytes_val / (1024 * 1024)
                                
                                # Use unified scoring
                                score_data = scoring.get_alert_metadata("firewall_exfiltration", [])
                                
                                alerts.append({
                                    "type": "firewall_exfiltration",
                                    "subject": username,
                                    "severity": score_data["severity"],
                                    "score": score_data["score"],
                                    "text": f"Data exfiltration detected: {username} transferred {bytes_mb:.1f} MB to external IP {dest_host}.",
                                    "evidence": {
                                        "username": username,
                                        "source_ip": str(src_ip),
                                        "dest_ip": str(dest_ip),
                                        "dest_host": str(dest_host),
                                        "bytes_transferred": int(bytes_val),
                                        "bytes_mb": round(bytes_mb, 2),
                                        "threshold_mb": 10.0,
                                        "detection_method": "bytes_threshold",
                                    },
                                    "prompt_ctx": {
                                        "user": username,
                                        "group": None,
                                        "behavior": {
                                            "type": "data_exfiltration",
                                            "bytes": int(bytes_val),
                                            "destination": str(dest_host),
                                        },
                                        "time": None,
                                        "baseline": {"normal_bytes": 1200000},  # ~1.2 MB baseline
                                        "extras": {"reason": "Abnormally large data transfer to external IP may indicate exfiltration"},
                                    },
                                })
                            
                            # Strategy 2: Statistical anomaly - group by user and detect outliers
                            if "source_ip" in external_df.columns:
                                for src_ip, group in external_df.groupby("source_ip"):
                                    valid_bytes = group["bytes_num"].dropna()
                                    
                                    if len(valid_bytes) >= 3:  # Need at least 3 samples
                                        mean_bytes = valid_bytes.mean()
                                        std_bytes = valid_bytes.std()
                                        
                                        if std_bytes > 0 and mean_bytes > 0:
                                            # Find outliers: >5x mean or Z-score >3
                                            threshold_mult = max(mean_bytes * 5, 5 * 1024 * 1024)  # At least 5MB
                                            outliers = valid_bytes[valid_bytes > threshold_mult]
                                            
                                            if len(outliers) > 0:
                                                username = get_user_from_ip(src_ip)
                                                max_transfer = outliers.max()
                                                max_mb = max_transfer / (1024 * 1024)
                                                mean_mb = mean_bytes / (1024 * 1024)
                                                z_score = (max_transfer - mean_bytes) / std_bytes if std_bytes > 0 else 0
                                                
                                                # Only alert if significantly anomalous
                                                if z_score >= 3 or max_transfer > threshold_mult:
                                                    # Find the row with max transfer
                                                    max_row = group[group["bytes_num"] == max_transfer].iloc[0]
                                                    dest_ip = max_row.get("dest_ip", "unknown")
                                                    dest_host = max_row.get("dst_host", dest_ip)
                                                    
                                                    score_data = scoring.get_alert_metadata("firewall_exfiltration", [])
                                                    
                                                    alerts.append({
                                                        "type": "firewall_exfiltration",
                                                        "subject": username,
                                                        "severity": score_data["severity"],
                                                        "score": score_data["score"],
                                                        "text": f"Statistical data exfiltration anomaly: {username} transferred {max_mb:.1f} MB to {dest_host} (baseline: {mean_mb:.1f} MB, Z-score: {z_score:.1f}).",
                                                        "evidence": {
                                                            "username": username,
                                                            "source_ip": str(src_ip),
                                                            "dest_ip": str(dest_ip),
                                                            "dest_host": str(dest_host),
                                                            "bytes_transferred": int(max_transfer),
                                                            "bytes_mb": round(max_mb, 2),
                                                            "baseline_mb": round(mean_mb, 2),
                                                            "z_score": round(z_score, 2),
                                                            "detection_method": "statistical_anomaly",
                                                        },
                                                        "prompt_ctx": {
                                                            "user": username,
                                                            "group": None,
                                                            "behavior": {
                                                                "type": "data_exfiltration_statistical",
                                                                "bytes": int(max_transfer),
                                                                "baseline_bytes": int(mean_bytes),
                                                            },
                                                            "time": None,
                                                            "baseline": {"normal_bytes": int(mean_bytes)},
                                                            "extras": {"reason": "Data transfer significantly exceeds user baseline"},
                                                        },
                                                    })
    except Exception as e:
        # Silently skip on error
        pass
    
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
        
        # ALWAYS extract username from Apache log message (may override existing username column)
        if "message" in apache_df.columns:
            def extract_apache_user(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                # Pattern: IP - username [timestamp] "METHOD
                match = re.search(r'\d+\.\d+\.\d+\.\d+\s+-\s+(\S+)\s+\[', msg)
                if match:
                    user = match.group(1)
                    return user if user != "-" else None
                return None
            apache_df["extracted_username"] = apache_df["message"].apply(extract_apache_user)
            
            # Override username column with extracted value if extraction was successful
            valid_extractions = apache_df["extracted_username"].notna().sum()
            import sys
            print(f"[DEBUG] Extracted {valid_extractions} usernames from {len(apache_df)} Apache log entries", file=sys.stderr)
            
            if valid_extractions > 0:
                if "username" in apache_df.columns:
                    # Merge: use extracted if available, otherwise keep original
                    apache_df["username"] = apache_df["extracted_username"].fillna(apache_df["username"])
                else:
                    apache_df["username"] = apache_df["extracted_username"]
                    
                unique_users = apache_df["username"].dropna().nunique()
                sample_users = apache_df["username"].dropna().unique().tolist()[:5]
                print(f"[DEBUG] Total unique users in Apache logs: {unique_users}, samples: {sample_users}", file=sys.stderr)
        
        # Convert status to numeric for all detections
        apache_df["status_code"] = pd.to_numeric(apache_df[status_col], errors="coerce")
        
        
        # Extract additional fields needed for user behavior analysis
        if "method" not in apache_df.columns and "message" in apache_df.columns:
            def extract_method(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', msg, re.IGNORECASE)
                return match.group(1) if match else None
            apache_df["method"] = apache_df["message"].apply(extract_method)
        
        if "bytes_sent" not in apache_df.columns and "message" in apache_df.columns:
            def extract_bytes(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                match = re.search(r'"\s+\d+\s+(\d+)', msg)
                return match.group(1) if match else None
            apache_df["bytes_sent"] = apache_df["message"].apply(extract_bytes)
        apache_df["bytes_num"] = pd.to_numeric(apache_df["bytes_sent"], errors="coerce")
        
        # ============================================================
        # USER-CENTRIC DETECTION: Track all behaviors per user
        # ============================================================
        from collections import defaultdict
        user_activities = defaultdict(lambda: {
            "account_takeover": False,
            "takeover_ips": [],
            "account_takeover_internal": False,
            "takeover_ips_internal": [],
            "total_200_success_internal": 0,
            "internal_movement": False,
            "internal_ips": [],
            "exfiltration_files": [],
            "suspicious_operations": [],
            "all_source_ips": set(),
            "total_401_failures": 0,
            "total_200_success": 0,
        })
        
        # Step 1: Detect Brute Force & Account Takeover
        auth_failures = apache_df[apache_df["status_code"] == 401]
        print(f"[DEBUG] Found {len(auth_failures)} total 401 auth failures", file=sys.stderr)
        
        if len(auth_failures) > 5:
            # Get all IPs involved in brute force
            ip_failure_counts = auth_failures["source_ip"].value_counts()
            all_ips = ip_failure_counts.index.tolist()
            
            # Track 401 failures per user
            for idx, row in auth_failures.iterrows():
                username = row.get("username")
                if pd.notna(username) and username != "-":
                    user_activities[username]["total_401_failures"] += 1
                    user_activities[username]["all_source_ips"].add(row.get("source_ip"))
            
            # ============================================================
            # ACCOUNT TAKEOVER DETECTION (FIXED - No False Positives)
            # ============================================================
            # OLD WRONG LOGIC:
            #   all_ips = [IPs with 401]
            #   successful_logins = [200 OK from any IP in all_ips]
            #   => Flag ALL as takeover (FALSE POSITIVE for normal users)
            #
            # NEW CORRECT LOGIC:
            #   For each IP:
            #     IF same IP has BOTH 401 failures AND 200 success:
            #       => Account Takeover (attacker succeeded!)
            #     ELSE:
            #       => Just brute force attempt, no compromise
            
            print(f"[DEBUG] Checking {len(all_ips)} IPs for Account Takeover (SAME IP must have both 401+200)", file=sys.stderr)
            
            # Helper function to check if IP is public
            def is_public_ip(ip_str):
                if pd.isna(ip_str):
                    return False
                ip = str(ip_str)
                # Private IP ranges: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
                if ip.startswith("10.") or ip.startswith("192.168."):
                    return False
                if ip.startswith("172."):
                    try:
                        second_octet = int(ip.split(".")[1])
                        if 16 <= second_octet <= 31:
                            return False
                    except:
                        pass
                return True  # Assume public if not in private ranges
            
            # For each IP that had failures, check if it ALSO had successes
            takeover_count_public = 0
            takeover_count_internal = 0
            
            for ip in all_ips:
                # Get failures from THIS IP
                ip_failures = auth_failures[auth_failures["source_ip"] == ip]
                
                # Get successes from THIS SAME IP
                ip_successes = apache_df[(apache_df["source_ip"] == ip) & (apache_df["status_code"] == 200)]
                
                # ONLY flag if SAME IP has BOTH failures and successes
                if len(ip_failures) > 0 and len(ip_successes) > 0:
                    # This IP tried many times (401) then succeeded (200) = Real Attack!
                    compromised_users = ip_successes["username"].dropna().unique().tolist()
                    is_public = is_public_ip(ip)
                    
                    for user in compromised_users:
                        if user and user != "-":
                            user_logins = ip_successes[ip_successes["username"] == user]
                            
                            if is_public:
                                # PUBLIC IP: CRITICAL 10.0 - External attack!
                                user_activities[user]["account_takeover"] = True
                                if ip not in user_activities[user]["takeover_ips"]:
                                    user_activities[user]["takeover_ips"].append(ip)
                                user_activities[user]["total_200_success"] += len(user_logins)
                                takeover_count_public += 1
                                print(f"[DEBUG] Account Takeover (Public) detected: {user} from {ip}", file=sys.stderr)
                            else:
                                # PRIVATE IP: WARNING 6.5 - Internal suspicious activity
                                # Downgraded from CRITICAL per user feedback
                                user_activities[user]["account_takeover_internal"] = True
                                if ip not in user_activities[user]["takeover_ips_internal"]:
                                    user_activities[user]["takeover_ips_internal"].append(ip)
                                user_activities[user]["total_200_success_internal"] += len(user_logins)
                                takeover_count_internal += 1
                                # DON'T print debug for internal - too noisy
            
            if takeover_count_public > 0:
                print(f"[DEBUG] Total Account Takeover (Public): {takeover_count_public} instances", file=sys.stderr)
            if takeover_count_internal > 0:
                print(f"[DEBUG] Total Account Takeover (Internal): {takeover_count_internal} instances (WARNING level)", file=sys.stderr)
        
        # Step 2: Detect Data Exfiltration (large file downloads)
        export_patterns = [r"/export/", r"/download/", r"\.csv", r"\.zip", r"\.sql", r"/backup", r"all_customers", r"full_dump", r"all_invoices", r"/leads"]
        export_requests = apache_df[apache_df["path"].str.contains("|".join(export_patterns), case=False, regex=True, na=False)]
        
        if len(export_requests) > 0:
            large_exports = export_requests[export_requests["bytes_num"] > 50000]  # >50KB
            print(f"[DEBUG] Found {len(large_exports)} large file downloads (>50KB)", file=sys.stderr)
            
            for idx, row in large_exports.iterrows():
                username = row.get("username")
                if pd.notna(username) and username != "-":
                    user_activities[username]["exfiltration_files"].append({
                        "path": row.get("path"),
                        "size_mb": round(row.get("bytes_num", 0) / 1024 / 1024, 2),
                        "timestamp": str(row.get("timestamp", ""))
                    })
                    user_activities[username]["all_source_ips"].add(row.get("source_ip"))
        
        # Step 3: Detect Suspicious Operations (DELETE requests + 500 errors)
        delete_requests = apache_df[apache_df["method"].astype(str).str.upper() == "DELETE"]
        server_errors = apache_df[apache_df["status_code"] == 500]
        
        for idx, row in delete_requests.iterrows():
            username = row.get("username")
            if pd.notna(username) and username != "-":
                user_activities[username]["suspicious_operations"].append({
                    "type": "DELETE",
                    "path": row.get("path"),
                    "status": int(row.get("status_code", 0)),
                    "timestamp": str(row.get("timestamp", ""))
                })
        
        for idx, row in server_errors.iterrows():
            username = row.get("username")
            if pd.notna(username) and username != "-":
                user_activities[username]["suspicious_operations"].append({
                    "type": "500_ERROR",
                    "path": row.get("path"),
                    "method": row.get("method"),
                    "timestamp": str(row.get("timestamp", ""))
                })
        
        # ============================================================
        # Generate Per-User Alerts
        # ============================================================
        print(f"[DEBUG] Generating alerts for {len(user_activities)} users", file=sys.stderr)
        
        for username, activities in user_activities.items():
            # Skip if user has no significant activities
            if (not activities["account_takeover"] and 
                not activities["account_takeover_internal"] and
                not activities["internal_movement"] and
                len(activities["exfiltration_files"]) == 0 and 
                len(activities["suspicious_operations"]) == 0 and
                activities["total_401_failures"] < 5):
                continue
            
            # ============================================================
            # MULTIPLE ALERTS PER USER (separate by behavior type)
            # ============================================================
            
            # ALERT 1: Account Takeover from Public IPs
            if activities["account_takeover"]:
                ips_str = ", ".join(activities["takeover_ips"][:3])
                alert_text = f"User {username}: Account Takeover from PUBLIC IPs - {len(activities['takeover_ips'])} external IPs ({ips_str})"
                
                # Use unified scoring - public IP takeover = highest severity
                score_data = scoring.get_alert_metadata("account_takeover", ["public_ip", "confirmed_success"])
                
                alerts.append({
                    "type": "account_takeover",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "takeover_ips": activities["takeover_ips"],
                        "total_200_success": activities["total_200_success"],
                        "ip_classification": "public"
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "account_takeover", "from_public_ip": True}},
                })
            
            # ALERT 1B: Account Takeover from Private IPs
            if activities["account_takeover_internal"]:
                ips_str = ", ".join(activities["takeover_ips_internal"][:3])
                alert_text = f"User {username}: Suspicious activity - Login from internal IP after brute force - {len(activities['takeover_ips_internal'])} IPs ({ips_str})"
                
                # Use unified scoring - internal IP modifier reduces score
                score_data = scoring.get_alert_metadata("account_takeover_internal", ["internal_ip"])
                
                alerts.append({
                    "type": "account_takeover_internal",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "takeover_ips": activities["takeover_ips_internal"],
                        "total_200_success": activities["total_200_success_internal"],
                        "ip_classification": "private"
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "suspicious_internal_login", "from_public_ip": False}},
                })
            
            # ALERT 2: Internal Movement - from Private IPs
            if activities["internal_movement"]:
                alert_text = f"User {username}: Suspicious internal movement - Login from {len(activities['internal_ips'])} different internal IPs"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("internal_movement", ["internal_ip"])
                
                alerts.append({
                    "type": "internal_movement",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "internal_ips": activities["internal_ips"],
                        "ip_classification": "private"
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "lateral_movement"}},
                })
            
            # ALERT 3: Data Exfiltration
            if len(activities["exfiltration_files"]) > 0:
                total_mb = sum(f["size_mb"] for f in activities["exfiltration_files"])
                file_names = [f["path"] for f in activities["exfiltration_files"][:3]]
                alert_text = f"User {username}: Downloaded {len(activities['exfiltration_files'])} large files ({total_mb:.1f}MB) - {', '.join(file_names)}"
                
                # Use unified scoring - add sensitive_data modifier if large volume
                modifiers = ["sensitive_data"] if total_mb > 5 else []
                score_data = scoring.get_alert_metadata("data_exfiltration", modifiers)
                
                alerts.append({
                    "type": "data_exfiltration",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "exfiltration_files_count": len(activities["exfiltration_files"]),
                        "exfiltration_total_mb": round(total_mb, 2),
                        "exfiltration_files": activities["exfiltration_files"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "data_exfiltration"}},
                })
            
            # ALERT 4: Suspicious Operations
            if len(activities["suspicious_operations"]) > 0:
                delete_count = sum(1 for op in activities["suspicious_operations"] if op["type"] == "DELETE")
                error_count = sum(1 for op in activities["suspicious_operations"] if op["type"] == "500_ERROR")
                
                if delete_count > 0 and error_count > 0:
                    alert_text = f"User {username}: {delete_count} DELETE requests + {error_count} 500 errors"
                elif delete_count > 0:
                    alert_text = f"User {username}: {delete_count} DELETE requests"
                else:
                    alert_text = f"User {username}: {error_count} 500 server errors"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("suspicious_operations", [])
                
                alerts.append({
                    "type": "suspicious_operations",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "suspicious_operations_count": len(activities["suspicious_operations"]),
                        "delete_count": delete_count,
                        "error_count": error_count,
                        "suspicious_operations": activities["suspicious_operations"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "suspicious_operations"}},
                })
            
            # ALERT 5: Brute Force Target
            if activities["total_401_failures"] >= 10 and not activities["account_takeover"]:
                alert_text = f"User {username}: Brute force target - {activities['total_401_failures']} failed login attempts"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("brute_force_target", [])
                
                alerts.append({
                    "type": "brute_force_target",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "total_401_failures": activities["total_401_failures"],
                        "all_source_ips": list(activities["all_source_ips"])[:10]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "brute_force_target"}},
                })
        
        print(f"[DEBUG] Generated {len(alerts)} user-based alerts", file=sys.stderr)
    
    except Exception as e:
        import sys
        import traceback
        print(f"[DEBUG] Apache anomaly detection error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    
    return alerts

def _detect_dns_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect DNS-based attacks (amplification, DGA, NXDOMAIN storm, tunneling) - PER USER."""
    alerts = []
    
    if "program" not in df.columns or not df["program"].eq("dnsmasq").any():
        return alerts
    
    try:
        dns_df = df[df["program"] == "dnsmasq"].copy()
        if dns_df.empty:
            return alerts
        
        # Extract username from DNS logs if available
        # DNS logs may have username in message or separate field
        if "username" not in dns_df.columns and "message" in dns_df.columns:
            def extract_dns_user(msg):
                if pd.isna(msg) or not isinstance(msg, str):
                    return None
                # Try to extract user from DNS log message
                match = re.search(r'user[=:](\S+)', msg, re.IGNORECASE)
                return match.group(1) if match else None
            dns_df["username"] = dns_df["message"].apply(extract_dns_user)
        
        # If still no username, prefer hostname over IP
        if "username" not in dns_df.columns or dns_df["username"].isna().all():
            # Priority 1: Use 'host' or 'hostname' field if available  
            if "host" in dns_df.columns:
                dns_df["username"] = dns_df["host"].fillna("unknown")
            elif "hostname" in dns_df.columns:
                dns_df["username"] = dns_df["hostname"].fillna("unknown")
            # Priority 2: Fallback to source_ip
            elif "source_ip" in dns_df.columns:
                dns_df["username"] = dns_df["source_ip"].fillna("unknown")
            else:
                dns_df["username"] = "unknown"
        
        import sys
        from collections import defaultdict
        
        # Track DNS activities per user
        user_activities = defaultdict(lambda: {
            "amplification_queries": [],
            "nxdomain_queries": [],
            "suspicious_domains": [],
            "tunneling_queries": [],
            "total_queries": 0,
        })
        
        # Track queries per user
        for idx, row in dns_df.iterrows():
            username = row.get("username")
            if pd.isna(username) or username == "-":
                username = row.get("source_ip", "unknown")
            
            user_activities[username]["total_queries"] += 1
            
            # Track amplification (LARGE_ANSWER status)
            if row.get("status") == "large_answer":
                user_activities[username]["amplification_queries"].append({
                    "domain": row.get("domain"),
                    "timestamp": str(row.get("timestamp", ""))
                })
            
            # Track NXDOMAIN
            status_val = row.get("status")
            if status_val == "nxdomain":
                user_activities[username]["nxdomain_queries"].append({
                    "domain": row.get("domain"),
                    "timestamp": str(row.get("timestamp", ""))
                })
            elif "NXDOMAIN" in str(row.get("message", "")) and status_val != "nxdomain":
                # Debug: NXDOMAIN in message but status is not "nxdomain"
                print(f"[DEBUG] DNS: NXDOMAIN in message but status={status_val}, message={str(row.get('message', ''))[:80]}", file=sys.stderr)
            
            
            # Track suspicious domains (DGA-like)
            domain = str(row.get("domain", ""))
            if domain and len(domain) > 10:
                # Simple DGA heuristic: long domain with few vowels
                if len(domain) > 20 or (len(domain) > 10 and not any(c in domain.lower() for c in "aeiou")):
                    user_activities[username]["suspicious_domains"].append({
                        "domain": domain,
                        "timestamp": str(row.get("timestamp", ""))
                    })
            
            # Track DNS tunneling (TXT queries with suspicious patterns)
            if row.get("query_type") == "TXT" and pd.notna(row.get("domain")):
                if any(pattern in str(row.get("domain", "")).lower() for pattern in ["_dns", "exfil", "tunnel"]):
                    user_activities[username]["tunneling_queries"].append({
                        "domain": row.get("domain"),
                        "timestamp": str(row.get("timestamp", ""))
                    })
        
        
        print(f"[DEBUG] DNS: Analyzing {len(user_activities)} users/IPs", file=sys.stderr)
        
        # Debug: Print NXDOMAIN counts for each user
        for username, activities in user_activities.items():
            nxdomain_count = len(activities["nxdomain_queries"])
            if nxdomain_count > 0:
                print(f"[DEBUG] DNS: User {username} has {nxdomain_count} NXDOMAIN queries", file=sys.stderr)
        
        # Generate alerts per user
        for username, activities in user_activities.items():
            # ALERT 1: DNS Amplification
            if len(activities["amplification_queries"]) >= 3:
                alert_text = f"User/IP {username}: {len(activities['amplification_queries'])} DNS amplification queries (LARGE_ANSWER/NSEC)"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dns_amplification", [])
                
                alerts.append({
                    "type": "dns_amplification",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "amplification_count": len(activities["amplification_queries"]),
                        "examples": activities["amplification_queries"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "dns_amplification"}},
                })
            
            # ALERT 2: NXDOMAIN Flood
            if len(activities["nxdomain_queries"]) >= 10:
                alert_text = f"User/IP {username}: {len(activities['nxdomain_queries'])} NXDOMAIN queries (potential scanning)"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dns_nxdomain_flood", [])
                
                alerts.append({
                    "type": "dns_nxdomain_flood",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "nxdomain_count": len(activities["nxdomain_queries"]),
                        "examples": activities["nxdomain_queries"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "dns_nxdomain_flood"}},
                })
            
            # ALERT 2B: NXDOMAIN Storm (DoS Attack)
            # Detect high-volume NXDOMAIN in short time = DNS DoS attack
            if len(activities["nxdomain_queries"]) >= 50:
                # Calculate time span for the NXDOMAIN queries
                try:
                    timestamps = [pd.to_datetime(q["timestamp"]) for q in activities["nxdomain_queries"] if q.get("timestamp")]
                    if timestamps:
                        timestamps = [ts for ts in timestamps if pd.notna(ts)]  # Filter out invalid timestamps
                        
                        if len(timestamps) >= 2:
                            time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60  # Convert to minutes
                            
                            # If 50+ NXDOMAIN in < 15 minutes = Storm attack (DoS)
                            if time_span < 15:
                                alert_text = f"User/IP {username}: {len(activities['nxdomain_queries'])} NXDOMAIN queries in {time_span:.1f} minutes - NXDOMAIN Storm DoS attack"
                                
                                # Use unified scoring - CRITICAL severity
                                score_data = scoring.get_alert_metadata("dns_nxdomain_storm", [])
                                
                                alerts.append({
                                    "type": "dns_nxdomain_storm",
                                    "subject": username,
                                    "severity": score_data["severity"],
                                    "score": score_data["score"],
                                    "text": alert_text,
                                    "evidence": {
                                        "nxdomain_count": len(activities["nxdomain_queries"]),
                                        "duration_minutes": round(time_span, 1),
                                        "examples": activities["nxdomain_queries"][:5],
                                        "pattern": "nxdomain_storm"
                                    },
                                    "prompt_ctx": {"user": username, "behavior": {"type": "dns_nxdomain_storm"}},
                                })
                except Exception as e:
                    import sys
                    print(f"[DEBUG] NXDOMAIN Storm time calculation error: {e}", file=sys.stderr)
            
            
            # ALERT 3: Suspicious Domains (DGA/Malware)
            if len(activities["suspicious_domains"]) >= 3:
                unique_domains = list({d["domain"] for d in activities["suspicious_domains"]})
                alert_text = f"User/IP {username}: {len(unique_domains)} suspicious domains (potential DGA/malware)"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dns_suspicious_domains", [])
                
                alerts.append({
                    "type": "dns_suspicious_domains",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "suspicious_domain_count": len(unique_domains),
                        "examples": unique_domains[:5],
                        "details": activities["suspicious_domains"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "dns_dga"}},
                })
            
            # ALERT 4: DNS Tunneling
            if len(activities["tunneling_queries"]) > 0:
                alert_text = f"User/IP {username}: {len(activities['tunneling_queries'])} DNS tunneling queries (data exfiltration)"
                
                # Use unified scoring
                score_data = scoring.get_alert_metadata("dns_tunneling", [])
                
                alerts.append({
                    "type": "dns_tunneling",
                    "subject": username,
                    "severity": score_data["severity"],
                    "score": score_data["score"],
                    "text": alert_text,
                    "evidence": {
                        "tunneling_count": len(activities["tunneling_queries"]),
                        "examples": activities["tunneling_queries"][:5]
                    },
                    "prompt_ctx": {"user": username, "behavior": {"type": "dns_tunneling"}},
                })
        
        print(f"[DEBUG] DNS: Generated {len(alerts)} user-based alerts", file=sys.stderr)
    
    except Exception:
        pass
    
    return alerts

def _detect_network_link_flap(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect network link flapping (eth0 Link Up events on multiple servers).""" 
    alerts = []
    
    if "message" not in df.columns or "host" not in df.columns:
        return alerts
    
    try:
        # Filter logs with "Link is Up" pattern
        link_up_logs = df[df["message"].astype(str).str.contains(r"eth\d+:.*Link is Up", case=False, regex=True, na=False)].copy()
        
        if len(link_up_logs) == 0:
            return alerts
        
        # Count unique servers and total events
        unique_servers = link_up_logs["host"].nunique()
        total_events = len(link_up_logs)
        
        # Alert if link flap affects many servers (network infrastructure issue)
        if unique_servers >= 10 or total_events >= 20:
            # Get affected servers list
            affected_servers = link_up_logs["host"].unique().tolist()[:15]  # Top 15
            
            alert_text = f"Network link flap detected: eth0 Link Up on {unique_servers} servers ({total_events} events)"
            
            # Calculate score first, then derive severity from score
            link_flap_score = min(8.0 + (unique_servers / 10), 10.0)
            
            alerts.append({
                "type": "network_link_flap",
                "subject": "Network Infrastructure",
                "severity": scoring.get_severity(link_flap_score),  # Use unified scoring
                "score": link_flap_score,
                "text": alert_text,
                "evidence": {"unique_servers": int(unique_servers), "total_events": int(total_events), "affected_servers": [str(s) for s in affected_servers]},
                "prompt_ctx": {"behavior": {"type": "network_link_flap"}},
            })
    except Exception as e:
        import sys
        print(f"[DEBUG] Network link flap error: {e}", file=sys.stderr)
    return alerts

def _detect_cron_job_overlap(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect cron job overlaps (same script running multiple times by different users)."""
    alerts = []
    if "message" not in df.columns or "program" not in df.columns:
        return alerts
    try:
        cron_logs = df[df["program"].astype(str).str.contains(r"cron\[", case=False, na=False)].copy()
        if len(cron_logs) == 0:
            return alerts
        cron_logs["cron_user"] = cron_logs["message"].str.extract(r"\(([^)]+)\)\s+CMD", flags=re.IGNORECASE)[0]
        cron_logs["cron_script"] = cron_logs["message"].str.extract(r"CMD\s+\(([^)]+)\)", flags=re.IGNORECASE)[0]
        cron_logs = cron_logs[cron_logs["cron_script"].notna() & cron_logs["cron_user"].notna()]
        if len(cron_logs) == 0:
            return alerts
        for script, group in cron_logs.groupby("cron_script"):
            execution_count = len(group)
            unique_users = group["cron_user"].nunique()
            users_list = group["cron_user"].unique().tolist()
            if execution_count >= 10 and unique_users >= 3:
                host = group["host"].iloc[0] if "host" in group.columns else "unknown"
                alert_text = f"Cron job overlap: script '{script}' executed {execution_count} times by {unique_users} users. ⚠️ Có thể là kỹ thuật Defense Evasion - lợi dụng tiến trình backup/cron hợp pháp để che giấu hành vi đáng ngờ."
                
                # Calculate score first, then derive severity from score
                cron_score = min(5.0 + (execution_count / 10), 8.0)
                
                alerts.append({
                    "type": "cron_job_overlap",
                    "subject": str(host),
                    "severity": scoring.get_severity(cron_score),  # Use unified scoring
                    "score": cron_score,
                    "text": alert_text,
                    "evidence": {"script": str(script), "execution_count": int(execution_count), "unique_users": int(unique_users), "users": [str(u) for u in users_list]},
                    "prompt_ctx": {
                        "behavior": {
                            "type": "cron_job_overlap",
                            "defense_evasion_warning": "Đây có thể là kỹ thuật ẩn mình (Defense Evasion), lợi dụng tiến trình backup/cron hợp pháp để che giấu hành vi gửi dữ liệu trái phép ra ngoài hoặc thực thi mã độc."
                        }
                    },
                })
    except Exception as e:
        import sys
        print(f"[DEBUG] Cron overlap error: {e}", file=sys.stderr)
    return alerts

def _detect_privilege_escalation(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect privilege escalation - USER-CENTRIC detection.
    
    Detects non-admin users reloading/restarting system services (nginx, apache, mysql, etc.)
    which indicates potential privilege abuse or account compromise.
    """
    alerts = []
    if "message" not in df.columns:
        return alerts
    
    try:
        # Define ADMIN users who ARE allowed to reload services (whitelist approach)
        # Anyone NOT in this list who reloads services is suspicious
        admin_users = ["root", "admin", "sysadmin", "operator", "ops", "www-data", "nginx", "apache", "mysql", "postgres"]
        
        # Track detected users to avoid duplicates for same user/host combo
        detected_privesc = set()
        
        for _, row in df.iterrows():
            msg = str(row.get("message", ""))
            host = str(row.get("host", "unknown"))
            
            # Check for service reload pattern with "requested by" user
            requested_match = re.search(r"Reload(ing)?\s+(\w+)\s+server.*requested\s+by\s+(\w+)", msg, re.IGNORECASE)
            if requested_match:
                service_name = requested_match.group(2)
                username = requested_match.group(3)
                
                # Unique key to avoid duplicate alerts for same user+host+service
                alert_key = (username, host, service_name)
                if alert_key in detected_privesc:
                    continue
                detected_privesc.add(alert_key)
                
                # Check if user is NOT an admin (whitelist approach)
                is_non_admin = username.lower() not in admin_users
                
                if is_non_admin:
                    # This is suspicious - non-admin reloading system service
                    priv_score = 8.5  # High score - privilege escalation
                    
                    alerts.append({
                        "type": "privilege_escalation",
                        "subject": username,  # USER-CENTRIC: subject is the USER
                        "severity": scoring.get_severity(priv_score),
                        "score": priv_score,
                        "text": f"Privilege escalation detected: Non-admin user '{username}' reloaded {service_name} server on {host}.",
                        "evidence": {
                            "username": username,
                            "service": service_name,
                            "action": "reload",
                            "host": host,
                            "message": msg[:200],
                        },
                        "prompt_ctx": {
                            "user": username,
                            "group": None,
                            "behavior": {"type": "privilege_escalation", "service": service_name, "action": "reload"},
                            "time": None,
                            "baseline": {"expected_role": "admin"},
                            "extras": {"reason": "Non-admin users should not have access to reload system services"},
                        },
                    })
            
            # Also check for sudo/su commands
            sudo_match = re.search(r"sudo:\s+(\w+)\s*:", msg, re.IGNORECASE)
            if sudo_match:
                username = sudo_match.group(1)
                is_non_admin = any(pattern in username.lower() for pattern in non_admin_patterns)
                
                if is_non_admin:
                    # Check for sensitive commands
                    if re.search(r"(systemctl|service|reboot|shutdown|passwd|useradd|userdel|chmod|chown)", msg, re.IGNORECASE):
                        priv_score = 9.0  # Very high - sudo with sensitive commands
                        
                        alerts.append({
                            "type": "privilege_escalation",
                            "subject": username,
                            "severity": scoring.get_severity(priv_score),
                            "score": priv_score,
                            "text": f"Privilege escalation detected: Non-admin user '{username}' used sudo for sensitive operations.",
                            "evidence": {
                                "username": username,
                                "action": "sudo_sensitive_command",
                                "host": host,
                                "message": msg[:200],
                            },
                            "prompt_ctx": {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "privilege_escalation", "action": "sudo"},
                                "time": None,
                                "baseline": {"expected_role": "admin"},
                                "extras": {"reason": "Non-admin users using sudo for sensitive commands is highly suspicious"},
                            },
                        })
    except Exception as e:
        import sys
        print(f"[DEBUG] Privilege escalation error: {e}", file=sys.stderr)
    return alerts

def _detect_windows_lsass_dumping(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detects LSASS memory access attempts (Mimikatz, credential dumping).
    
    Pattern:
    - Sysmon EventID=10 (Process Access)
    - TargetImage contains "lsass.exe"
    - GrantedAccess indicates memory read (0x1410, 0x1FFFFF, etc.)
    """
    import sys  # Required for debug output
    import re
    alerts = []
    
    if df.empty:
        return alerts
    
    # Handle column name variations (EventID vs event_id)
    event_id_col = None
    for col in ["EventID", "event_id"]:
        if col in df.columns:
            event_id_col = col
            break
    
    if event_id_col is None:
        print(f"[DEBUG LSASS] No EventID/event_id column. Columns: {list(df.columns)[:15]}", file=sys.stderr)
        return alerts
    
    print(f"[DEBUG LSASS] DataFrame has {len(df)} rows, using column '{event_id_col}'", file=sys.stderr)
    
    try:
        # Filter for EventID=10 (Process Access)
        eid_10_df = df[df[event_id_col].astype(str) == "10"].copy()
        
        print(f"[DEBUG LSASS] EventID=10 count: {len(eid_10_df)}", file=sys.stderr)
        print(f"[DEBUG LSASS] Available columns: {list(eid_10_df.columns)}", file=sys.stderr)
        
        if eid_10_df.empty:
            return alerts
        
        # Check if TargetImage is already a column (preprocess may have extracted it)
        target_image_col = None
        for col in ["TargetImage", "target_image", "targetimage"]:
            if col in eid_10_df.columns:
                target_image_col = col
                break
        
        source_image_col = None
        for col in ["SourceImage", "source_image", "sourceimage"]:
            if col in eid_10_df.columns:
                source_image_col = col
                break
        
        user_col = None
        for col in ["User", "user", "username"]:
            if col in eid_10_df.columns:
                user_col = col
                break
        
        print(f"[DEBUG LSASS] Found columns: TargetImage={target_image_col}, SourceImage={source_image_col}, User={user_col}", file=sys.stderr)
        
        # If TargetImage column exists, use it directly
        if target_image_col:
            eid_10_df["_TargetImage"] = eid_10_df[target_image_col]
            eid_10_df["_SourceImage"] = eid_10_df.get(source_image_col, "")
            eid_10_df["_User"] = eid_10_df.get(user_col, "")
            eid_10_df["_GrantedAccess"] = eid_10_df.get("GrantedAccess", eid_10_df.get("grantedaccess", ""))
        else:
            # Fallback: Try to extract from raw_line or message column
            raw_col = None
            for col in ["raw_line", "message", "raw"]:
                if col in eid_10_df.columns:
                    raw_col = col
                    break
            
            if raw_col is None:
                print(f"[DEBUG LSASS] No raw_line/message column found!", file=sys.stderr)
                return alerts
            
            print(f"[DEBUG LSASS] Extracting from '{raw_col}' column", file=sys.stderr)
            
            # Check sample raw content
            sample_raw = str(eid_10_df[raw_col].iloc[0])[:200] if len(eid_10_df) > 0 else ""
            print(f"[DEBUG LSASS] Sample {raw_col}: {sample_raw}", file=sys.stderr)
        
            # Extract fields from raw_line using regex
            def extract_field(msg, field_name):
                """Extract quoted or unquoted value from key=value pattern."""
                pattern = rf'{field_name}="([^"]+)"|{field_name}=(\S+)'
                match = re.search(pattern, str(msg), re.IGNORECASE)
                if match:
                    return match.group(1) or match.group(2)
                return None
            
            # Parse fields from raw_line
            eid_10_df["_TargetImage"] = eid_10_df[raw_col].apply(lambda m: extract_field(m, "TargetImage"))
            eid_10_df["_SourceImage"] = eid_10_df[raw_col].apply(lambda m: extract_field(m, "SourceImage"))
            eid_10_df["_GrantedAccess"] = eid_10_df[raw_col].apply(lambda m: extract_field(m, "GrantedAccess"))
            
            # Debug: check extracted values
            non_null_target = eid_10_df["_TargetImage"].notna().sum()
            print(f"[DEBUG LSASS] Extracted TargetImage: {non_null_target} non-null values", file=sys.stderr)
            
            # Get User from column or raw_line
            if user_col:
                eid_10_df["_User"] = eid_10_df[user_col]
            else:
                eid_10_df["_User"] = eid_10_df[raw_col].apply(lambda m: extract_field(m, "User"))
        
        # Filter for LSASS access
        lsass_access = eid_10_df[
            eid_10_df["_TargetImage"].astype(str).str.contains("lsass.exe", case=False, na=False)
        ].copy()
        
        print(f"[DEBUG LSASS] Found {len(lsass_access)} LSASS access events from {len(eid_10_df)} EventID=10", file=sys.stderr)
        
        if lsass_access.empty:
            return alerts
        
        # Group by user and source process
        for (user, src_image), group in lsass_access.groupby(["_User", "_SourceImage"]):
            if pd.isna(user) or str(user).strip() in ["", "(unknown)", "None"]:
                continue
                
            count = len(group)
            src_ips = group.get("source_ip", group.get("SrcIp", pd.Series(index=group.index))).dropna().unique().tolist()
            hosts = group.get("hostname", group.get("Host", pd.Series(index=group.index))).unique().tolist()
            access_rights = group["_GrantedAccess"].dropna().unique().tolist()
           
            # Score based on count and process type
            base_score = min(7.0 + (count / 10.0), 10.0)
            
            # Boost for suspicious processes
            suspicious_processes = ["powershell.exe", "rundll32.exe", "cmd.exe", "wmic.exe", "msedge.exe"]
            src_image_lower = str(src_image).lower()
            is_suspicious_process = any(proc in src_image_lower for proc in suspicious_processes)
            
            if is_suspicious_process:
                base_score = min(base_score + 2.0, 10.0)
            
            score = round(base_score, 2)
            severity = "CRITICAL" if score >= 8.5 else "WARNING"
            
            alerts.append({
                "type": "lsass_credential_dumping_detected",
                "subject": str(user),
                "severity": severity,
                "score": float(score),
                "text": f"[{severity}] LSASS memory access detected: User '{user}' accessed LSASS {count} time(s) using {src_image}",
                "evidence": {
                    "username": str(user),
                    "access_count": int(count),
                    "source_process": str(src_image),
                    "access_rights": [str(ar) for ar in access_rights],
                    "source_ips": [str(ip) for ip in src_ips if ip],
                    "affected_hosts": [str(h) for h in hosts if h],
                    "is_suspicious_process": is_suspicious_process
                },
                "prompt_ctx": {
                    "user": str(user),
                    "behavior": {"type": "lsass_credential_dumping"}
                }
            })
        
        print(f"[DEBUG LSASS] Generated {len(alerts)} alerts", file=sys.stderr)
    
    except Exception as e:
        print(f"[DEBUG LSASS] Error: {e}", file=sys.stderr)
    
    return alerts

def _detect_windows_privilege_escalation(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detects Windows privilege escalation attempts via lateral movement tools.
    
    Pattern:
    - EventID=4672 (Special privileges assigned) + EventID=4688 (Process created)
    - Suspicious processes: psexec.exe, encoded PowerShell
    """
    import sys
    import re
    alerts = []
    
    if df.empty:
        return alerts
    
    # Handle column name variations (EventID vs event_id)
    event_id_col = None
    for col in ["EventID", "event_id"]:
        if col in df.columns:
            event_id_col = col
            break
    
    if event_id_col is None:
        return alerts
    
    # Handle User column name variations
    user_col = None
    for col in ["User", "user", "username"]:
        if col in df.columns:
            user_col = col
            break
    
    if user_col is None:
        print(f"[DEBUG PRIVESC] No user column found in: {list(df.columns)[:10]}", file=sys.stderr)
        return alerts
    
    try:
        # Filter for special privilege events and process creation
        priv_events = df[df[event_id_col].astype(str) == "4672"].copy()
        proc_events = df[df[event_id_col].astype(str) == "4688"].copy()
        
        print(f"[DEBUG PRIVESC] EventID=4672 count: {len(priv_events)}, EventID=4688 count: {len(proc_events)}", file=sys.stderr)
        
        if priv_events.empty or proc_events.empty:
            return alerts
        
        # Handle NewProcessName column variations
        proc_name_col = None
        for col in ["NewProcessName", "new_process_name", "newprocessname"]:
            if col in proc_events.columns:
                proc_name_col = col
                break
        
        # Handle CommandLine column variations
        cmd_line_col = None
        for col in ["CommandLine", "command_line", "commandline"]:
            if col in proc_events.columns:
                cmd_line_col = col
                break
        
        print(f"[DEBUG PRIVESC] Columns: user={user_col}, proc_name={proc_name_col}, cmd_line={cmd_line_col}", file=sys.stderr)
        
        # If NewProcessName not found as column, extract from raw_line or message
        if proc_name_col is None:
            raw_col = "raw_line" if "raw_line" in proc_events.columns else "message" if "message" in proc_events.columns else None
            if raw_col:
                def extract_new_process_name(line):
                    match = re.search(r'NewProcessName="([^"]+)"', str(line))
                    if match:
                        return match.group(1)
                    return None
                proc_events["_new_process_name"] = proc_events[raw_col].apply(extract_new_process_name)
                proc_name_col = "_new_process_name"
        
        # If CommandLine not found as column, extract from raw_line or message
        if cmd_line_col is None:
            raw_col = "raw_line" if "raw_line" in proc_events.columns else "message" if "message" in proc_events.columns else None
            if raw_col:
                def extract_command_line(line):
                    match = re.search(r'CommandLine="([^"]+)"', str(line))
                    if match:
                        return match.group(1)
                    return None
                proc_events["_command_line"] = proc_events[raw_col].apply(extract_command_line)
                cmd_line_col = "_command_line"
        
        if proc_name_col is None:
            print(f"[DEBUG PRIVESC] No NewProcessName column or extraction method available", file=sys.stderr)
            return alerts
        
        # Ensure user column is consistently named for merge
        priv_events["_user"] = priv_events[user_col]
        proc_events["_user"] = proc_events[user_col]
        
        # Sort by timestamp for merge_asof
        priv_events = priv_events.sort_values("timestamp")
        proc_events = proc_events.sort_values("timestamp")
        
        # Join privilege events with process creation (within 10 seconds)
        merged = pd.merge_asof(
            priv_events,
            proc_events,
            on="timestamp",
            by="_user",  # Use normalized _user column
            direction="forward",
            tolerance=pd.Timedelta(seconds=10),
            suffixes=("_priv", "_proc")
        )
        
        print(f"[DEBUG PRIVESC] Merged {len(merged)} events, proc_name_col={proc_name_col}, cmd_line_col={cmd_line_col}", file=sys.stderr)
        
        # Get the right column names (after merge they might have suffix)
        proc_name_col_merged = proc_name_col + "_proc" if proc_name_col + "_proc" in merged.columns else proc_name_col
        cmd_line_col_merged = cmd_line_col + "_proc" if cmd_line_col and cmd_line_col + "_proc" in merged.columns else (cmd_line_col if cmd_line_col else None)
        
        # Filter for suspicious processes
        proc_col = merged.get(proc_name_col_merged, pd.Series("", index=merged.index)).astype(str)
        cmd_col = merged.get(cmd_line_col_merged, pd.Series("", index=merged.index)).astype(str) if cmd_line_col_merged else pd.Series("", index=merged.index)
        
        suspicious_mask = (
            (proc_col.str.contains("psexec.exe", case=False, na=False)) |
            (proc_col.str.contains("powershell.exe", case=False, na=False) & cmd_col.str.contains("-enc", case=False, na=False)) |
            (proc_col.str.contains("wmic.exe", case=False, na=False)) |
            (cmd_col.str.contains("whoami|net user|net group|\\\\\\\\", case=False, na=False, regex=True))  # Added psexec lateral movement pattern
        )
        
        merged = merged[suspicious_mask]
        
        print(f"[DEBUG PRIVESC] After suspicious filter: {len(merged)} events", file=sys.stderr)
        
        if merged.empty:
            return alerts
        
        # Group by user
        for user, group in merged.groupby("_user"):
            if pd.isna(user) or str(user).strip() in ["", "(unknown)"]:
                continue
                
            count = len(group)
            processes = group.get(proc_name_col_merged, pd.Series(index=group.index)).dropna().unique().tolist()
            hosts_priv = group.get("host_priv", group.get("Host_priv", pd.Series(index=group.index))).unique().tolist()
            src_ips = group.get("source_ip_priv", group.get("SrcIp_priv", pd.Series(index=group.index))).dropna().unique().tolist()
            
            # Detect encoded PowerShell
            cmd_vals = group.get(cmd_line_col_merged, pd.Series("", index=group.index)).astype(str) if cmd_line_col_merged else pd.Series("", index=group.index)
            proc_vals = group.get(proc_name_col_merged, pd.Series("", index=group.index)).astype(str)
            
            has_encoded_ps = cmd_vals.str.contains("-enc", case=False, na=False).any()
            has_psexec = proc_vals.str.contains("psexec", case=False, na=False).any()
            
            # Scoring
            base_score = min(7.5 + (count / 5.0), 10.0)
            
            if has_psexec:
                base_score = min(base_score + 1.5, 10.0)
            if has_encoded_ps:
                base_score = min(base_score + 1.0, 10.0)
            
            score = round(base_score, 2)
            severity = "CRITICAL" if score >= 8.0 else "WARNING"
            
            alerts.append({
                "type": "windows_privilege_escalation_detected",
                "subject": str(user),
                "severity": severity,
                "score": float(score),
                "text": f"[{severity}] Windows privilege escalation detected: User '{user}' executed {count} suspicious privileged process(es)",
                "evidence": {
                    "username": str(user),
                    "escalation_count": int(count),
                    "processes": [str(p) for p in processes],
                    "has_psexec": bool(has_psexec),
                    "has_encoded_powershell": bool(has_encoded_ps),
                    "source_ips": [str(ip) for ip in src_ips],
                    "affected_hosts": [str(h) for h in hosts_priv]
                },
                "prompt_ctx": {
                    "user": str(user),
                    "behavior": {"type": "windows_privilege_escalation"}
                }
            })
    
    except Exception as e:
        import sys
        print(f"[DEBUG] Windows privilege escalation detection error: {e}", file=sys.stderr)
    
    return alerts


def _detect_windows_schtask_persistence(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detects Windows scheduled task persistence attacks.
    
    Pattern:
    - EventID=4698 (Scheduled task created) in Security channel
    - Suspicious actions: hidden PowerShell (-enc, -WindowStyle Hidden), 
      executables in Temp folders, or scripts running from suspicious paths
    - Task names masquerading as Windows updates/maintenance
    
    MITRE ATT&CK: T1053.005 (Scheduled Task/Job)
    """
    import sys
    alerts = []
    
    if df.empty:
        return alerts
    
    # Handle column name variations
    event_id_col = None
    for col in ["EventID", "event_id"]:
        if col in df.columns:
            event_id_col = col
            break
    
    if event_id_col is None:
        return alerts
    
    try:
        # Filter for EventID 4698 (Scheduled task created)
        schtask_events = df[df[event_id_col].astype(str) == "4698"].copy()
        
        if schtask_events.empty:
            return alerts
        
        print(f"[DEBUG SCHTASK] Found {len(schtask_events)} scheduled task creation events", file=sys.stderr)
        
        # Find user column
        user_col = None
        for col in ["User", "username", "user.name"]:
            if col in schtask_events.columns:
                user_col = col
                break
        
        # Find taskname and action columns (from parsed fields or message/raw_line)
        taskname_col = None
        for col in ["TaskName", "task_name"]:
            if col in schtask_events.columns:
                taskname_col = col
                break
        
        action_col = None
        for col in ["Action", "action"]:
            if col in schtask_events.columns:
                action_col = col
                break
        
        # Extract TaskName and Action from raw_line or message if not available
        def extract_from_message(row):
            msg = ""
            if "raw_line" in row and pd.notna(row.get("raw_line")):
                msg = str(row["raw_line"])
            elif "message" in row and pd.notna(row.get("message")):
                msg = str(row["message"])
            
            task_name = None
            action = None
            
            # Extract TaskName
            tn_match = re.search(r'TaskName="([^"]+)"', msg)
            if tn_match:
                task_name = tn_match.group(1)
            
            # Extract Action
            action_match = re.search(r'Action="([^"]+)"', msg)
            if action_match:
                action = action_match.group(1)
            
            return pd.Series([task_name, action])
        
        if taskname_col is None or action_col is None:
            extracted = schtask_events.apply(extract_from_message, axis=1)
            extracted.columns = ["_task_name", "_action"]
            schtask_events = pd.concat([schtask_events, extracted], axis=1)
            taskname_col = "_task_name" if taskname_col is None else taskname_col
            action_col = "_action" if action_col is None else action_col
        
        # Define suspicious patterns
        SUSPICIOUS_ACTION_PATTERNS = [
            r"-enc\s+[A-Za-z0-9+/=]+",                    # Encoded PowerShell
            r"-EncodedCommand\s+[A-Za-z0-9+/=]+",         # Another encoded PS form
            r"-WindowStyle\s+Hidden",                      # Hidden window
            r"C:\\Windows\\Temp\\.*\.exe",                 # Exe in Temp
            r"C:\\Users\\.*\\AppData\\.*\.exe",            # Exe in AppData
            r"powershell\.exe.*(-w\s+h|-nop|-ep\s+bypass)", # Bypass execution policy
            r"cmd\.exe.*/c.*powershell",                   # cmd launching powershell
            r"regsvr32.*(/s|/u)",                          # Silent regsvr32
            r"mshta.*http[s]?://",                         # Remote HTA
            r"rundll32.*,\s*#",                            # suspicious rundll32
            r"svc\.exe",                                   # Common malware name
            r"update\.exe.*-run",                          # Suspicious update pattern
        ]
        
        # Task names that look like masquerading
        LEGITIMATE_TASK_PATTERNS = [
            r"\\Microsoft\\Windows\\",
            r"WinUpdate",
            r"Telemetry",
            r"OneDrive",
            r"Index",
            r"Sync",
        ]
        
        suspicious_tasks = []
        
        for idx, row in schtask_events.iterrows():
            task_name = str(row.get(taskname_col, "")) if pd.notna(row.get(taskname_col)) else ""
            action = str(row.get(action_col, "")) if pd.notna(row.get(action_col)) else ""
            user = str(row.get(user_col, "unknown")) if user_col and pd.notna(row.get(user_col)) else "unknown"
            host = str(row.get("Host", row.get("host", "unknown")))
            timestamp = row.get("timestamp")
            
            # Check if action is suspicious
            is_suspicious = False
            suspicious_indicators = []
            
            for pattern in SUSPICIOUS_ACTION_PATTERNS:
                if re.search(pattern, action, re.IGNORECASE):
                    is_suspicious = True
                    suspicious_indicators.append(pattern.replace("\\", "").replace(".*", "*"))
                    break
            
            # Check if task name is masquerading as Windows task
            is_masquerading = False
            for pattern in LEGITIMATE_TASK_PATTERNS:
                if re.search(pattern, task_name, re.IGNORECASE):
                    is_masquerading = True
                    break
            
            # Flag if both suspicious action AND masquerading name
            if is_suspicious or (action and is_masquerading):
                suspicious_tasks.append({
                    "user": user,
                    "host": host,
                    "task_name": task_name,
                    "action": action[:200] if len(action) > 200 else action,  # Truncate long actions
                    "timestamp": timestamp,
                    "is_masquerading": is_masquerading,
                    "indicators": suspicious_indicators
                })
        
        print(f"[DEBUG SCHTASK] Found {len(suspicious_tasks)} suspicious scheduled tasks", file=sys.stderr)
        
        if not suspicious_tasks:
            return alerts
        
        # Group by user
        from collections import defaultdict
        user_tasks = defaultdict(list)
        for task in suspicious_tasks:
            user_tasks[task["user"]].append(task)
        
        for user, tasks in user_tasks.items():
            count = len(tasks)
            hosts = list(set(t["host"] for t in tasks))
            task_names = list(set(t["task_name"][:50] for t in tasks))[:5]
            
            # Check for high-risk patterns
            has_encoded_ps = any("-enc" in t["action"].lower() for t in tasks)
            has_temp_exe = any(re.search(r"Temp\\.*\.exe", t["action"], re.IGNORECASE) for t in tasks)
            has_hidden_window = any("-windowstyle" in t["action"].lower() for t in tasks)
            
            # Scoring
            base_score = min(7.0 + (count / 3.0), 10.0)
            
            if has_encoded_ps:
                base_score = min(base_score + 1.5, 10.0)
            if has_temp_exe:
                base_score = min(base_score + 1.0, 10.0)
            if has_hidden_window:
                base_score = min(base_score + 0.5, 10.0)
            
            score = round(base_score, 2)
            severity = "CRITICAL" if score >= 8.0 else "WARNING"
            
            alerts.append({
                "type": "schtask_persistence_detected",
                "subject": user,
                "severity": severity,
                "score": float(score),
                "text": f"[{severity}] Scheduled task persistence detected: User '{user}' created {count} suspicious scheduled task(s) with malicious patterns",
                "evidence": {
                    "username": user,
                    "task_count": count,
                    "task_names": task_names,
                    "has_encoded_powershell": has_encoded_ps,
                    "has_temp_executable": has_temp_exe,
                    "has_hidden_window": has_hidden_window,
                    "affected_hosts": hosts,
                    "sample_actions": [t["action"][:100] for t in tasks[:3]]
                },
                "prompt_ctx": {
                    "user": user,
                    "behavior": {"type": "schtask_persistence"}
                }
            })
        
        print(f"[DEBUG SCHTASK] Generated {len(alerts)} alerts", file=sys.stderr)
    
    except Exception as e:
        import sys
        print(f"[DEBUG] Scheduled task persistence detection error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    
    return alerts


def _detect_windows_service_persistence(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detects Windows service persistence attacks.
    
    Pattern:
    - EventID=7045 (A service was installed in the system) in System channel
    - Suspicious ImagePaths: executables in Temp folders, ProgramData, 
      or masquerading as Windows binaries
    - Fake service names mimicking Windows updates
    
    MITRE ATT&CK: T1543.003 (Create or Modify System Process: Windows Service)
    """
    import sys
    alerts = []
    
    if df.empty:
        return alerts
    
    # Handle column name variations
    event_id_col = None
    for col in ["EventID", "event_id"]:
        if col in df.columns:
            event_id_col = col
            break
    
    if event_id_col is None:
        return alerts
    
    try:
        # Filter for EventID 7045 (Service installed)
        svc_events = df[df[event_id_col].astype(str) == "7045"].copy()
        
        if svc_events.empty:
            return alerts
        
        print(f"[DEBUG SVCPERSIST] Found {len(svc_events)} service installation events", file=sys.stderr)
        
        # Find user column
        user_col = None
        for col in ["User", "username", "user.name"]:
            if col in svc_events.columns:
                user_col = col
                break
        
        # Find ServiceName and ImagePath columns
        svc_name_col = None
        for col in ["ServiceName", "service_name"]:
            if col in svc_events.columns:
                svc_name_col = col
                break
        
        image_path_col = None
        for col in ["ImagePath", "image_path", "ServiceImagePath"]:
            if col in svc_events.columns:
                image_path_col = col
                break
        
        # Extract from raw_line or message if columns not available
        def extract_from_message(row):
            msg = ""
            if "raw_line" in row and pd.notna(row.get("raw_line")):
                msg = str(row["raw_line"])
            elif "message" in row and pd.notna(row.get("message")):
                msg = str(row["message"])
            
            service_name = None
            image_path = None
            
            # Extract ServiceName
            sn_match = re.search(r'ServiceName="([^"]+)"', msg)
            if sn_match:
                service_name = sn_match.group(1)
            
            # Extract ImagePath
            ip_match = re.search(r'ImagePath="([^"]+)"', msg)
            if ip_match:
                image_path = ip_match.group(1)
            
            return pd.Series([service_name, image_path])
        
        if svc_name_col is None or image_path_col is None:
            extracted = svc_events.apply(extract_from_message, axis=1)
            extracted.columns = ["_service_name", "_image_path"]
            svc_events = pd.concat([svc_events, extracted], axis=1)
            svc_name_col = "_service_name" if svc_name_col is None else svc_name_col
            image_path_col = "_image_path" if image_path_col is None else image_path_col
        
        # Define suspicious patterns
        SUSPICIOUS_PATH_PATTERNS = [
            r"C:\\Windows\\Temp\\.*\.exe",           # Exe in Windows Temp
            r"C:\\Users\\.*\\AppData\\.*\.exe",      # Exe in user AppData
            r"C:\\ProgramData\\(?!Microsoft).*\.exe", # Exe in ProgramData (non-Microsoft)
            r"C:\\Temp\\.*\.exe",                    # Exe in C:\Temp
            r"updsvc\.exe",                          # Known malware name
            r"winupd\.exe",                          # Known malware name
            r"svc\.exe",                             # Common malware name
            r"-enc\s+[A-Za-z0-9+/=]+",               # Encoded PowerShell in path
            r"powershell.*-enc",                     # PowerShell with encoding
        ]
        
        # Suspicious service name patterns (fake Windows services)
        SUSPICIOUS_NAME_PATTERNS = [
            r"Update_\d+",                            # Fake update service
            r"WindowsUpdate\d+",                      # Fake Windows update
            r"WinUpdate\d*",                          # Fake Windows update
            r"SvcHost\d+",                            # Fake svchost
            r"System\d+",                             # Fake system service
        ]
        
        # Legitimate-looking but suspicious when coming from non-standard paths
        MASQUERADE_BINARIES = [
            "svchost.exe",
            "services.exe",
            "lsass.exe",
        ]
        
        suspicious_services = []
        
        for idx, row in svc_events.iterrows():
            svc_name = str(row.get(svc_name_col, "")) if pd.notna(row.get(svc_name_col)) else ""
            image_path = str(row.get(image_path_col, "")) if pd.notna(row.get(image_path_col)) else ""
            user = str(row.get(user_col, "unknown")) if user_col and pd.notna(row.get(user_col)) else "unknown"
            host = str(row.get("Host", row.get("host", "unknown")))
            timestamp = row.get("timestamp")
            
            is_suspicious = False
            suspicious_indicators = []
            
            # Check if image path is suspicious
            for pattern in SUSPICIOUS_PATH_PATTERNS:
                if re.search(pattern, image_path, re.IGNORECASE):
                    is_suspicious = True
                    suspicious_indicators.append(f"suspicious_path:{pattern[:20]}")
                    break
            
            # Check if service name is suspicious
            for pattern in SUSPICIOUS_NAME_PATTERNS:
                if re.search(pattern, svc_name, re.IGNORECASE):
                    is_suspicious = True
                    suspicious_indicators.append(f"fake_service_name:{svc_name}")
                    break
                    
            # Check for masquerading (legitimate exe from non-standard path)
            for masq in MASQUERADE_BINARIES:
                if masq.lower() in image_path.lower():
                    # Legitimate paths for these binaries
                    legitimate_paths = [
                        r"C:\\Windows\\system32\\",
                        r"C:\\Windows\\SysWOW64\\"
                    ]
                    is_legit = any(re.search(lp, image_path, re.IGNORECASE) for lp in legitimate_paths)
                    if not is_legit:
                        is_suspicious = True
                        suspicious_indicators.append(f"masquerading:{masq}")
            
            if is_suspicious:
                suspicious_services.append({
                    "user": user,
                    "host": host,
                    "service_name": svc_name,
                    "image_path": image_path[:200] if len(image_path) > 200 else image_path,
                    "timestamp": timestamp,
                    "indicators": suspicious_indicators
                })
        
        print(f"[DEBUG SVCPERSIST] Found {len(suspicious_services)} suspicious services", file=sys.stderr)
        
        if not suspicious_services:
            return alerts
        
        # Group by user
        from collections import defaultdict
        user_services = defaultdict(list)
        for svc in suspicious_services:
            user_services[svc["user"]].append(svc)
        
        for user, services in user_services.items():
            count = len(services)
            hosts = list(set(s["host"] for s in services))
            service_names = list(set(s["service_name"][:30] for s in services))[:5]
            
            # Check for high-risk patterns
            has_temp_exe = any(re.search(r"Temp\\.*\.exe", s["image_path"], re.IGNORECASE) for s in services)
            has_fake_update = any("Update_" in s["service_name"] for s in services)
            has_programdata = any("ProgramData" in s["image_path"] for s in services)
            
            # Scoring
            base_score = min(7.0 + (count / 3.0), 10.0)
            
            if has_temp_exe:
                base_score = min(base_score + 1.5, 10.0)
            if has_fake_update:
                base_score = min(base_score + 1.0, 10.0)
            if has_programdata:
                base_score = min(base_score + 0.5, 10.0)
            
            score = round(base_score, 2)
            severity = "CRITICAL" if score >= 8.0 else "WARNING"
            
            alerts.append({
                "type": "service_persistence_detected",
                "subject": user,
                "severity": severity,
                "score": float(score),
                "text": f"[{severity}] Service persistence detected: User '{user}' installed {count} suspicious service(s) with malicious patterns",
                "evidence": {
                    "username": user,
                    "service_count": count,
                    "service_names": service_names,
                    "has_temp_executable": has_temp_exe,
                    "has_fake_update_name": has_fake_update,
                    "has_programdata_exe": has_programdata,
                    "affected_hosts": hosts,
                    "sample_paths": [s["image_path"][:80] for s in services[:3]]
                },
                "prompt_ctx": {
                    "user": user,
                    "behavior": {"type": "service_persistence"}
                }
            })
        
        print(f"[DEBUG SVCPERSIST] Generated {len(alerts)} alerts", file=sys.stderr)
    
    except Exception as e:
        import sys
        print(f"[DEBUG] Service persistence detection error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    
    return alerts


def _detect_ssh_login_burst(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect SSH lateral movement - USER-CENTRIC detection.
    
    Creates per-user alerts for SSH logins from multiple IPs, indicating potential
    lateral movement or account compromise.
    """
    alerts = []
    if "message" not in df.columns:
        return alerts
    try:
        import sys
        
        # Find SSH daemon logs - check both program column AND message content
        ssh_logs = pd.DataFrame()
        
        if "program" in df.columns:
            program_ssh = df[df["program"].astype(str).str.contains(r"sshd", case=False, na=False)].copy()
            ssh_logs = pd.concat([ssh_logs, program_ssh], ignore_index=True)
        
        # Fallback: Check message directly for SSH patterns
        message_ssh = df[df["message"].astype(str).str.contains(r"(sshd|Accepted\s+(publickey|password)\s+for)", case=False, regex=True, na=False)].copy()
        ssh_logs = pd.concat([ssh_logs, message_ssh], ignore_index=True)
        
        # Remove duplicates
        if not ssh_logs.empty:
            ssh_logs = ssh_logs.drop_duplicates()
        
        if len(ssh_logs) == 0:
            print(f"[DEBUG] SSH detection: No SSH logs found in {len(df)} rows", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Found {len(ssh_logs)} SSH log entries", file=sys.stderr)
        
        # Filter for successful logins (lateral movement indicator)
        successful_logins = ssh_logs[ssh_logs["message"].astype(str).str.contains(r"Accepted\s+(publickey|password)", case=False, regex=True, na=False)].copy()
        if len(successful_logins) == 0:
            print(f"[DEBUG] SSH detection: No 'Accepted publickey/password' found", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Found {len(successful_logins)} successful SSH logins", file=sys.stderr)
        
        # Extract username and source IP from message
        # Pattern: "Accepted publickey for huydev from 10.141.10.67 port 12345"
        successful_logins["ssh_user"] = successful_logins["message"].str.extract(r"Accepted\s+\S+\s+for\s+(\S+)\s+from", flags=re.IGNORECASE)[0]
        successful_logins["ssh_source_ip"] = successful_logins["message"].str.extract(r"from\s+([0-9\.]+)\s+port", flags=re.IGNORECASE)[0]
        
        # Drop rows without extracted data
        successful_logins = successful_logins[successful_logins["ssh_user"].notna() & successful_logins["ssh_source_ip"].notna()]
        
        if len(successful_logins) == 0:
            print(f"[DEBUG] SSH detection: Failed to extract user/IP from messages", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Extracted {len(successful_logins)} logins with user+IP, users: {successful_logins['ssh_user'].unique().tolist()}", file=sys.stderr)
        
        # GROUP BY USER - Create per-user alerts (USER-CENTRIC approach)
        for username, user_group in successful_logins.groupby("ssh_user"):
            username = str(username).strip()
            if not username or username in ["(unknown)", "nan", ""]:
                continue
            
            login_count = len(user_group)
            unique_source_ips = user_group["ssh_source_ip"].nunique()
            source_ips_list = user_group["ssh_source_ip"].unique().tolist()[:10]
            unique_hosts = user_group["host"].nunique() if "host" in user_group.columns else 0
            target_hosts = user_group["host"].unique().tolist()[:5] if "host" in user_group.columns else []
            
            # ALERT ON ANY SSH LOGIN: Even 1 login can indicate lateral movement in attack scenarios
            # Score increases with more logins/IPs
            if login_count >= 1:
                # Calculate score based on login patterns
                # High score for many source IPs (potential botnet/compromised machines)
                # Medium score for high login count from few IPs
                lateral_score = 5.0
                if unique_source_ips >= 5:
                    lateral_score = 8.5  # Definitely suspicious - many source IPs
                elif unique_source_ips >= 3:
                    lateral_score = 7.0  # Suspicious
                if login_count >= 10:
                    lateral_score = min(lateral_score + 1.0, 10.0)
                if unique_hosts >= 5:
                    lateral_score = min(lateral_score + 1.0, 10.0)  # Targeting many hosts
                
                alerts.append({
                    "type": "ssh_lateral_movement",
                    "subject": username,  # USER-CENTRIC: subject is the USER
                    "severity": scoring.get_severity(lateral_score),
                    "score": lateral_score,
                    "text": f"SSH lateral movement detected: User '{username}' logged in {login_count} times from {unique_source_ips} different source IPs to {unique_hosts} servers.",
                    "evidence": {
                        "username": username,
                        "login_count": int(login_count),
                        "unique_source_ips": int(unique_source_ips),
                        "source_ips": source_ips_list,
                        "target_hosts": target_hosts,
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {"type": "ssh_lateral_movement", "logins": login_count, "source_ips": unique_source_ips},
                        "time": None,
                        "baseline": {"expected_source_ips": 1},
                        "extras": {"reason": "Multiple source IPs indicate lateral movement or compromised credentials"},
                    },
                })
    except Exception as e:
        import sys
        print(f"[DEBUG] SSH lateral movement error: {e}", file=sys.stderr)
    return alerts

# ==============================================================================
# Context-Aware EDR Anomaly Detection (V2 - With Beaconing & Process Analysis)
# ==============================================================================

def _detect_edr_anomalies(df: pd.DataFrame, baselines_dir: str) -> List[Dict[str, Any]]:
    """
    Context-Aware Risk Scoring for EDR/Sysmon Network Connection Logs (EventID=3).
    
    V2 Improvements:
    - Module A: C2 Beaconing detection (periodic connections)
    - Module B: Suspicious process execution (non-tech users + risky tools)
    - Module C: Refined volume spike (absolute count based)
    - Module D: Relaxed unauthorized access (only external admin ports)
    
    Args:
        df: DataFrame with EDR logs containing User, SrcIp, DestinationIp, DestinationPort
        baselines_dir: Path to baseline statistics
    
    Returns:
        List of alert dictionaries with type, subject, severity, score, text, evidence
    """
    alerts = []
    
    # ===== STEP 1: VALIDATE & PARSE EDR LOGS =====
    required_cols = {"username", "message"}
    if not required_cols.issubset(df.columns):
        return alerts  # Not EDR logs
    
    # Check if this is EDR/Sysmon log
    is_edr = False
    if "message" in df.columns:
        sample_msgs = df["message"].head(10).astype(str)
        is_edr = sample_msgs.str.contains("Sysmon.*EventID=3|DestinationIp=|DestinationPort=", 
                                          case=False, regex=True, na=False).any()
    
    if not is_edr:
        return alerts  # Not EDR logs, skip
    
    # ===== STEP 2: EXTRACT NETWORK FEATURES FROM EDR LOGS =====
    
    def extract_edr_features(row):
        """Extract network features including Image (process name)."""
        msg = str(row.get("message", ""))
        
        # Extract DestinationIp
        dest_ip_match = re.search(r"DestinationIp=([0-9\.]+)", msg)
        dest_ip = dest_ip_match.group(1) if dest_ip_match else None
        
        # Extract DestinationPort
        dest_port_match = re.search(r"DestinationPort=(\d+)", msg)
        dest_port = int(dest_port_match.group(1)) if dest_port_match else None
        
        # Extract SrcIp
        src_ip = row.get("source_ip")
        if pd.isna(src_ip) or not src_ip:
            src_ip_match = re.search(r"SrcIp=([0-9\.]+)", msg)
            src_ip = src_ip_match.group(1) if src_ip_match else None
        
        # Extract Image (process path)
        image_match = re.search(r"Image=([^\s]+)", msg)
        image = image_match.group(1) if image_match else None
        
        return pd.Series({
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "src_ip": src_ip,
            "image": image
        })
    
    # Apply extraction
    edr_features = df.apply(extract_edr_features, axis=1)
    df_edr = pd.concat([df, edr_features], axis=1)
    
    # Ensure timestamp is datetime
    if "timestamp" in df_edr.columns:
        df_edr["timestamp"] = pd.to_datetime(df_edr["timestamp"], errors="coerce")
    
    # ===== STEP 3: CONFIG - LOAD USER BASELINE & DEFINE POLICIES =====
    
    # Load user-to-group mapping from baseline
    user_baseline = {}
    try:
        user_to_group_path = os.path.join(baselines_dir, "members", "user_to_group.json")
        if os.path.exists(user_to_group_path):
            with open(user_to_group_path, "r", encoding="utf-8") as f:
                user_baseline = json.load(f)
    except Exception:
        pass  # If baseline not available, user_baseline will be empty
    
    # Map Baseline Group → Security Policy Role
    GROUP_TO_ROLE_POLICY = {
        "itadmin": "admin",
        "engineering": "engineer",
        "sales": "sales",
        "finance": "finance"
    }
    
    # Role characteristics (Security Policies)
    ROLE_CONFIG = {
        "engineer": {
            "risk_multiplier": 0.8,
            "allowed_processes": ["powershell.exe", "cmd.exe", "ssh.exe", "python.exe"],
            "is_technical": True,
            "allow_ssh": True,
            "allow_internal_infrastructure": True
        },
        "sales": {
            "risk_multiplier": 1.2,
            "allowed_processes": ["chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe"],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK SSH/RDP
            "allow_internal_infrastructure": False  # BLOCK 10.10.10.x
        },
        "finance": {
            "risk_multiplier": 1.3,
            "allowed_processes": ["chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe", "excel.exe"],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK SSH/RDP
            "allow_internal_infrastructure": False  # BLOCK 10.10.10.x
        },
        "admin": {
            "risk_multiplier": 1.0,
            "allowed_processes": [],  # Admins can run anything
            "is_technical": True,
            "allow_ssh": True,
            "allow_internal_infrastructure": True
        },
        "unknown": {  # Default for unknown users
            "risk_multiplier": 1.5,  # Higher risk for unknown users
            "allowed_processes": [],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK all sensitive access
            "allow_internal_infrastructure": False
        }
    }
    
    # Risky processes for non-technical users
    RISKY_PROCESSES = ["powershell.exe", "cmd.exe", "ssh.exe", "psexec.exe", "wmic.exe"]
    
    # Admin ports (SSH, RDP, etc.)
    ADMIN_PORTS = {22, 23, 3389, 445, 1433, 3306, 5432}
    
    # Internal infrastructure servers
    INTERNAL_INFRASTRUCTURE = ["10.10.10.20", "10.10.10.30", "10.10.10.40"]
    
    # ===== STEP 4: HELPER - GET USER ROLE FROM BASELINE =====
    
    def get_user_role(username: str) -> tuple:
        """
        Get user role from baseline data dynamically.
        Returns: (role_name, role_config)
        """
        username_lower = str(username).lower().strip()
        
        # Lookup user in baseline
        if username_lower in user_baseline:
            group = user_baseline[username_lower]
            # Map group to role policy
            role_name = GROUP_TO_ROLE_POLICY.get(group, "unknown")
        else:
            # User not in baseline - treat as unknown
            role_name = "unknown"
        
        role_config = ROLE_CONFIG.get(role_name, ROLE_CONFIG["unknown"])
        
        return role_name, role_config
    
    def is_external_ip(ip: str) -> bool:
        """Check if IP is external (not RFC1918 private)."""
        if not ip:
            return False
        ip_str = str(ip)
        return not (ip_str.startswith("10.") or 
                    ip_str.startswith("192.168.") or 
                    ip_str.startswith("172.16.") or
                    ip_str.startswith("172.17.") or
                    ip_str.startswith("172.18.") or
                    ip_str.startswith("172.19.") or
                    ip_str.startswith("172.20.") or
                    ip_str.startswith("172.21.") or
                    ip_str.startswith("172.22.") or
                    ip_str.startswith("172.23.") or
                    ip_str.startswith("172.24.") or
                    ip_str.startswith("172.25.") or
                    ip_str.startswith("172.26.") or
                    ip_str.startswith("172.27.") or
                    ip_str.startswith("172.28.") or
                    ip_str.startswith("172.29.") or
                    ip_str.startswith("172.30.") or
                    ip_str.startswith("172.31."))
    
    # ==============================================================================
    # MODULE A: C2 BEACONING DETECTION (CRITICAL - New!)
    # ==============================================================================
    # Detect periodic connections to external IPs (malware calling home)
    
    try:
        # Filter connections to external IPs
        external_conns = df_edr[df_edr["dest_ip"].apply(is_external_ip)].copy()
        
        if not external_conns.empty and "timestamp" in external_conns.columns:
            # Group by (user, dest_ip)
            for (username, dest_ip), group in external_conns.groupby(["username", "dest_ip"]):
                username = str(username).strip()
                dest_ip = str(dest_ip)
                
                if len(group) < 10:  # Need at least 10 connections to detect pattern
                    continue
                
                # Sort by timestamp
                sorted_group = group.sort_values("timestamp")
                timestamps = sorted_group["timestamp"].dropna()
                
                if len(timestamps) < 10:
                    continue
                
                # Calculate time deltas between consecutive connections
                time_deltas = timestamps.diff().dropna()
                delta_seconds = time_deltas.dt.total_seconds()
                
                if len(delta_seconds) < 5:
                    continue
                
                # Calculate variance of time deltas
                mean_interval = delta_seconds.mean()
                variance = delta_seconds.var()
                std_dev = delta_seconds.std()
                
                # Beaconing signature: Low variance + regular interval
                # Typical C2: every 5s, 10s, 30s, 60s with very low deviation
                is_beaconing = False
                
                if variance < 5.0 and mean_interval < 300:  # < 5min interval, very regular
                    is_beaconing = True
                elif std_dev < 2.0 and mean_interval < 60:  # < 1min interval, tight timing
                    is_beaconing = True
                
                if is_beaconing:
                    # Extract process name
                    process_name = "unknown"
                    if "image" in sorted_group.columns:
                        images = sorted_group["image"].dropna()
                        if len(images) > 0:
                            # Get most common process
                            process_name = images.mode()[0] if not images.mode().empty else str(images.iloc[0])
                            # Extract basename
                            if "\\" in process_name or "/" in process_name:
                                process_name = process_name.split("\\")[-1].split("/")[-1]
                    
                    alerts.append({
                        "type": "c2_beaconing_detected",
                        "subject": username,
                        "severity": "CRITICAL",
                        "score": 10.0,
                        "text": f"🚨 C2 BEACONING: User {username} machine infected! Process '{process_name}' connecting to {dest_ip} every {mean_interval:.1f}s (variance: {variance:.2f})",
                        "evidence": {
                            "username": username,
                            "dest_ip": dest_ip,
                            "process": process_name,
                            "connection_count": len(group),
                            "mean_interval_seconds": float(mean_interval),
                            "variance": float(variance),
                            "std_dev": float(std_dev),
                            "beaconing_pattern": f"Every {mean_interval:.1f}±{std_dev:.1f}s"
                        },
                        "prompt_ctx": {
                            "user": username,
                            "group": None,
                            "behavior": {
                                "type": "c2_beaconing",
                                "process": process_name,
                                "dest_ip": dest_ip,
                                "interval": mean_interval
                            },
                            "time": None,
                            "baseline": {},
                            "extras": {
                                "reason": "Periodic connection pattern detected - strong indicator of malware C2 communication"
                            }
                        }
                    })
    except Exception as e:
        pass  # Beaconing detection failed, continue
    
    # ==============================================================================
    # MODULE B: SUSPICIOUS PROCESS EXECUTION (CRITICAL - New!)
    # ==============================================================================
    # Detect non-technical users running technical tools to external IPs
    
    try:
        for idx, row in df_edr.iterrows():
            username = str(row.get("username", "")).strip()
            if not username or username in ["(unknown)", "nan", ""]:
                continue
            
            image = str(row.get("image", ""))
            dest_ip = str(row.get("dest_ip", ""))
            
            if not image or not dest_ip:
                continue
            
            # Extract process basename
            process_name = image.split("\\")[-1].split("/")[-1].lower()
            
            # Check if external IP
            if not is_external_ip(dest_ip):
                continue
            
            # Infer user role
            user_role, role_config = get_user_role(username)
            
            # Check if non-technical user
            if role_config.get("is_technical", False):
                continue  # Technical users can run these tools
            
            # Check if risky process
            if any(risky in process_name for risky in RISKY_PROCESSES):
                # Create alert key to avoid duplicates
                alert_key = f"{username}_{process_name}_{dest_ip}"
                
                # Check if already alerted (use a set to track)
                if not hasattr(_detect_edr_anomalies, '_process_alerts'):
                    _detect_edr_anomalies._process_alerts = set()
                
                if alert_key in _detect_edr_anomalies._process_alerts:
                    continue
                
                _detect_edr_anomalies._process_alerts.add(alert_key)
                
                alerts.append({
                    "type": "suspicious_process_external_connection",
                    "subject": username,
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "text": f"🚨 SUSPICIOUS PROCESS: {user_role} user '{username}' running {process_name} connecting to external IP {dest_ip}",
                    "evidence": {
                        "username": username,
                        "user_role": user_role,
                        "process": process_name,
                        "dest_ip": dest_ip,
                        "reason": f"{user_role} users should not run {process_name}"
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {
                            "type": "suspicious_process",
                            "process": process_name,
                            "dest_ip": dest_ip
                        },
                        "time": None,
                        "baseline": {},
                        "extras": {
                            "reason": f"Non-technical user ({user_role}) executing technical tool ({process_name}) to external network"
                        }
                    }
                })
    except Exception as e:
        pass  # Process detection failed, continue
    
    # Clear process alerts tracking for next call
    if hasattr(_detect_edr_anomalies, '_process_alerts'):
        _detect_edr_anomalies._process_alerts = set()
    
    # ==============================================================================
    # MODULE C: VOLUME SPIKE (Refined - Absolute Count Based)
    # ==============================================================================
    
    # Load baseline
    base = _load_baseline_tables(baselines_dir)
    user_stats = base.get("user_stats")
    if not isinstance(user_stats, pd.DataFrame) or user_stats.empty:
        user_stats = pd.DataFrame()
    else:
        if "username" in user_stats.columns:
            user_stats = user_stats.copy()
            user_stats["username"] = user_stats["username"].astype(str)
    
    # Aggregate per-user activity
    user_network_activity = df_edr.groupby("username").agg({
        "src_ip": lambda x: x.dropna().nunique(),
        "dest_ip": lambda x: x.dropna().unique().tolist(),
        "dest_port": lambda x: x.dropna().unique().tolist()
    }).reset_index()
    
    user_network_activity.columns = ["username", "unique_src_ips", "destinations", "dest_ports"]
    
    for _, row in user_network_activity.iterrows():
        username = str(row["username"]).strip()
        if not username or username in ["(unknown)", "nan", ""]:
            continue
        
        unique_src_ips = int(row["unique_src_ips"])
        destinations = row["destinations"]
        dest_ports = [int(p) for p in row["dest_ports"] if pd.notna(p)]
        
        # Skip if too few connections
        if unique_src_ips < 3:
            continue
        
        # Get baseline
        baseline_ips = 0.0
        if not user_stats.empty and "unique_src_ips_mean" in user_stats.columns:
            user_baseline = user_stats[user_stats["username"] == username]
            if not user_baseline.empty:
                baseline_ips = float(user_baseline["unique_src_ips_mean"].iloc[0] or 0.0)
        
        if baseline_ips == 0.0:
            baseline_ips = 10.0  # Default baseline
        
        # Infer role
        user_role, role_config = get_user_role(username)
        
        # ===== MODULE C: SCORING (Absolute + Percentage) =====
        
        # Base score (absolute count)
        if unique_src_ips >= 30:
            base_score = 9.0
        elif unique_src_ips >= 20:
            base_score = 7.0
        elif unique_src_ips >= 10:
            base_score = 5.0
        else:
            base_score = 3.0
        
        # Percentage increase bonus (capped)
        if baseline_ips > 0:
            pct_increase = (unique_src_ips - baseline_ips) / baseline_ips
            if pct_increase > 3.0:
                base_score += 1.0
            elif pct_increase > 2.0:
                base_score += 0.5
        
        
        # ===== MODULE D: UPDATED PENALTY LOGIC (Sales/Finance Enforcement) =====
        
        penalty = 0.0
        penalty_reasons = []
        
        # Rule 1: Sales/Finance BLOCKED from SSH/RDP (Port 22, 3389)
        if not role_config.get("allow_ssh", True):  # If user NOT allowed SSH
            ssh_rdp_ports = {22, 3389}
            accessed_ssh_rdp = set(dest_ports) & ssh_rdp_ports
            if accessed_ssh_rdp:
                penalty += 3.0
                port_names = [f"Port {p} ({'SSH' if p == 22 else 'RDP'})" for p in accessed_ssh_rdp]
                penalty_reasons.append(f"{user_role.upper()} users BLOCKED from {', '.join(port_names)}")
        
        # Rule 2: Sales/Finance BLOCKED from Internal Infrastructure (10.10.10.x)
        if not role_config.get("allow_internal_infrastructure", True):
            accessed_internal = [ip for ip in destinations if ip in INTERNAL_INFRASTRUCTURE]
            if accessed_internal:
                penalty += 2.5
                penalty_reasons.append(f"{user_role.upper()} users BLOCKED from internal infrastructure: {', '.join(accessed_internal)}")
        
        # Rule 3: Check for external connections to admin ports (all users)
        external_admin_access = False
        for dest_ip, dest_port in zip(destinations, dest_ports):
            if is_external_ip(dest_ip) and dest_port in ADMIN_PORTS:
                external_admin_access = True
                penalty += 2.0
                penalty_reasons.append(f"External admin access: {dest_ip}:{dest_port}")
                break
        
        # Rule 4: Check for excessive external connections
        external_ips = [ip for ip in destinations if is_external_ip(ip)]
        if len(external_ips) > 10:
            penalty += 1.0
            penalty_reasons.append(f"High external IP count: {len(external_ips)} connections")
        
        # Apply role multiplier
        risk_multiplier = role_config.get("risk_multiplier", 1.0)
        final_score = (base_score + penalty) * risk_multiplier
        final_score = min(final_score, 10.0)
        
        # Determine severity
        if final_score >= 8.0:
            severity = "CRITICAL"
        elif final_score >= 5.0:
            severity = "WARNING"
        else:
            severity = "INFO"
        
        # Skip low-risk alerts
        if final_score < 4.0:
            continue
        
        # Build alert text
        alert_text = f"User {username} ({user_role}): {unique_src_ips} unique source IPs (baseline: {baseline_ips:.0f})"
        
        if penalty_reasons:
            alert_text += " - " + "; ".join(penalty_reasons)
        
        # Build evidence
        evidence = {
            "username": username,
            "user_role": user_role,
            "unique_src_ips": unique_src_ips,
            "baseline_ips": baseline_ips,
            "destinations_count": len(destinations),
            "unique_ports": len(dest_ports),
            "external_ips_count": len(external_ips),
            "penalty_reasons": penalty_reasons,
            "risk_multiplier": risk_multiplier
        }
        
        # Create alert
        alerts.append({
            "type": "edr_suspicious_network_activity",
            "subject": username,
            "severity": severity,
            "score": final_score,
            "text": alert_text,
            "evidence": evidence,
            "prompt_ctx": {
                "user": username,
                "group": None,
                "behavior": {
                    "type": "network_anomaly",
                    "role": user_role,
                    "unique_src_ips": unique_src_ips,
                    "baseline_ips": baseline_ips
                },
                "time": None,
                "baseline": {
                    "expected_ips": baseline_ips,
                    "user_role": user_role
                },
                "extras": {
                    "penalty_reasons": penalty_reasons,
                    "risk_calculation": "context-aware v2 (absolute + % + role + external admin only)"
                }
            }
        })
    
    return alerts

def _detect_ssh_login_burst(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect SSH lateral movement - USER-CENTRIC detection.
    
    Creates per-user alerts for SSH logins from multiple IPs, indicating potential
    lateral movement or account compromise.
    """
    alerts = []
    if "message" not in df.columns:
        return alerts
    try:
        import sys
        
        # Find SSH daemon logs - check both program column AND message content
        ssh_logs = pd.DataFrame()
        
        if "program" in df.columns:
            program_ssh = df[df["program"].astype(str).str.contains(r"sshd", case=False, na=False)].copy()
            ssh_logs = pd.concat([ssh_logs, program_ssh], ignore_index=True)
        
        # Fallback: Check message directly for SSH patterns
        message_ssh = df[df["message"].astype(str).str.contains(r"(sshd|Accepted\s+(publickey|password)\s+for)", case=False, regex=True, na=False)].copy()
        ssh_logs = pd.concat([ssh_logs, message_ssh], ignore_index=True)
        
        # Remove duplicates
        if not ssh_logs.empty:
            ssh_logs = ssh_logs.drop_duplicates()
        
        if len(ssh_logs) == 0:
            print(f"[DEBUG] SSH detection: No SSH logs found in {len(df)} rows", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Found {len(ssh_logs)} SSH log entries", file=sys.stderr)
        
        # Filter for successful logins (lateral movement indicator)
        successful_logins = ssh_logs[ssh_logs["message"].astype(str).str.contains(r"Accepted\s+(publickey|password)", case=False, regex=True, na=False)].copy()
        if len(successful_logins) == 0:
            print(f"[DEBUG] SSH detection: No 'Accepted publickey/password' found", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Found {len(successful_logins)} successful SSH logins", file=sys.stderr)
        
        # Extract username and source IP from message
        # Pattern: "Accepted publickey for huydev from 10.141.10.67 port 12345"
        successful_logins["ssh_user"] = successful_logins["message"].str.extract(r"Accepted\s+\S+\s+for\s+(\S+)\s+from", flags=re.IGNORECASE)[0]
        successful_logins["ssh_source_ip"] = successful_logins["message"].str.extract(r"from\s+([0-9\.]+)\s+port", flags=re.IGNORECASE)[0]
        
        # Drop rows without extracted data
        successful_logins = successful_logins[successful_logins["ssh_user"].notna() & successful_logins["ssh_source_ip"].notna()]
        
        if len(successful_logins) == 0:
            print(f"[DEBUG] SSH detection: Failed to extract user/IP from messages", file=sys.stderr)
            return alerts
        
        print(f"[DEBUG] SSH detection: Extracted {len(successful_logins)} logins with user+IP, users: {successful_logins['ssh_user'].unique().tolist()}", file=sys.stderr)
        
        # GROUP BY USER - Create per-user alerts (USER-CENTRIC approach)
        for username, user_group in successful_logins.groupby("ssh_user"):
            username = str(username).strip()
            if not username or username in ["(unknown)", "nan", ""]:
                continue
            
            login_count = len(user_group)
            unique_source_ips = user_group["ssh_source_ip"].nunique()
            source_ips_list = user_group["ssh_source_ip"].unique().tolist()[:10]
            unique_hosts = user_group["host"].nunique() if "host" in user_group.columns else 0
            target_hosts = user_group["host"].unique().tolist()[:5] if "host" in user_group.columns else []
            
            # ALERT ON ANY SSH LOGIN: Even 1 login can indicate lateral movement in attack scenarios
            # Score increases with more logins/IPs
            if login_count >= 1:
                # Calculate score based on login patterns
                # High score for many source IPs (potential botnet/compromised machines)
                # Medium score for high login count from few IPs
                lateral_score = 5.0
                if unique_source_ips >= 5:
                    lateral_score = 8.5  # Definitely suspicious - many source IPs
                elif unique_source_ips >= 3:
                    lateral_score = 7.0  # Suspicious
                if login_count >= 10:
                    lateral_score = min(lateral_score + 1.0, 10.0)
                if unique_hosts >= 5:
                    lateral_score = min(lateral_score + 1.0, 10.0)  # Targeting many hosts
                
                alerts.append({
                    "type": "ssh_lateral_movement",
                    "subject": username,  # USER-CENTRIC: subject is the USER
                    "severity": scoring.get_severity(lateral_score),
                    "score": lateral_score,
                    "text": f"SSH lateral movement detected: User '{username}' logged in {login_count} times from {unique_source_ips} different source IPs to {unique_hosts} servers.",
                    "evidence": {
                        "username": username,
                        "login_count": int(login_count),
                        "unique_source_ips": int(unique_source_ips),
                        "source_ips": source_ips_list,
                        "target_hosts": target_hosts,
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {"type": "ssh_lateral_movement", "logins": login_count, "source_ips": unique_source_ips},
                        "time": None,
                        "baseline": {"expected_source_ips": 1},
                        "extras": {"reason": "Multiple source IPs indicate lateral movement or compromised credentials"},
                    },
                })
    except Exception as e:
        import sys
        print(f"[DEBUG] SSH lateral movement error: {e}", file=sys.stderr)
    return alerts

# ==============================================================================
# Context-Aware EDR Anomaly Detection (V2 - With Beaconing & Process Analysis)
# ==============================================================================

def _detect_edr_anomalies(df: pd.DataFrame, baselines_dir: str, log_type: str = "generic") -> List[Dict[str, Any]]:
    """
    Context-Aware Risk Scoring for EDR/Sysmon Network Connection Logs (EventID=3).
    
    V2 Improvements:
    - Module A: C2 Beaconing detection (periodic connections)
    - Module B: Suspicious process execution (non-tech users + risky tools)
    - Module C: Refined volume spike (absolute count based)
    - Module D: Relaxed unauthorized access (only external admin ports)
    
    Args:
        df: DataFrame with EDR logs containing User, SrcIp, DestinationIp, DestinationPort
        baselines_dir: Path to baseline statistics
        log_type: Log type for MongoDB query
    
    Returns:
        List of alert dictionaries with type, subject, severity, score, text, evidence
    """
    alerts = []
    
    # ===== STEP 1: VALIDATE & PARSE EDR LOGS =====
    required_cols = {"username", "message"}
    if not required_cols.issubset(df.columns):
        return alerts  # Not EDR logs
    
    # Check if this is EDR/Sysmon log
    is_edr = False
    if "message" in df.columns:
        sample_msgs = df["message"].head(10).astype(str)
        is_edr = sample_msgs.str.contains("Sysmon.*EventID=3|DestinationIp=|DestinationPort=", 
                                          case=False, regex=True, na=False).any()
    
    if not is_edr:
        return alerts  # Not EDR logs, skip
    
    # ===== STEP 2: EXTRACT NETWORK FEATURES FROM EDR LOGS =====
    
    def extract_edr_features(row):
        """Extract network features including Image (process name)."""
        msg = str(row.get("message", ""))
        
        # Extract DestinationIp
        dest_ip_match = re.search(r"DestinationIp=([0-9\.]+)", msg)
        dest_ip = dest_ip_match.group(1) if dest_ip_match else None
        
        # Extract DestinationPort
        dest_port_match = re.search(r"DestinationPort=(\d+)", msg)
        dest_port = int(dest_port_match.group(1)) if dest_port_match else None
        
        # Extract SrcIp
        src_ip = row.get("source_ip")
        if pd.isna(src_ip) or not src_ip:
            src_ip_match = re.search(r"SrcIp=([0-9\.]+)", msg)
            src_ip = src_ip_match.group(1) if src_ip_match else None
        
        # Extract Image (process path)
        image_match = re.search(r"Image=([^\s]+)", msg)
        image = image_match.group(1) if image_match else None
        
        return pd.Series({
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "src_ip": src_ip,
            "image": image
        })
    
    # Apply extraction
    edr_features = df.apply(extract_edr_features, axis=1)
    df_edr = pd.concat([df, edr_features], axis=1)
    
    # Ensure timestamp is datetime
    if "timestamp" in df_edr.columns:
        df_edr["timestamp"] = pd.to_datetime(df_edr["timestamp"], errors="coerce")
    
    # ===== STEP 3: CONFIG - LOAD USER BASELINE & DEFINE POLICIES =====
    
    # Load user-to-group mapping from baseline (MongoDB or fallback to files)
    user_baseline = {}
    try:
        from services.database import load_user_to_group
        user_baseline = load_user_to_group(log_type=log_type)
        if not user_baseline:
            # Fallback to file
            user_to_group_path = os.path.join(baselines_dir, "members", "user_to_group.json")
            if os.path.exists(user_to_group_path):
                with open(user_to_group_path, "r", encoding="utf-8") as f:
                    user_baseline = json.load(f)
    except Exception:
        # If MongoDB fails, try file
        try:
            user_to_group_path = os.path.join(baselines_dir, "members", "user_to_group.json")
            if os.path.exists(user_to_group_path):
                with open(user_to_group_path, "r", encoding="utf-8") as f:
                    user_baseline = json.load(f)
        except Exception:
            pass  # If baseline not available, user_baseline will be empty
    
    # Map Baseline Group → Security Policy Role
    GROUP_TO_ROLE_POLICY = {
        "itadmin": "admin",
        "engineering": "engineer",
        "sales": "sales",
        "finance": "finance"
    }
    
    # Role characteristics (Security Policies)
    ROLE_CONFIG = {
        "engineer": {
            "risk_multiplier": 0.8,
            "allowed_processes": ["powershell.exe", "cmd.exe", "ssh.exe", "python.exe"],
            "is_technical": True,
            "allow_ssh": True,
            "allow_internal_infrastructure": True
        },
        "sales": {
            "risk_multiplier": 1.2,
            "allowed_processes": ["chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe"],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK SSH/RDP
            "allow_internal_infrastructure": False  # BLOCK 10.10.10.x
        },
        "finance": {
            "risk_multiplier": 1.3,
            "allowed_processes": ["chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe", "excel.exe"],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK SSH/RDP
            "allow_internal_infrastructure": False  # BLOCK 10.10.10.x
        },
        "admin": {
            "risk_multiplier": 1.0,
            "allowed_processes": [],  # Admins can run anything
            "is_technical": True,
            "allow_ssh": True,
            "allow_internal_infrastructure": True
        },
        "unknown": {  # Default for unknown users
            "risk_multiplier": 1.5,  # Higher risk for unknown users
            "allowed_processes": [],
            "is_technical": False,
            "allow_ssh": False,  # BLOCK all sensitive access
            "allow_internal_infrastructure": False
        }
    }
    
    # Risky processes for non-technical users
    RISKY_PROCESSES = ["powershell.exe", "cmd.exe", "ssh.exe", "psexec.exe", "wmic.exe"]
    
    # Admin ports (SSH, RDP, etc.)
    ADMIN_PORTS = {22, 23, 3389, 445, 1433, 3306, 5432}
    
    # Internal infrastructure servers
    INTERNAL_INFRASTRUCTURE = ["10.10.10.20", "10.10.10.30", "10.10.10.40"]
    
    # ===== STEP 4: HELPER - GET USER ROLE FROM BASELINE =====
    
    def get_user_role(username: str) -> tuple:
        """
        Get user role from baseline data dynamically.
        Returns: (role_name, role_config)
        """
        username_lower = str(username).lower().strip()
        
        # Lookup user in baseline
        if username_lower in user_baseline:
            group = user_baseline[username_lower]
            # Map group to role policy
            role_name = GROUP_TO_ROLE_POLICY.get(group, "unknown")
        else:
            # User not in baseline - treat as unknown
            role_name = "unknown"
        
        role_config = ROLE_CONFIG.get(role_name, ROLE_CONFIG["unknown"])
        
        return role_name, role_config
    
    def is_external_ip(ip: str) -> bool:
        """Check if IP is external (not RFC1918 private)."""
        if not ip:
            return False
        ip_str = str(ip)
        return not (ip_str.startswith("10.") or 
                    ip_str.startswith("192.168.") or 
                    ip_str.startswith("172.16.") or
                    ip_str.startswith("172.17.") or
                    ip_str.startswith("172.18.") or
                    ip_str.startswith("172.19.") or
                    ip_str.startswith("172.20.") or
                    ip_str.startswith("172.21.") or
                    ip_str.startswith("172.22.") or
                    ip_str.startswith("172.23.") or
                    ip_str.startswith("172.24.") or
                    ip_str.startswith("172.25.") or
                    ip_str.startswith("172.26.") or
                    ip_str.startswith("172.27.") or
                    ip_str.startswith("172.28.") or
                    ip_str.startswith("172.29.") or
                    ip_str.startswith("172.30.") or
                    ip_str.startswith("172.31."))
    
    # ==============================================================================
    # MODULE A: C2 BEACONING DETECTION (CRITICAL - New!)
    # ==============================================================================
    # Detect periodic connections to external IPs (malware calling home)
    
    try:
        # Filter connections to external IPs
        external_conns = df_edr[df_edr["dest_ip"].apply(is_external_ip)].copy()
        
        if not external_conns.empty and "timestamp" in external_conns.columns:
            # Group by (user, dest_ip)
            for (username, dest_ip), group in external_conns.groupby(["username", "dest_ip"]):
                username = str(username).strip()
                dest_ip = str(dest_ip)
                
                if len(group) < 10:  # Need at least 10 connections to detect pattern
                    continue
                
                # Sort by timestamp
                sorted_group = group.sort_values("timestamp")
                timestamps = sorted_group["timestamp"].dropna()
                
                if len(timestamps) < 10:
                    continue
                
                # Calculate time deltas between consecutive connections
                time_deltas = timestamps.diff().dropna()
                delta_seconds = time_deltas.dt.total_seconds()
                
                if len(delta_seconds) < 5:
                    continue
                
                # Calculate variance of time deltas
                mean_interval = delta_seconds.mean()
                variance = delta_seconds.var()
                std_dev = delta_seconds.std()
                
                # Beaconing signature: Low variance + regular interval
                # Typical C2: every 5s, 10s, 30s, 60s with very low deviation
                is_beaconing = False
                
                if variance < 5.0 and mean_interval < 300:  # < 5min interval, very regular
                    is_beaconing = True
                elif std_dev < 2.0 and mean_interval < 60:  # < 1min interval, tight timing
                    is_beaconing = True
                
                if is_beaconing:
                    # Extract process name
                    process_name = "unknown"
                    if "image" in sorted_group.columns:
                        images = sorted_group["image"].dropna()
                        if len(images) > 0:
                            # Get most common process
                            process_name = images.mode()[0] if not images.mode().empty else str(images.iloc[0])
                            # Extract basename
                            if "\\" in process_name or "/" in process_name:
                                process_name = process_name.split("\\")[-1].split("/")[-1]
                    
                    alerts.append({
                        "type": "c2_beaconing_detected",
                        "subject": username,
                        "severity": "CRITICAL",
                        "score": 10.0,
                        "text": f"🚨 C2 BEACONING: User {username} machine infected! Process '{process_name}' connecting to {dest_ip} every {mean_interval:.1f}s (variance: {variance:.2f})",
                        "evidence": {
                            "username": username,
                            "dest_ip": dest_ip,
                            "process": process_name,
                            "connection_count": len(group),
                            "mean_interval_seconds": float(mean_interval),
                            "variance": float(variance),
                            "std_dev": float(std_dev),
                            "beaconing_pattern": f"Every {mean_interval:.1f}±{std_dev:.1f}s"
                        },
                        "prompt_ctx": {
                            "user": username,
                            "group": None,
                            "behavior": {
                                "type": "c2_beaconing",
                                "process": process_name,
                                "dest_ip": dest_ip,
                                "interval": mean_interval
                            },
                            "time": None,
                            "baseline": {},
                            "extras": {
                                "reason": "Periodic connection pattern detected - strong indicator of malware C2 communication"
                            }
                        }
                    })
    except Exception as e:
        pass  # Beaconing detection failed, continue
    
    # ==============================================================================
    # MODULE B: SUSPICIOUS PROCESS EXECUTION (CRITICAL - New!)
    # ==============================================================================
    # Detect non-technical users running technical tools to external IPs
    
    try:
        for idx, row in df_edr.iterrows():
            username = str(row.get("username", "")).strip()
            if not username or username in ["(unknown)", "nan", ""]:
                continue
            
            image = str(row.get("image", ""))
            dest_ip = str(row.get("dest_ip", ""))
            
            if not image or not dest_ip:
                continue
            
            # Extract process basename
            process_name = image.split("\\")[-1].split("/")[-1].lower()
            
            # Check if external IP
            if not is_external_ip(dest_ip):
                continue
            
            # Infer user role
            user_role, role_config = get_user_role(username)
            
            # Check if non-technical user
            if role_config.get("is_technical", False):
                continue  # Technical users can run these tools
            
            # Check if risky process
            if any(risky in process_name for risky in RISKY_PROCESSES):
                # Create alert key to avoid duplicates
                alert_key = f"{username}_{process_name}_{dest_ip}"
                
                # Check if already alerted (use a set to track)
                if not hasattr(_detect_edr_anomalies, '_process_alerts'):
                    _detect_edr_anomalies._process_alerts = set()
                
                if alert_key in _detect_edr_anomalies._process_alerts:
                    continue
                
                _detect_edr_anomalies._process_alerts.add(alert_key)
                
                alerts.append({
                    "type": "suspicious_process_external_connection",
                    "subject": username,
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "text": f"🚨 SUSPICIOUS PROCESS: {user_role} user '{username}' running {process_name} connecting to external IP {dest_ip}",
                    "evidence": {
                        "username": username,
                        "user_role": user_role,
                        "process": process_name,
                        "dest_ip": dest_ip,
                        "reason": f"{user_role} users should not run {process_name}"
                    },
                    "prompt_ctx": {
                        "user": username,
                        "group": None,
                        "behavior": {
                            "type": "suspicious_process",
                            "process": process_name,
                            "dest_ip": dest_ip
                        },
                        "time": None,
                        "baseline": {},
                        "extras": {
                            "reason": f"Non-technical user ({user_role}) executing technical tool ({process_name}) to external network"
                        }
                    }
                })
    except Exception as e:
        pass  # Process detection failed, continue
    
    # Clear process alerts tracking for next call
    if hasattr(_detect_edr_anomalies, '_process_alerts'):
        _detect_edr_anomalies._process_alerts = set()
    
    # ==============================================================================
    # MODULE C: VOLUME SPIKE (Refined - Absolute Count Based)
    # ==============================================================================
    
    # Load baseline from MongoDB (PRIMARY) or files (FALLBACK)
    base = _load_baseline_tables(baselines_dir, log_type=log_type)
    user_stats = base.get("user_stats")
    if not isinstance(user_stats, pd.DataFrame) or user_stats.empty:
        user_stats = pd.DataFrame()
    else:
        if "username" in user_stats.columns:
            user_stats = user_stats.copy()
            user_stats["username"] = user_stats["username"].astype(str)
    
    # Aggregate per-user activity
    user_network_activity = df_edr.groupby("username").agg({
        "src_ip": lambda x: x.dropna().nunique(),
        "dest_ip": lambda x: x.dropna().unique().tolist(),
        "dest_port": lambda x: x.dropna().unique().tolist()
    }).reset_index()
    
    user_network_activity.columns = ["username", "unique_src_ips", "destinations", "dest_ports"]
    
    for _, row in user_network_activity.iterrows():
        username = str(row["username"]).strip()
        if not username or username in ["(unknown)", "nan", ""]:
            continue
        
        unique_src_ips = int(row["unique_src_ips"])
        destinations = row["destinations"]
        dest_ports = [int(p) for p in row["dest_ports"] if pd.notna(p)]
        
        # Skip if too few connections
        if unique_src_ips < 3:
            continue
        
        # Get baseline
        baseline_ips = 0.0
        if not user_stats.empty and "unique_src_ips_mean" in user_stats.columns:
            user_baseline = user_stats[user_stats["username"] == username]
            if not user_baseline.empty:
                baseline_ips = float(user_baseline["unique_src_ips_mean"].iloc[0] or 0.0)
        
        if baseline_ips == 0.0:
            baseline_ips = 10.0  # Default baseline
        
        # Infer role
        user_role, role_config = get_user_role(username)
        
        # ===== PATTERN CLASSIFICATION: Detect specific attack type =====
        
        # Get this user's actual connections for detailed analysis
        user_connections = df_edr[df_edr["username"] == username].copy()
        
        def classify_network_pattern(user_df, destinations, dest_ports, unique_src_ips, user_role):
            """
            Classify network anomaly into specific attack pattern.
            Priority order: LOLBins > Port Scan > RDP Brute Force > Lateral Movement > Data Exfiltration > Network Spike
            """
            # Known Living Off The Land Binaries
            LOLBINS = {"powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe", 
                       "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                       "msiexec.exe", "regasm.exe", "installutil.exe", "cscript.exe", "wscript.exe"}
            
            # Calculate metrics
            external_ips = [ip for ip in destinations if is_external_ip(ip)]
            external_ip_count = len(set(external_ips))
            unique_dest_ips = len(set(destinations))
            unique_ports = len(set(dest_ports))
            
            
            # Priority 1: LOLBins Outbound
            # Check if user executed LOLBins processes making external connections
            if external_ip_count > 0:
                # Check all processes (images) executed by this user
                lolbins_detected = set()
                for _, conn in user_df.iterrows():
                    image = str(conn.get("image", "")).lower()
                    # Extract just the filename from full path
                    if "\\" in image:
                        image = image.split("\\")[-1]
                    
                    # Check if it's a LOLBin
                    for lolbin in LOLBINS:
                        if lolbin.lower() in image:
                            lolbins_detected.add(lolbin)
                            break
                
                # If LOLBins found with external connections, flag it
                if len(lolbins_detected) > 0:
                    return "edr_lolbins_outbound_detected", "lolbins_outbound"
            
            # Priority 2: Port Scanning
            # Scanning 10+ different ports indicates reconnaissance behavior
            if unique_ports >= 10 and unique_dest_ips > 0:
                return "edr_port_scan_detected", "port_scan"
            
            # Priority 3: RDP Brute Force
            rdp_connections = sum(1 for p in dest_ports if p == 3389)
            if rdp_connections >= 30 and unique_src_ips >= 10:
                if user_role not in ["admin", "netops"]:
                    return "edr_rdp_bruteforce_detected", "rdp_bruteforce"
            
            # Priority 4: Lateral Movement 
            #Check connections to internal infrastructure servers on admin ports
            admin_ports = {22, 23, 3389, 445, 1433, 3306, 5432}
            internal_servers_accessed = set()
            
            for _, conn in user_df.iterrows():
                dest_ip = conn.get("destination_ip")
                dest_port = conn.get("destination_port")
                if pd.notna(dest_ip) and pd.notna(dest_port):
                    if dest_ip in INTERNAL_INFRASTRUCTURE and int(dest_port) in admin_ports:
                        internal_servers_accessed.add(dest_ip)
            
            # Lateral movement: >=2 internal servers accessed on admin ports
            if len(internal_servers_accessed) >= 2:
                if user_role not in ["admin", "netops"]:
                    return "edr_lateral_movement_detected", "lateral_movement"
            
            # Priority 5: C2 Beacon Detection
            # C2 beacons repeatedly connect to same external IP on suspicious ports
            C2_PORTS = {443, 8080, 4444, 8443, 1337, 6666, 9999, 53, 80}
            c2_connections = {}  # external_ip -> count
            for _, conn in user_df.iterrows():
                dest_ip = str(conn.get("destination_ip", ""))
                dest_port = conn.get("destination_port", 0)
                try:
                    dest_port = int(dest_port)
                except:
                    dest_port = 0
                
                # Check for external IP on C2 common ports
                if dest_ip and is_external_ip(dest_ip) and dest_port in C2_PORTS:
                    c2_connections[dest_ip] = c2_connections.get(dest_ip, 0) + 1
            
            # If any external IP has >= 10 connections on C2 ports = beaconing
            for ext_ip, conn_count in c2_connections.items():
                if conn_count >= 10:
                    return "edr_c2_beacon_detected", "c2_beacon"
            
            # Priority 6: Data Exfiltration
            if external_ip_count >= 15 and unique_dest_ips > 0:
                external_ip_ratio = external_ip_count / unique_dest_ips
                if external_ip_ratio > 0.6:
                    return "edr_data_exfiltration_detected", "data_exfiltration"
            
            # Fallback: Network Spike
            return "edr_network_spike", "network_spike"
        
        # Classify the pattern
        alert_type, attack_pattern = classify_network_pattern(user_connections, destinations, dest_ports, unique_src_ips, user_role)
        
        
        # ===== MODULE C: SCORING (Absolute + Percentage) =====
        
        # Base score (absolute count)
        if unique_src_ips >= 30:
            base_score = 9.0
        elif unique_src_ips >= 20:
            base_score = 7.0
        elif unique_src_ips >= 10:
            base_score = 5.0
        else:
            base_score = 3.0
        
        # Percentage increase bonus (capped)
        if baseline_ips > 0:
            pct_increase = (unique_src_ips - baseline_ips) / baseline_ips
            if pct_increase > 3.0:
                base_score += 1.0
            elif pct_increase > 2.0:
                base_score += 0.5
        
        
        # ===== MODULE D: UPDATED PENALTY LOGIC (Sales/Finance Enforcement) =====
        
        penalty = 0.0
        penalty_reasons = []
        
        # Rule 1: Sales/Finance BLOCKED from SSH/RDP (Port 22, 3389)
        if not role_config.get("allow_ssh", True):  # If user NOT allowed SSH
            ssh_rdp_ports = {22, 3389}
            accessed_ssh_rdp = set(dest_ports) & ssh_rdp_ports
            if accessed_ssh_rdp:
                penalty += 3.0
                port_names = [f"Port {p} ({'SSH' if p == 22 else 'RDP'})" for p in accessed_ssh_rdp]
                penalty_reasons.append(f"{user_role.upper()} users BLOCKED from {', '.join(port_names)}")
        
        # Rule 2: Sales/Finance BLOCKED from Internal Infrastructure (10.10.10.x)
        if not role_config.get("allow_internal_infrastructure", True):
            accessed_internal = [ip for ip in destinations if ip in INTERNAL_INFRASTRUCTURE]
            if accessed_internal:
                penalty += 2.5
                penalty_reasons.append(f"{user_role.upper()} users BLOCKED from internal infrastructure: {', '.join(accessed_internal)}")
        
        # Rule 3: Check for external connections to admin ports (all users)
        external_admin_access = False
        for dest_ip, dest_port in zip(destinations, dest_ports):
            if is_external_ip(dest_ip) and dest_port in ADMIN_PORTS:
                external_admin_access = True
                penalty += 2.0
                penalty_reasons.append(f"External admin access: {dest_ip}:{dest_port}")
                break
        
        # Rule 4: Check for excessive external connections
        external_ips = [ip for ip in destinations if is_external_ip(ip)]
        if len(external_ips) > 10:
            penalty += 1.0
            penalty_reasons.append(f"High external IP count: {len(external_ips)} connections")
        
        # Apply role multiplier
        risk_multiplier = role_config.get("risk_multiplier", 1.0)
        final_score = (base_score + penalty) * risk_multiplier
        final_score = min(final_score, 10.0)
        
        # Determine severity
        if final_score >= 8.0:
            severity = "CRITICAL"
        elif final_score >= 5.0:
            severity = "WARNING"
        else:
            severity = "INFO"
        
        # Skip low-risk alerts
        if final_score < 4.0:
            continue
        
        # Build alert text
        alert_text = f"User {username} ({user_role}): {unique_src_ips} unique source IPs (baseline: {baseline_ips:.0f})"
        
        if penalty_reasons:
            alert_text += " - " + "; ".join(penalty_reasons)
        
        # Build evidence
        evidence = {
            "username": username,
            "user_role": user_role,
            "attack_pattern": attack_pattern,  # NEW: Add attack pattern classification
            "unique_src_ips": unique_src_ips,
            "baseline_ips": baseline_ips,
            "destinations_count": len(destinations),
            "unique_ports": len(dest_ports),
            "external_ips_count": len(external_ips),
            "penalty_reasons": penalty_reasons,
            "risk_multiplier": risk_multiplier
        }
        
        # Create alert
        alerts.append({
            "type": alert_type,  # Use classified alert type instead of hardcoded
            "subject": username,
            "severity": severity,
            "score": final_score,
            "text": alert_text,
            "evidence": evidence,
            "prompt_ctx": {
                "user": username,
                "group": None,
                "behavior": {
                    "type": "network_anomaly",
                    "role": user_role,
                    "unique_src_ips": unique_src_ips,
                    "baseline_ips": baseline_ips
                },
                "time": None,
                "baseline": {
                    "expected_ips": baseline_ips,
                    "user_role": user_role
                },
                "extras": {
                    "penalty_reasons": penalty_reasons,
                    "risk_calculation": "context-aware v2 (absolute + % + role + external admin only)"
                }
            }
        })
    
    return alerts


# ==============================================================================
# Router/Network Infrastructure Anomaly Detection
# ==============================================================================

def _detect_router_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Detect router/network infrastructure attacks based on Cisco IOS syslog patterns.
    
    Enhanced with User Correlation:
    - Extracts login events (SEC_LOGIN) and config events (CONFIG_I)
    - Builds user timeline per router
    - Attributes infrastructure attacks to users who were active within correlation window
    
    Detections:
    1. BGP Flap Attack - Rapid BGP neighbor down events indicating route hijacking/instability
    2. Interface Flap Attack - Rapid interface up/down events indicating physical layer issues
    3. Config Tampering - Unauthorized configuration changes via VTY
    4. OSPF Storm - Rapid OSPF adjacency changes indicating routing attack
    
    Args:
        df: DataFrame containing router syslog entries
        
    Returns:
        List of alert dictionaries with type, subject (user or router), severity, score, text, evidence
    """
    alerts: List[Dict[str, Any]] = []
    
    if df is None or df.empty:
        return alerts
    
    # Check if this is router log data
    is_router_log = False
    msg_col = "message" if "message" in df.columns else None
    host_col = "hostname" if "hostname" in df.columns else ("host" if "host" in df.columns else None)
    
    if msg_col:
        # Check for Cisco IOS patterns
        sample_msgs = df[msg_col].astype(str).head(100).str.cat(sep=' ')
        router_indicators = [
            r'%BGP-\d+-',
            r'%OSPF-\d+-',
            r'%LINK-\d+-',
            r'%LINEPROTO-\d+-',
            r'%SYS-\d+-CONFIG_I',
            r'%SEC_LOGIN-\d+-',
            r'ios\[',
            r'rtr-\w+'
        ]
        for pattern in router_indicators:
            if re.search(pattern, sample_msgs, re.IGNORECASE):
                is_router_log = True
                break
    
    if not is_router_log:
        return alerts
    
    # Extract time window for rate calculations
    time_window_minutes = 60
    if "timestamp" in df.columns:
        try:
            timestamps = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
            valid_ts = timestamps.dropna()
            if len(valid_ts) >= 2:
                time_window_minutes = (valid_ts.max() - valid_ts.min()).total_seconds() / 60
                if time_window_minutes < 1:
                    time_window_minutes = 1
        except:
            pass
    
    # =========================================================================
    # STEP 1: Extract User Activity Events (Login + Config)
    # =========================================================================
    
    # Pattern for SEC_LOGIN: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user:X] [Source:Y] [VTY] device=Z
    login_pattern = r'%SEC_LOGIN-\d+-LOGIN_SUCCESS.*\[user:(\S+)\].*\[Source:([\d\.]+)\]'
    
    # Pattern for CONFIG_I: %SYS-5-CONFIG_I: Configured from vty by USER (IP) using device DEV
    config_pattern = r'%SYS-\d+-CONFIG_I.*Configured\s+from\s+(\w+)\s+by\s+(\S+)\s*\(?([\d\.]+)?'
    
    # Store user activity per router: {router: [(timestamp, user, source_ip, event_type), ...]}
    user_activity_by_router = {}
    
    for idx, row in df.iterrows():
        msg = str(row.get(msg_col, "")) if msg_col else ""
        router = str(row.get(host_col, "unknown")) if host_col else "unknown"
        timestamp = row.get("timestamp")
        
        # Check for login event
        login_match = re.search(login_pattern, msg, re.IGNORECASE)
        if login_match:
            username = login_match.group(1)
            source_ip = login_match.group(2)
            if router not in user_activity_by_router:
                user_activity_by_router[router] = []
            user_activity_by_router[router].append({
                "timestamp": timestamp,
                "user": username,
                "source_ip": source_ip,
                "event_type": "login"
            })
            continue
        
        # Check for config event
        config_match = re.search(config_pattern, msg, re.IGNORECASE)
        if config_match:
            username = config_match.group(2)
            source_ip = config_match.group(3) if config_match.group(3) else "unknown"
            if router not in user_activity_by_router:
                user_activity_by_router[router] = []
            user_activity_by_router[router].append({
                "timestamp": timestamp,
                "user": username,
                "source_ip": source_ip,
                "event_type": "config"
            })
    
    # Helper function to find users active on router within time window
    def find_correlated_users(router: str, event_timestamp, correlation_minutes: int = 5) -> List[dict]:
        """Find users who were active on this router within correlation_minutes before event."""
        if router not in user_activity_by_router:
            return []
        
        correlated = []
        try:
            event_ts = pd.to_datetime(event_timestamp, utc=True)
            if pd.isna(event_ts):
                return []
            
            for activity in user_activity_by_router[router]:
                activity_ts = pd.to_datetime(activity["timestamp"], utc=True)
                if pd.isna(activity_ts):
                    continue
                
                # Check if activity happened within correlation_minutes before the event
                time_diff = (event_ts - activity_ts).total_seconds() / 60
                if 0 <= time_diff <= correlation_minutes:
                    correlated.append({
                        "user": activity["user"],
                        "source_ip": activity["source_ip"],
                        "event_type": activity["event_type"],
                        "minutes_before": round(time_diff, 1)
                    })
        except:
            pass
        
        return correlated
    
    # =========================================================================
    # STEP 2: Collect All Infrastructure Events with Timestamps
    # =========================================================================
    
    # BGP Flap events
    bgp_down_pattern = r'%BGP-\d+-ADJCHANGE.*neighbor\s+([\d\.]+)\s+Down'
    bgp_events = []
    
    # Interface Flap events
    interface_pattern = r'%(LINK|LINEPROTO)-\d+-UPDOWN.*Interface\s+(\S+).*changed\s+state\s+to\s+(up|down)'
    interface_events = []
    
    # OSPF Storm events
    ospf_pattern = r'%OSPF-\d+-ADJCHG.*Nbr\s+([\d\.]+)\s+on\s+(\S+)\s+from\s+(\w+)\s+to\s+(\w+)'
    ospf_events = []
    
    # Config Tampering events (already captured above, collect here for alerting)
    config_events = []
    
    for idx, row in df.iterrows():
        msg = str(row.get(msg_col, "")) if msg_col else ""
        router = str(row.get(host_col, "unknown")) if host_col else "unknown"
        timestamp = row.get("timestamp")
        
        # BGP Down
        bgp_match = re.search(bgp_down_pattern, msg, re.IGNORECASE)
        if bgp_match:
            bgp_events.append({
                "router": router,
                "neighbor": bgp_match.group(1),
                "timestamp": timestamp
            })
            continue
        
        # Interface state change
        iface_match = re.search(interface_pattern, msg, re.IGNORECASE)
        if iface_match:
            interface_events.append({
                "router": router,
                "interface": iface_match.group(2).rstrip(','),
                "state": iface_match.group(3).lower(),
                "timestamp": timestamp
            })
            continue
        
        # OSPF adjacency change
        ospf_match = re.search(ospf_pattern, msg, re.IGNORECASE)
        if ospf_match:
            from_state = ospf_match.group(3)
            to_state = ospf_match.group(4)
            ospf_events.append({
                "router": router,
                "neighbor": ospf_match.group(1),
                "interface": ospf_match.group(2).rstrip(','),
                "from_state": from_state,
                "to_state": to_state,
                "is_down": from_state.upper() == "FULL" and to_state.upper() != "FULL",
                "timestamp": timestamp
            })
            continue
        
        # Config change
        config_match = re.search(config_pattern, msg, re.IGNORECASE)
        if config_match:
            config_events.append({
                "router": router,
                "user": config_match.group(2),
                "source_ip": config_match.group(3) if config_match.group(3) else "unknown",
                "source": config_match.group(1),
                "timestamp": timestamp
            })
    
    # =========================================================================
    # STEP 3: Generate Alerts with User Attribution
    # =========================================================================
    
    # Aggregate user involvement across all routers for infrastructure events
    user_infrastructure_involvement = {}  # {user: {bgp: [...], interface: [...], ospf: [...]}}
    
    # Process BGP events and correlate with users
    for event in bgp_events:
        correlated_users = find_correlated_users(event["router"], event["timestamp"], correlation_minutes=5)
        for user_info in correlated_users:
            user = user_info["user"]
            if user not in user_infrastructure_involvement:
                user_infrastructure_involvement[user] = {"bgp": [], "interface": [], "ospf": [], "config": [], "routers": set(), "source_ips": set()}
            user_infrastructure_involvement[user]["bgp"].append(event)
            user_infrastructure_involvement[user]["routers"].add(event["router"])
            user_infrastructure_involvement[user]["source_ips"].add(user_info["source_ip"])
    
    # Process Interface events
    for event in interface_events:
        correlated_users = find_correlated_users(event["router"], event["timestamp"], correlation_minutes=5)
        for user_info in correlated_users:
            user = user_info["user"]
            if user not in user_infrastructure_involvement:
                user_infrastructure_involvement[user] = {"bgp": [], "interface": [], "ospf": [], "config": [], "routers": set(), "source_ips": set()}
            user_infrastructure_involvement[user]["interface"].append(event)
            user_infrastructure_involvement[user]["routers"].add(event["router"])
            user_infrastructure_involvement[user]["source_ips"].add(user_info["source_ip"])
    
    # Process OSPF events
    for event in ospf_events:
        correlated_users = find_correlated_users(event["router"], event["timestamp"], correlation_minutes=5)
        for user_info in correlated_users:
            user = user_info["user"]
            if user not in user_infrastructure_involvement:
                user_infrastructure_involvement[user] = {"bgp": [], "interface": [], "ospf": [], "config": [], "routers": set(), "source_ips": set()}
            user_infrastructure_involvement[user]["ospf"].append(event)
            user_infrastructure_involvement[user]["routers"].add(event["router"])
            user_infrastructure_involvement[user]["source_ips"].add(user_info["source_ip"])
    
    # Process Config events (direct attribution)
    for event in config_events:
        user = event["user"]
        if user not in user_infrastructure_involvement:
            user_infrastructure_involvement[user] = {"bgp": [], "interface": [], "ospf": [], "config": [], "routers": set(), "source_ips": set()}
        user_infrastructure_involvement[user]["config"].append(event)
        user_infrastructure_involvement[user]["routers"].add(event["router"])
        if event["source_ip"] != "unknown":
            user_infrastructure_involvement[user]["source_ips"].add(event["source_ip"])
    
    # =========================================================================
    # STEP 4: Generate Per-User Alerts with Filtering & Ranking
    # =========================================================================
    # 
    # FILTERING RULES:
    # Rule 1 (Smoking Gun): Users with config changes are PRIMARY SUSPECTS
    # Rule 2 (Frequency): Only show Top 5 users by correlation score
    # 
    # Correlation Score = config_count * 10 + bgp_count + iface_count + ospf_count
    # (Config changes weighted 10x because "login + config" is much more suspicious than "login only")
    # =========================================================================
    
    # Calculate correlation score for each user
    user_scores = []
    for user, involvement in user_infrastructure_involvement.items():
        bgp_count = len(involvement["bgp"])
        iface_count = len(involvement["interface"])
        ospf_count = len(involvement["ospf"])
        config_count = len(involvement["config"])
        
        # Smoking Gun Rule: Config changes weighted 10x
        correlation_score = (config_count * 10) + bgp_count + iface_count + ospf_count
        
        # Determine suspect level
        if config_count >= 3:
            suspect_level = "PRIMARY_SUSPECT"
        elif config_count >= 1:
            suspect_level = "SECONDARY_SUSPECT"
        else:
            suspect_level = "INCIDENTAL"  # Login only, no config changes
        
        user_scores.append({
            "user": user,
            "involvement": involvement,
            "correlation_score": correlation_score,
            "suspect_level": suspect_level,
            "bgp_count": bgp_count,
            "iface_count": iface_count,
            "ospf_count": ospf_count,
            "config_count": config_count
        })
    
    # Sort by correlation_score descending, then by config_count descending
    user_scores.sort(key=lambda x: (x["correlation_score"], x["config_count"]), reverse=True)
    
    # Rule 2: Only keep Top 5 users
    TOP_N_SUSPECTS = 5
    top_suspects = user_scores[:TOP_N_SUSPECTS]
    
    # Generate alerts only for top suspects
    for suspect in top_suspects:
        user = suspect["user"]
        involvement = suspect["involvement"]
        bgp_count = suspect["bgp_count"]
        iface_count = suspect["iface_count"]
        ospf_count = suspect["ospf_count"]
        config_count = suspect["config_count"]
        correlation_score = suspect["correlation_score"]
        suspect_level = suspect["suspect_level"]
        
        routers_list = list(involvement["routers"])
        source_ips = list(involvement["source_ips"])
        
        total_infra_events = bgp_count + iface_count + ospf_count
        
        alert_types = []
        event_details = []
        
        # BGP involvement
        if bgp_count >= 3:
            alert_types.append("bgp_flap_correlated")
            event_details.append(f"{bgp_count} BGP neighbor down events")
        
        # Interface involvement
        if iface_count >= 5:
            alert_types.append("interface_flap_correlated")
            event_details.append(f"{iface_count} interface state changes")
        
        # OSPF involvement
        ospf_downs = sum(1 for e in involvement["ospf"] if e.get("is_down", False))
        if ospf_count >= 3 or ospf_downs >= 2:
            alert_types.append("ospf_storm_correlated")
            event_details.append(f"{ospf_count} OSPF events ({ospf_downs} adjacency downs)")
        
        # Config tampering - primary indicator
        if config_count >= 1:
            alert_types.append("config_tampering")
            event_details.append(f"{config_count} config changes")
        
        # Skip if no meaningful alert types (shouldn't happen for top suspects)
        if not alert_types:
            continue
        
        # Calculate score based on involvement level and suspect status
        if suspect_level == "PRIMARY_SUSPECT":
            base_score = 8.0  # Primary suspects start higher
        elif suspect_level == "SECONDARY_SUSPECT":
            base_score = 6.5
        else:
            base_score = 5.0
        
        # Boost score based on event counts
        if correlation_score >= 80:
            base_score = max(base_score, 9.0)
        elif correlation_score >= 50:
            base_score = max(base_score, 8.0)
        elif correlation_score >= 30:
            base_score = max(base_score, 7.0)
        
        if len(routers_list) >= 5:
            base_score += 0.5  # Multi-router involvement
        
        score = min(9.5, base_score)
        severity = "CRITICAL" if score >= 7.0 else "WARNING"
        
        # Add suspect level and correlation score to text
        suspect_label = f"[{suspect_level}] " if suspect_level == "PRIMARY_SUSPECT" else ""
        
        ctx = {
            "user": user,
            "group": None,
            "behavior": {
                "type": "router_infrastructure_attack",
                "bgp_events": bgp_count,
                "interface_events": iface_count,
                "ospf_events": ospf_count,
                "config_events": config_count,
                "correlation_score": correlation_score,
                "suspect_level": suspect_level
            },
            "time": {"window_minutes": time_window_minutes},
            "baseline": {"expected_events": 0},
            "extras": {
                "routers": routers_list,
                "source_ips": source_ips,
                "alert_types": alert_types
            },
        }
        
        alerts.append({
            "type": ", ".join(alert_types),
            "subject": user,
            "severity": severity,
            "score": float(score),
            "text": f"{suspect_label}User {user} correlated with network infrastructure attacks: {'; '.join(event_details)}. "
                    f"Correlation score: {correlation_score}. "
                    f"Active on {len(routers_list)} router(s): {', '.join(routers_list[:5])}. "
                    f"Source IPs: {', '.join(source_ips[:3])}. "
                    f"User was logged in/configuring devices within 5 minutes of attack events.",
            "evidence": {
                "username": user,
                "suspect_level": suspect_level,
                "correlation_score": correlation_score,
                "bgp_events": bgp_count,
                "interface_events": iface_count,
                "ospf_events": ospf_count,
                "config_events": config_count,
                "affected_routers": routers_list[:10],
                "source_ips": source_ips[:5],
                "correlation_window_minutes": 5
            },
            "prompt_ctx": ctx
        })
    
    # =========================================================================
    # STEP 5: Generate Infrastructure-Level Alerts (for events without user correlation)
    # =========================================================================
    
    # Find routers with events that have NO correlated users
    uncorrelated_bgp = [e for e in bgp_events if not find_correlated_users(e["router"], e["timestamp"], 5)]
    uncorrelated_iface = [e for e in interface_events if not find_correlated_users(e["router"], e["timestamp"], 5)]
    uncorrelated_ospf = [e for e in ospf_events if not find_correlated_users(e["router"], e["timestamp"], 5)]
    
    # BGP Flap Attack (uncorrelated)
    if len(uncorrelated_bgp) >= 5:
        rate_per_min = len(uncorrelated_bgp) / time_window_minutes
        affected_routers = list(set(e["router"] for e in uncorrelated_bgp))
        
        if rate_per_min >= 1.0:
            score = min(9.0, 6.5 + rate_per_min)
            severity = "CRITICAL"
        else:
            score = min(6.0, 4.5 + rate_per_min)
            severity = "WARNING"
        
        alerts.append({
            "type": "bgp_flap_attack_unattributed",
            "subject": f"{len(affected_routers)} routers",
            "severity": severity,
            "score": float(score),
            "text": f"BGP Flap Attack detected (no user correlation found): {len(uncorrelated_bgp)} BGP neighbor down events "
                    f"in {time_window_minutes:.0f} minutes ({rate_per_min:.2f}/min). "
                    f"Affected routers: {', '.join(affected_routers[:5])}. "
                    f"Could be external attack or network issue.",
            "evidence": {
                "total_bgp_downs": len(uncorrelated_bgp),
                "rate_per_minute": float(rate_per_min),
                "affected_routers": affected_routers[:10],
                "user_attribution": "none"
            },
            "prompt_ctx": {"user": None, "group": None, "behavior": {"type": "bgp_flap_unattributed"}}
        })
    
    # Interface Flap (uncorrelated)
    if len(uncorrelated_iface) >= 10:
        rate_per_min = len(uncorrelated_iface) / time_window_minutes
        affected_routers = list(set(e["router"] for e in uncorrelated_iface))
        
        if rate_per_min >= 2.0:
            score = min(8.0, 6.0 + rate_per_min * 0.5)
            severity = "CRITICAL"
        else:
            score = min(5.5, 4.0 + rate_per_min * 0.5)
            severity = "WARNING"
        
        alerts.append({
            "type": "interface_flap_attack_unattributed",
            "subject": f"{len(affected_routers)} routers",
            "severity": severity,
            "score": float(score),
            "text": f"Interface Flap detected (no user correlation found): {len(uncorrelated_iface)} interface state changes "
                    f"in {time_window_minutes:.0f} minutes. Could be physical layer issue or external attack.",
            "evidence": {
                "total_events": len(uncorrelated_iface),
                "affected_routers": affected_routers[:10],
                "user_attribution": "none"
            },
            "prompt_ctx": {"user": None, "group": None, "behavior": {"type": "interface_flap_unattributed"}}
        })
    
    # OSPF Storm (uncorrelated)
    if len(uncorrelated_ospf) >= 5:
        ospf_downs = sum(1 for e in uncorrelated_ospf if e.get("is_down", False))
        rate_per_min = len(uncorrelated_ospf) / time_window_minutes
        affected_routers = list(set(e["router"] for e in uncorrelated_ospf))
        
        if rate_per_min >= 1.0 or ospf_downs >= 5:
            score = min(8.0, 6.0 + rate_per_min * 0.5)
            severity = "CRITICAL"
        else:
            score = min(5.5, 4.5 + rate_per_min)
            severity = "WARNING"
        
        alerts.append({
            "type": "ospf_storm_unattributed",
            "subject": f"{len(affected_routers)} routers",
            "severity": severity,
            "score": float(score),
            "text": f"OSPF Adjacency Storm detected (no user correlation found): {len(uncorrelated_ospf)} OSPF events "
                    f"({ospf_downs} adjacency downs) in {time_window_minutes:.0f} minutes. "
                    f"Could be routing attack or network instability.",
            "evidence": {
                "total_ospf_events": len(uncorrelated_ospf),
                "adjacency_downs": ospf_downs,
                "affected_routers": affected_routers[:10],
                "user_attribution": "none"
            },
            "prompt_ctx": {"user": None, "group": None, "behavior": {"type": "ospf_storm_unattributed"}}
        })
    
    return alerts


def generate_raw_anomalies(df: pd.DataFrame, baselines_dir: str, log_type: str = "generic") -> List[Dict[str, Any]]:
    """
    Step-2 generator: compare current window against stored baselines to produce human-readable alerts.
    Returns a list of dicts {type, subject, severity, score, text, evidence}
    
    This improved version handles mixed logs (normal + attack) by using multiple detection strategies:
    1. Pattern-based detection (high-confidence attacks)
    2. Statistical deviation from baseline
    3. Behavioral anomalies (spike detection)
    
    Args:
        df: DataFrame with logs
        baselines_dir: Path to baselines directory (for fallback)
        log_type: Log type for MongoDB query (generic, linuxsyslog, edr, etc.)
    """
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return []
    df = _to_dt_utc(df)

    base = _load_baseline_tables(baselines_dir, log_type=log_type)
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
    
    # ===== DETECT LOG TYPE TO PREVENT HALLUCINATIONS =====
    # DHCP logs only have IP allocation - NO database, NO downloads, NO login failures
    is_dhcp = False
    if "program" in df.columns:
        dhcp_programs = df["program"].astype(str).str.contains("dhcpd|dhcp", case=False, na=False).any()
        is_dhcp = dhcp_programs
    # Alternative: check for typical DHCP actions
    if not is_dhcp and "action" in df.columns:
        dhcp_actions = df["action"].astype(str).str.lower().isin(["discover", "offer", "request", "ack", "nak", "release", "inform"]).any()
        is_dhcp = dhcp_actions
    
    # ===== DHCP-SPECIFIC DETECTIONS =====
    # Call DHCP behavior analysis functions for DHCP logs
    if is_dhcp:
        alerts.extend(_detect_dhcp_scope_conflicts(df))
        alerts.extend(_detect_dhcp_rogue_server(df))
        alerts.extend(_detect_dhcp_user_device_mismatch(df))
        alerts.extend(_detect_dhcp_vlan_hopping(df))
        alerts.extend(_detect_dhcp_frequent_release(df))

    # ===== FIREWALL-SPECIFIC DETECTIONS WITH IP-TO-USER ATTRIBUTION =====
    # Firewall logs get IP-based detection with username resolution
    alerts.extend(_detect_firewall_anomalies(df))

    # ===== EDR/SYSMON-SPECIFIC DETECTIONS WITH CONTEXT-AWARE SCORING =====
    # EDR logs get context-aware detection (role + destination + behavioral analysis)
    alerts.extend(_detect_edr_anomalies(df, baselines_dir))

    # ===== ROUTER/NETWORK INFRASTRUCTURE DETECTIONS =====
    # Router logs get Cisco IOS pattern-based detection (BGP, OSPF, Interface, Config)
    alerts.extend(_detect_router_anomalies(df))

    # ===== WINDOWS-SPECIFIC ATTACK DETECTIONS =====
    # Windows Security & Sysmon logs - LSASS dumping and privilege escalation
    alerts.extend(_detect_windows_lsass_dumping(df))
    alerts.extend(_detect_windows_privilege_escalation(df))

    # ===== SECTION 0: ENHANCED DETECTION FOR MIXED LOGS =====

    
    # 0A) Credential Brute Force Detection - detect rapid login attempts (SSH, RDP, Windows Logon, etc.)
    if "action" in df.columns and "status" in df.columns and "username" in df.columns:
        try:
            # Helper function to check if IP is external (not RFC1918 private)
            def is_external_ip(ip_str: str) -> bool:
                """Check if IP is external (public) IP address."""
                try:
                    import ipaddress
                    ip = ipaddress.ip_address(ip_str)
                    # Check if IP is in private ranges (RFC1918)
                    return not ip.is_private
                except Exception:
                    return False
            
            login_logs = df[df.get("program", pd.Series(index=df.index)).astype(str).str.contains("sshd", case=False, na=False) |
                         df.get("action", pd.Series(index=df.index)).astype(str).str.contains("login|logon", case=False, na=False)]
            if not login_logs.empty:
                # Group by source IP and count failures/attempts
                for src_ip, group in login_logs.groupby("source_ip"):
                    if pd.isna(src_ip) or str(src_ip).strip() == "":
                        continue
                    src_ip = str(src_ip)
                    
                    # Count failed logins
                    failed = group[group["status"].astype(str).str.lower().str.contains("fail|denied", na=False)]
                    total = len(group)
                    
                    if total >= 5 and len(failed) >= 3:  # at least 3 failures in 5+ attempts
                        failure_rate = len(failed) / total
                        if failure_rate >= 0.4:  # 40%+ failure rate
                            # Check if IP is external (public)
                            is_external = is_external_ip(src_ip)
                            
                            # Calculate base score
                            base_score = min(failure_rate * 10, 10.0)
                            
                            # BOOST SEVERITY FOR EXTERNAL IPs
                            # External brute force is almost always malicious, not misconfiguration
                            if is_external and failure_rate >= 0.9:
                                # Override Option C capping for high-confidence external attacks
                                score = max(base_score, 9.0)
                                severity = "CRITICAL"
                                reason = f"High login failure rate from EXTERNAL IP {src_ip} (likely attack)"
                            elif failure_rate >= 0.8:
                                # >= 80% failure rate is almost certainly brute force attack
                                score = max(base_score, 9.0)
                                severity = "CRITICAL"
                                reason = f"High login failure rate from {'EXTERNAL' if is_external else 'internal'} IP {src_ip} (brute force attack)"
                            elif failure_rate > 0.5:
                                score = base_score
                                severity = "WARNING"
                                reason = f"Elevated login failure rate from {'EXTERNAL' if is_external else 'internal'} IP {src_ip}"
                            else:
                                score = base_score
                                severity = "WARNING"
                                reason = f"High login failure rate from {src_ip}"
                            
                            ctx = {
                                "user": None,
                                "group": None,
                                "behavior": {
                                    "type": "credential_bruteforce", 
                                    "source_ip": src_ip, 
                                    "attempts": total, 
                                    "failures": len(failed),
                                    "is_external": is_external
                                },
                                "time": None,
                                "baseline": {"expected_failure_rate": 0.1},
                                "extras": {"reason": reason},
                            }
                            alerts.append({
                                "type": "credential_bruteforce_detected",
                                "subject": src_ip,
                                "severity": severity,
                                "score": float(score),
                                "text": f"Credential brute force detected from {'EXTERNAL' if is_external else 'internal'} IP {src_ip}: {len(failed)}/{total} failed attempts ({failure_rate:.1%} failure rate).",
                                "evidence": {
                                    "source_ip": src_ip, 
                                    "total_attempts": int(total), 
                                    "failed_attempts": int(len(failed)), 
                                    "failure_rate": float(failure_rate),
                                    "is_external_ip": is_external
                                },
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
                            
                            # Classify destination IP as EXTERNAL or INTERNAL
                            ip_label, is_external = _classify_ip(dest_ip)
                            mb_transferred = bytes_val / 1_000_000
                            
                            # Calculate score - boost for external destinations
                            base_score = (bytes_val / 100_000_000) * 9.5
                            if is_external:
                                base_score = max(base_score, 9.0)  # Minimum 9.0 for external
                            final_score = min(base_score, 10.0)
                            
                            ctx = {
                                "user": username,
                                "group": None,
                                "behavior": {
                                    "type": "data_exfiltration", 
                                    "bytes": bytes_val, 
                                    "destination": dest_ip,
                                    "destination_type": ip_label,
                                    "is_external": is_external
                                },
                                "time": _fmt_local_vn(timestamp),
                                "baseline": {"max_normal_transfer": "50MB"},
                                "extras": {"reason": f"Large SCP transfer detected: {mb_transferred:.1f}MB to {ip_label} IP {dest_ip}"},
                            }
                            alerts.append({
                                "type": "data_exfiltration_detected",
                                "subject": username,
                                "severity": "CRITICAL",
                                "score": final_score,
                                "text": f"🚨 [CRITICAL] DATA EXFILTRATION: User '{username}' transferred {mb_transferred:.1f}MB to {ip_label} IP {dest_ip}",
                                "evidence": {
                                    "user": username, 
                                    "bytes": int(bytes_val), 
                                    "destination": dest_ip, 
                                    "destination_type": ip_label,
                                    "is_external_destination": is_external,
                                    "method": "scp", 
                                    "hostname": hostname
                                },
                                "prompt_ctx": ctx,
                            })
                
                # Pattern 2: NETFILTER_PKT for large network transfers
                netfilter_match = re.search(r'NETFILTER_PKT\s+len=(\d+)\s+dst=([0-9\.]+)', msg)
                if netfilter_match:
                    bytes_val = int(netfilter_match.group(1))
                    dest_ip = netfilter_match.group(2)
                    # Flag if > 50MB
                    if bytes_val > 50_000_000:
                        # Try to get username, fallback to source_ip with clear labeling
                        username = str(row.get("username", "")).strip()
                        source_ip = str(row.get("source_ip", "")).strip()
                        
                        # Handle None/unknown user - show source IP for investigation
                        if not username or username in ["(unknown)", "nan", "", "None"]:
                            if source_ip and source_ip not in ["", "nan"]:
                                # Clear labeling: "Unknown User (Source IP: x.x.x.x)"
                                display_name = f"Unknown User (Source IP: {source_ip})"
                            else:
                                display_name = f"Unknown User (Host: {hostname})" if hostname else "Unknown User"
                        else:
                            display_name = username
                        
                        # Classify destination IP as EXTERNAL or INTERNAL
                        ip_label, is_external = _classify_ip(dest_ip)
                        mb_transferred = bytes_val / 1_000_000
                        
                        # Calculate score - boost for external destinations
                        base_score = (bytes_val / 100_000_000) * 9.0
                        if is_external:
                            base_score = max(base_score, 9.0)  # Minimum 9.0 for external
                        final_score = min(base_score, 10.0)
                        
                        key = (display_name, "netfilter", bytes_val, dest_ip)
                        if key not in detected_transfers:
                            detected_transfers[key] = True
                            
                            ctx = {
                                "user": display_name,
                                "group": None,
                                "behavior": {
                                    "type": "data_exfiltration", 
                                    "bytes": bytes_val, 
                                    "destination": dest_ip,
                                    "destination_type": ip_label,
                                    "is_external": is_external,
                                    "source_ip": source_ip if source_ip else None
                                },
                                "time": _fmt_local_vn(timestamp),
                                "baseline": {"max_normal_transfer": "50MB"},
                                "extras": {"reason": f"Large network transfer detected: {mb_transferred:.1f}MB to {ip_label} IP {dest_ip}"},
                            }
                            alerts.append({
                                "type": "data_exfiltration_detected",
                                "subject": display_name,  # USER-CENTRIC with clear "Unknown User" labeling
                                "severity": "CRITICAL",
                                "score": final_score,
                                "text": f"🚨 [CRITICAL] DATA EXFILTRATION: '{display_name}' transferred {mb_transferred:.1f}MB to {ip_label} IP {dest_ip}",
                                "evidence": {
                                    "user": display_name, 
                                    "bytes": int(bytes_val), 
                                    "destination": dest_ip, 
                                    "destination_type": ip_label,
                                    "is_external_destination": is_external,
                                    "source_ip": source_ip if source_ip else None,
                                    "source_host": hostname, 
                                    "method": "network"
                                },
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
                raw_username = row.get("username", "")
                username = str(raw_username).strip() if raw_username else ""
                
                # Handle None/empty/unknown username - provide context from hostname or source_ip
                if not username or username in ["(unknown)", "nan", "", "None", "none"]:
                    hostname = str(row.get("host", "")).strip()
                    source_ip = str(row.get("source_ip", "")).strip()
                    if source_ip and source_ip not in ["", "nan", "None"]:
                        display_name = f"Unknown User (Source IP: {source_ip})"
                    elif hostname and hostname not in ["", "nan", "None"]:
                        display_name = f"Unknown User (Host: {hostname})"
                    else:
                        display_name = "Unknown User"
                else:
                    display_name = username
                
                timestamp = row.get("timestamp")
                
                for pattern, pattern_name, score in priv_escalation_patterns:
                    if re.search(pattern, msg, re.IGNORECASE):
                        key = (display_name, pattern_name)
                        if key in detected_privesc:
                            continue
                        detected_privesc[key] = True
                        
                        ctx = {
                            "user": display_name,
                            "group": None,
                            "behavior": {"type": "privilege_escalation", "method": pattern_name},
                            "time": _fmt_local_vn(timestamp),
                            "baseline": {},
                            "extras": {"reason": f"Privilege escalation attempt detected"},
                        }
                        alerts.append({
                            "type": "privilege_escalation_detected",
                            "subject": display_name,
                            "severity": "CRITICAL",
                            "score": score,
                            "text": f"🚨 Privilege escalation by {display_name}: {msg[:200]}",
                            "evidence": {"method": pattern_name, "message": msg[:300], "original_user": username if username else "None"},
                            "prompt_ctx": ctx,
                        })
        except Exception:
            pass
    
    # 0E) Sensitive Database Access Detection - detect queries to sensitive tables
    if "message" in df.columns:
        try:
            # Sensitive database access patterns
            sensitive_db_patterns = [
                {
                    "pattern": r"COPY\s+(salary|payroll|employee|customers?|credit_card|ssn|password)\s+TO",
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "name": "data_export",
                    "description": "Data export via COPY command - extracting sensitive table data"
                },
                {
                    "pattern": r"SELECT\s+\*\s+FROM\s+(salary|payroll)\s+WHERE",
                    "severity": "CRITICAL",
                    "score": 8.5,
                    "name": "salary_query",
                    "description": "Query to salary/payroll table - potential data theft"
                },
                {
                    "pattern": r"SELECT\s+\*\s+FROM\s+employee[s]?\s+PII|SELECT.*FROM.*(pii|ssn|credit_card)",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "name": "pii_query",
                    "description": "Query to PII data - accessing personally identifiable information"
                },
                {
                    "pattern": r"(mysqldump|pg_dump)\s+.*--password|--all-databases",
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "name": "database_dump",
                    "description": "Database dump - potential data exfiltration"
                },
            ]
            
            detected_db_access = {}  # (username, pattern_name, host) -> bool to avoid duplicates
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", ""))
                raw_username = row.get("username", "")
                username = str(raw_username).strip() if raw_username else ""
                timestamp = row.get("timestamp")
                host = str(row.get("host", "")).strip()
                
                # Extract username from postgres log format: [local] user@database LOG:
                postgres_match = re.search(r"\[local\]\s+(\w+)@(\w+)\s+LOG:", msg)
                if postgres_match:
                    username = postgres_match.group(1)
                    database = postgres_match.group(2)
                else:
                    database = "unknown"
                
                # Handle None/empty username
                if not username or username in ["(unknown)", "nan", "", "None", "none"]:
                    if host and host not in ["", "nan", "None"]:
                        display_name = f"Unknown User (Host: {host})"
                    else:
                        display_name = "Unknown User"
                else:
                    display_name = username
                
                for pattern_info in sensitive_db_patterns:
                    if re.search(pattern_info["pattern"], msg, re.IGNORECASE):
                        key = (display_name, pattern_info["name"], host)
                        if key in detected_db_access:
                            # Increment count
                            detected_db_access[key]["count"] += 1
                            continue
                        
                        detected_db_access[key] = {
                            "count": 1,
                            "display_name": display_name,
                            "pattern_info": pattern_info,
                            "database": database,
                            "host": host,
                            "timestamp": timestamp,
                            "sample_query": msg[:300],
                        }
            
            # Generate alerts for detected sensitive DB access
            for key, data in detected_db_access.items():
                pattern_info = data["pattern_info"]
                ctx = {
                    "user": data["display_name"],
                    "group": None,
                    "behavior": {"type": "sensitive_db_access", "method": pattern_info["name"]},
                    "time": _fmt_local_vn(data["timestamp"]),
                    "baseline": {},
                    "extras": {
                        "database": data["database"],
                        "host": data["host"],
                        "query_count": data["count"],
                    },
                }
                
                alerts.append({
                    "type": "sensitive_db_access_detected",
                    "subject": data["display_name"],
                    "severity": pattern_info["severity"],
                    "score": pattern_info["score"],
                    "text": f"🚨 SENSITIVE DATABASE ACCESS: User '{data['display_name']}' performed {data['count']}x {pattern_info['name']} on {data['database']}@{data['host']}. {pattern_info['description']}",
                    "evidence": {
                        "method": pattern_info["name"],
                        "database": data["database"],
                        "host": data["host"],
                        "query_count": data["count"],
                        "sample_query": data["sample_query"],
                    },
                    "prompt_ctx": ctx,
                })
        except Exception:
            pass
    
    # 0F) Service Manipulation Detection - detect suspicious service stop/restart
    if "message" in df.columns:
        try:
            # Service manipulation patterns - stopping critical services
            service_manipulation_patterns = [
                {
                    "pattern": r"Stopping\s+auditd\s+service|auditd\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "name": "auditd_stop",
                    "description": "🚨 DEFENSE EVASION: Stopping auditd service - disabling security logging"
                },
                {
                    "pattern": r"Stopping\s+postgresql\s+service|postgresql\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "name": "postgresql_stop",
                    "description": "Database service shutdown - potential data attack or denial of service"
                },
                {
                    "pattern": r"Stopping\s+mysql\s+service|mysql\.service:\s*Deactivated|mariadb\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "name": "mysql_stop",
                    "description": "Database service shutdown - potential data attack or denial of service"
                },
                {
                    "pattern": r"Stopping\s+nginx\s+service|nginx\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 8.5,
                    "name": "nginx_stop",
                    "description": "Web server shutdown - service disruption or pre-attack preparation"
                },
                {
                    "pattern": r"Stopping\s+apache2?\s+service|apache2?\.service:\s*Deactivated|httpd\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 8.5,
                    "name": "apache_stop",
                    "description": "Web server shutdown - service disruption or pre-attack preparation"
                },
                {
                    "pattern": r"Stopping\s+ssh\s+service|ssh\.service:\s*Deactivated|sshd\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 9.0,
                    "name": "ssh_stop",
                    "description": "SSH service shutdown - denying remote access or hiding activity"
                },
                {
                    "pattern": r"Stopping\s+firewalld\s+service|firewalld\.service:\s*Deactivated|ufw\.service:\s*Deactivated",
                    "severity": "CRITICAL",
                    "score": 9.5,
                    "name": "firewall_stop",
                    "description": "🚨 DEFENSE EVASION: Firewall shutdown - disabling network security"
                },
            ]
            
            detected_service_manipulations = {}  # (username, pattern_name, host) -> data
            
            for idx, row in df.iterrows():
                msg = str(row.get("message", ""))
                raw_username = row.get("username", "")
                username = str(raw_username).strip() if raw_username else ""
                timestamp = row.get("timestamp")
                host = str(row.get("host", "")).strip()
                
                # Extract username from "requested by user" pattern
                requested_by_match = re.search(r"\(requested\s+by\s+(\w+)\)", msg)
                if requested_by_match:
                    username = requested_by_match.group(1)
                
                # Handle None/empty username
                if not username or username in ["(unknown)", "nan", "", "None", "none"]:
                    if host and host not in ["", "nan", "None"]:
                        display_name = f"Unknown User (Host: {host})"
                    else:
                        display_name = "Unknown User"
                else:
                    display_name = username
                
                for pattern_info in service_manipulation_patterns:
                    if re.search(pattern_info["pattern"], msg, re.IGNORECASE):
                        key = (display_name, pattern_info["name"], host)
                        if key in detected_service_manipulations:
                            detected_service_manipulations[key]["count"] += 1
                            continue
                        
                        detected_service_manipulations[key] = {
                            "count": 1,
                            "display_name": display_name,
                            "pattern_info": pattern_info,
                            "host": host,
                            "timestamp": timestamp,
                            "sample_message": msg[:300],
                        }
            
            # Generate alerts for detected service manipulations
            for key, data in detected_service_manipulations.items():
                pattern_info = data["pattern_info"]
                is_defense_evasion = pattern_info["name"] in ["auditd_stop", "firewall_stop"]
                
                ctx = {
                    "user": data["display_name"],
                    "group": None,
                    "behavior": {
                        "type": "service_manipulation",
                        "method": pattern_info["name"],
                        "defense_evasion": is_defense_evasion,
                    },
                    "time": _fmt_local_vn(data["timestamp"]),
                    "baseline": {},
                    "extras": {
                        "host": data["host"],
                        "stop_count": data["count"],
                    },
                }
                
                alerts.append({
                    "type": "service_manipulation_detected",
                    "subject": data["display_name"],
                    "severity": pattern_info["severity"],
                    "score": pattern_info["score"],
                    "text": f"🚨 SERVICE MANIPULATION: User '{data['display_name']}' stopped {pattern_info['name'].replace('_stop', '')} {data['count']}x on {data['host']}. {pattern_info['description']}",
                    "evidence": {
                        "method": pattern_info["name"],
                        "host": data["host"],
                        "stop_count": data["count"],
                        "sample_message": data["sample_message"],
                        "defense_evasion": is_defense_evasion,
                    },
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
    # SKIP FOR DHCP: DHCP logs only have IP allocation, not user login/download events
    if not is_dhcp:
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
                            
                            # Use unified scoring system for severity mapping
                            if has_variance:
                                raw_score = float(z)
                            else:
                                # If no variance, use ratio-based score
                                ratio = (cur / (mu or 1)) if (mu or 0) > 0 else 1
                                raw_score = min(ratio * 2, 10.0)  # Cap at 10
                            
                            # Map score to severity using unified thresholds
                            severity = scoring.get_severity(raw_score)
                            
                            alerts.append({
                                "type": f"user_{val_col}_spike",
                                "subject": u,
                                "severity": severity,
                                "score": raw_score,
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
                            
                            # Use username as subject if available, otherwise fall back to IP/entity
                            subject_name = str(username[0]) if len(username) > 0 and str(username[0]).strip() not in ["(unknown)", "nan", ""] else entity
                            
                            alerts.append({
                                "type": "blocked_actions_spike",
                                "subject": subject_name,  # Use username (e.g., 'quangdev') instead of IP when available
                                "severity": "CRITICAL" if blocked_ratio > 0.8 else "WARNING",
                                "score": min(blocked_ratio * 10, 10.0),
                                "text": f"Phát hiện {blocked_count}/{total_count} hành động bị chặn ({blocked_ratio:.1%}) từ {subject_name} (source_ip={entity}). {f'Chi tiết: {context_info}' if context_info else ''} Điều này có thể cho thấy cuộc tấn công hoặc cấu hình sai.",
                                "evidence": {"blocked_count": int(blocked_count), "total_count": int(total_count), "ratio": float(blocked_ratio), "source_ip": entity, "username": subject_name, "context": context_info},
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
                        # Calculate score first, then derive severity from score
                        off_hours_score = 4.0 + min(len(u_outside) * 0.1, 2.0)
                        alerts.append({
                            "type": "off_hours_access",
                            "subject": u,
                            "severity": scoring.get_severity(off_hours_score),  # Use unified scoring
                            "score": off_hours_score,
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
    
    # DISABLED: Network link flap is infrastructure noise, not user behavior
    # For UEBA (User Entity Behavior Analytics), focus on user actions only
    # network_alerts = _detect_network_link_flap(df)
    # alerts.extend(network_alerts)
    
    # NEW: Cron job overlap detection (same script running multiple times)
    cron_alerts = _detect_cron_job_overlap(df)
    alerts.extend(cron_alerts)
    
    # NEW: SSH successful login burst detection (potential lateral movement)
    ssh_burst_alerts = _detect_ssh_login_burst(df)
    alerts.extend(ssh_burst_alerts)
    
    # NEW: Privilege escalation detection (non-admin users running privileged operations)
    priv_esc_alerts = _detect_privilege_escalation(df)
    alerts.extend(priv_esc_alerts)

    # NEW: Windows-specific attack detection (when Windows Event Log format detected)
    # Check for Windows log indicators: EventID column, Security/Sysmon Channel
    has_windows_logs = False
    for col in ["EventID", "event_id"]:
        if col in df.columns:
            has_windows_logs = True
            break
    
    if has_windows_logs:
        # LSASS credential dumping detection (Mimikatz, credential theft)
        lsass_alerts = _detect_windows_lsass_dumping(df)
        alerts.extend(lsass_alerts)
        
        # Windows privilege escalation (psexec, encoded PowerShell)
        win_priv_esc_alerts = _detect_windows_privilege_escalation(df)
        alerts.extend(win_priv_esc_alerts)
        
        # Scheduled task persistence detection
        schtask_alerts = _detect_windows_schtask_persistence(df)
        alerts.extend(schtask_alerts)
        
        # Service persistence detection (malicious services installed)
        svc_persist_alerts = _detect_windows_service_persistence(df)
        alerts.extend(svc_persist_alerts)

    # =========================================================================
    # ATTACK CHAIN CORRELATION (Step 5 improvement)
    # Detect organized attacks: users with BOTH lateral movement AND exfiltration
    # =========================================================================
    alerts = _detect_attack_chain_correlation(alerts)

    return alerts


def _detect_attack_chain_correlation(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlate lateral movement + exfiltration to detect organized attacks.
    
    Creates summary alerts for users who show BOTH:
    - ssh_lateral_movement (logging in from multiple IPs)
    - data_exfiltration_detected (transferring large amounts of data)
    
    This pattern indicates a coordinated attack with compromised credentials.
    """
    if not alerts:
        return alerts
    
    try:
        # Group alerts by subject (user)
        user_alerts = {}
        for alert in alerts:
            user = alert.get("subject", "")
            if not user or user == "(unknown)":
                continue
            if user not in user_alerts:
                user_alerts[user] = []
            user_alerts[user].append(alert)
        
        # Find users with BOTH lateral movement AND exfiltration
        chain_alerts = []
        correlated_users = []
        
        for user, user_alert_list in user_alerts.items():
            alert_types = set(a.get("type") for a in user_alert_list)
            has_lateral = "ssh_lateral_movement" in alert_types
            has_exfil = "data_exfiltration_detected" in alert_types
            
            if has_lateral and has_exfil:
                correlated_users.append(user)
                
                # Calculate total exfiltrated bytes
                exfil_alerts = [a for a in user_alert_list if a["type"] == "data_exfiltration_detected"]
                total_bytes = sum(a.get("evidence", {}).get("bytes", 0) for a in exfil_alerts)
                dest_ips = set()
                external_count = 0
                for a in exfil_alerts:
                    dest = a.get("evidence", {}).get("destination", "")
                    if dest:
                        dest_ips.add(dest)
                    if a.get("evidence", {}).get("is_external_destination", False):
                        external_count += 1
                
                # Get lateral movement details
                lateral_alerts = [a for a in user_alert_list if a["type"] == "ssh_lateral_movement"]
                source_ips = set()
                for a in lateral_alerts:
                    ips = a.get("evidence", {}).get("source_ips", [])
                    source_ips.update(ips)
                
                mb_total = total_bytes / 1_000_000
                
                chain_alerts.append({
                    "type": "organized_attack_chain",
                    "subject": user,
                    "severity": "CRITICAL",
                    "score": 10.0,  # Maximum severity - organized attack
                    "text": f"🚨 PHÁT HIỆN TẤN CÔNG CÓ TỔ CHỨC: User '{user}' thực hiện Lateral Movement (từ {len(source_ips)} IPs) → Exfiltration ({mb_total:.1f}MB đến {len(dest_ips)} IP đích, {external_count} external).",
                    "evidence": {
                        "attack_phases": ["lateral_movement", "data_exfiltration"],
                        "total_bytes_exfiltrated": int(total_bytes),
                        "total_mb_exfiltrated": round(mb_total, 1),
                        "destination_ips": list(dest_ips),
                        "external_destination_count": external_count,
                        "source_login_ips": list(source_ips),
                        "exfiltration_alert_count": len(exfil_alerts),
                        "lateral_movement_alert_count": len(lateral_alerts),
                    },
                    "prompt_ctx": {
                        "user": user,
                        "behavior": {
                            "type": "organized_attack_chain",
                            "summary": "Các tài khoản bị chiếm đoạt thực hiện di chuyển ngang (Lateral Movement) để gom dữ liệu, sau đó đồng loạt gửi dữ liệu ra ngoài (Exfiltration) tới cùng một nhóm IP đích trong khoảng thời gian ngắn. Đây là dấu hiệu rõ ràng của cuộc tấn công có tổ chức."
                        }
                    }
                })
        
        # Add summary alert if multiple users are correlated
        if len(correlated_users) >= 2:
            chain_alerts.append({
                "type": "coordinated_attack_summary",
                "subject": f"{len(correlated_users)} users",
                "severity": "CRITICAL",
                "score": 10.0,
                "text": f"🚨🚨 CẢNH BÁO TẤN CÔNG PHỐI HỢP: {len(correlated_users)} tài khoản ({', '.join(correlated_users[:5])}{' và khác...' if len(correlated_users) > 5 else ''}) đều thể hiện chuỗi hành vi Lateral Movement → Data Exfiltration. Đây là dấu hiệu của cuộc tấn công có tổ chức quy mô lớn.",
                "evidence": {
                    "attack_type": "coordinated_multi_user_attack",
                    "affected_users": correlated_users,
                    "affected_user_count": len(correlated_users),
                },
                "prompt_ctx": {
                    "behavior": {
                        "type": "coordinated_attack",
                        "summary": f"Phát hiện {len(correlated_users)} người dùng cùng thực hiện chuỗi tấn công tương tự, cho thấy đây là cuộc tấn công có chủ đích và phối hợp."
                    }
                }
            })
        
        return alerts + chain_alerts
    
    except Exception as e:
        import sys
        print(f"[DEBUG] Attack chain correlation error: {e}", file=sys.stderr)
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


