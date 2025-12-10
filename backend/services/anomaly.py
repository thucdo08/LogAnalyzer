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
        # High volume of blocked connections indicates DoS attempt or scanning
        # Check BOTH status AND action columns for blocked/denied patterns
        blocked_df = pd.DataFrame()
        
        if "status" in df.columns:
            status_blocked = df[df["status"].astype(str).str.lower().isin(["blocked", "denied", "drop", "deny"])].copy()
            blocked_df = pd.concat([blocked_df, status_blocked], ignore_index=True)
        
        if "action" in df.columns:
            action_blocked = df[df["action"].astype(str).str.upper().isin(["DENY", "BLOCK", "DROP", "BLOCKED", "DENIED"])].copy()
            blocked_df = pd.concat([blocked_df, action_blocked], ignore_index=True)
        
        # Remove duplicates if any
        if not blocked_df.empty and "source_ip" in blocked_df.columns:
            blocked_df = blocked_df.drop_duplicates()
            
            if len(blocked_df) >= 10:  # Minimum threshold
                # Group by source IP
                for src_ip, group in blocked_df.groupby("source_ip"):
                    blocked_count = len(group)
                    
                    if blocked_count >= 20:  # High threshold for burst
                        # Get unique destinations
                        dest_ips = group["dest_ip"].dropna().unique() if "dest_ip" in group.columns else []
                        
                        # Resolve IP to username
                        username = get_user_from_ip(src_ip)
                        
                        # Use unified scoring
                        score_data = scoring.get_alert_metadata("firewall_deny_burst", [])
                        
                        alerts.append({
                            "type": "firewall_deny_burst",
                            "subject": username,  # Real user, not "Firewall Security"
                            "severity": score_data["severity"],
                            "score": score_data["score"],
                            "text": f"Firewall DENY/BLOCK burst detected: {blocked_count} blocked connections from {username} (IP: {src_ip}) to {len(dest_ips)} destination(s).",
                            "evidence": {
                                "source_ip": str(src_ip),
                                "username": username,
                                "blocked_count": int(blocked_count),
                                "destinations": [str(d) for d in dest_ips[:10]],
                                "dest_count": int(len(dest_ips)),
                            },
                            "prompt_ctx": {
                                "user": username,
                                "group": None,
                                "behavior": {"type": "deny_burst", "count": blocked_count},
                                "time": None,
                                "baseline": {"expected_denies": 5},
                                "extras": {"reason": "High volume of blocked connections may indicate DoS or scanning"},
                            },
                        })
        
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
            if row.get("status") == "nxdomain":
                user_activities[username]["nxdomain_queries"].append({
                    "domain": row.get("domain"),
                    "timestamp": str(row.get("timestamp", ""))
                })
            
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
            
            alerts.append({
                "type": "network_link_flap",
                "subject": "Network Infrastructure",
                "severity": "CRITICAL" if unique_servers >= 15 else "WARNING",
                "score": min(8.0 + (unique_servers / 10), 10.0),
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
                alert_text = f"Cron job overlap: script '{script}' executed {execution_count} times by {unique_users} users"
                alerts.append({
                    "type": "cron_job_overlap",
                    "subject": str(host),
                    "severity": "WARNING",
                    "score": min(5.0 + (execution_count / 10), 8.0),
                    "text": alert_text,
                    "evidence": {"script": str(script), "execution_count": int(execution_count), "unique_users": int(unique_users), "users": [str(u) for u in users_list]},
                    "prompt_ctx": {"behavior": {"type": "cron_job_overlap"}},
                })
    except Exception as e:
        import sys
        print(f"[DEBUG] Cron overlap error: {e}", file=sys.stderr)
    return alerts

def _detect_ssh_login_burst(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Detect SSH successful login bursts (potential lateral movement)."""
    alerts = []
    if "message" not in df.columns or "program" not in df.columns:
        return alerts
    try:
        ssh_logs = df[df["program"].astype(str).str.contains(r"sshd\[", case=False, na=False)].copy()
        if len(ssh_logs) == 0:
            return alerts
        successful_logins = ssh_logs[ssh_logs["message"].astype(str).str.contains(r"Accepted publickey", case=False, na=False)]
        if len(successful_logins) == 0:
            return alerts
        login_count = len(successful_logins)
        if login_count >= 30:
            unique_hosts = successful_logins["host"].nunique() if "host" in successful_logins.columns else 0
            affected_hosts = successful_logins["host"].unique().tolist()[:5] if "host" in successful_logins.columns else []
            alert_text = f"SSH login burst: {login_count} successful logins to {unique_hosts} servers"
            subject = f"CI/CD Infrastructure ({', '.join([str(h) for h in affected_hosts[:3]])})"
            alerts.append({
                "type": "ssh_login_burst",
                "subject": subject,
                "severity": "WARNING",
                "score": min(5.0 + (login_count / 30), 8.0),
                "text": alert_text,
                "evidence": {"login_count": int(login_count), "unique_hosts": int(unique_hosts), "affected_hosts": [str(h) for h in affected_hosts]},
                "prompt_ctx": {"behavior": {"type": "ssh_login_burst"}},
            })
    except Exception as e:
        import sys
        print(f"[DEBUG] SSH burst error: {e}", file=sys.stderr)
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
    
    # NEW: Network link flap detection (kernel Link Up events on multiple servers)
    network_alerts = _detect_network_link_flap(df)
    alerts.extend(network_alerts)
    
    # NEW: Cron job overlap detection (same script running multiple times)
    cron_alerts = _detect_cron_job_overlap(df)
    alerts.extend(cron_alerts)
    
    # NEW: SSH successful login burst detection (potential lateral movement)
    ssh_burst_alerts = _detect_ssh_login_burst(df)
    alerts.extend(ssh_burst_alerts)

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


