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
                                "evidence": {"source_ip": src_ip, "total_attempts": total, "failed_attempts": len(failed), "failure_rate": failure_rate},
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
                                "evidence": {"user": username, "bytes": bytes_val, "destination": dest_ip, "method": "scp", "hostname": hostname},
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
                                "evidence": {"bytes": bytes_val, "destination": dest_ip, "source_host": hostname, "method": "network"},
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
                                "db_queries": current_queries,
                                "db_queries_baseline": db_queries_mean,
                                "suspicious_ops": current_suspicious,
                                "suspicious_ops_baseline": suspicious_ops_mean,
                                "z_queries": z_queries,
                                "z_suspicious": z_suspicious,
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
                    "evidence": {"events": user_events},
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
                                "evidence": {"failures": len(auth_failures), "total_requests": total_requests, "failure_rate": failure_rate},
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
                                "behavior": {"type": "blocked_actions_spike", "ratio": blocked_ratio, "count": blocked_count, "source": entity},
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
                                "evidence": {"blocked_count": blocked_count, "total_count": total_count, "ratio": float(blocked_ratio), "source": entity, "context": context_info},
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
                            "behavior": {"type": "blocked_actions_spike", "ratio": blocked_ratio, "count": blocked_count},
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
                            "evidence": {"blocked_count": blocked_count, "total_count": total_count, "ratio": float(blocked_ratio)},
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
                        "evidence": {"countries": list(countries), "events": len(u_foreign)},
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
                            "evidence": {"hours": sorted([int(h) for h in hours]), "events": len(u_outside)},
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


