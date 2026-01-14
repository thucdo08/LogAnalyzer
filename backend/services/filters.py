# backend/services/filters.py
import re
import pandas as pd
import numpy as np

# Các mẫu log "bình thường" sẽ được giảm nhiễu
NOISE_PATTERNS = [
    # Generic session lifecycle (Linux)
    r"session opened for user",
    r"session closed for user",
    r"connection from",

    # SSH patterns - REMOVED FROM NOISE (critical for lateral movement detection!)
    # r"accepted publickey for",  # REMOVED - SSH logins are security events
    # r"accepted password for",   # REMOVED - SSH logins are security events
    r"disconnected from",
    r"received disconnect",
    r"pam_unix.*session (opened|closed)",

    # systemd chatter
    r"systemd.* (starting|started|stopping|stopped|reached target|created slice)",

    # Cron routine commands
    r"cron\[\d+\]: \(.*\) CMD \(.*\)",

    # OpenSSH variants - ONLY disconnect/close patterns, NOT login patterns
    # r"sshd: Accepted (publickey|password) for ",  # REMOVED - critical ssh logins
    r"sshd: Disconnected from( user)? ",
    r"sshd: Received disconnect from ",
    r"sshd: Connection closed by ",
    r"OpenSSH_\S+ .* protocol",

    # Windows benign chatter (keep minimal relevant)
    r"service entered the (running|stopped) state",
    r"service was successfully sent a (start|stop) control",
    r"task scheduler.* (started|completed) task",
    r"windows defender.* (started|completed|updated)",
    r"group policy successfully processed",

    # Windows Security Events (success, to be sampled)
    r"Event ID.*4624",
]

# Regex bắt IP (IPv4)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def _is_private_ipv4(ip: str) -> bool:
    if not isinstance(ip, str) or not ip:
        return False
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
    except Exception:
        return False
    return False

_STATIC_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf")

def _match_noise_fields(row: pd.Series) -> str | None:
    """Field-aware noise tagging per log type.
    Returns a stable noise_key or None.
    """
    try:
        program = str(row.get("program") or "").lower()
        action = str(row.get("action") or "").lower()
        status = str(row.get("status") or "").lower()
        message = str(row.get("message") or "")
        # Common fields
        source_ip = row.get("source_ip") or row.get("src_ip")
        dest_ip = row.get("dest_ip") or row.get("dst_ip")
        src_port = row.get("src_port")
        dst_port = row.get("dest_port") or row.get("dst_port")

        # 2.2 Web/App servers (Apache/Nginx/IIS) - Enhanced for attack detection
        if program in ("apache", "nginx", "iis") or ("http_status" in row.index) or ("user_agent" in row.index):
            http_status = None
            try:
                http_status = int(row.get("http_status")) if row.get("http_status") not in (None, "") else None
            except Exception:
                http_status = None
            path = str(row.get("path") or row.get("url") or "")
            ua = str(row.get("user_agent") or row.get("user") or "")
            
            # Check for known attack types
            attack_type = row.get("attack_type")
            if attack_type:
                return None  # Don't mark attacks as noise, let them through
            
            if path:
                lp = path.lower()
                # Skip static files (benign noise)
                if lp.endswith(_STATIC_EXTENSIONS) or lp == "/favicon.ico":
                    if http_status in (200, 204, 206, 301, 302, 304) or http_status is None:
                        return "web_static_success"
            
            if ua:
                ua_l = ua.lower()
                if "elb-healthchecker" in ua_l or "kube-probe" in ua_l or "healthcheck" in ua_l:
                    return "web_healthcheck"
                if "googlebot" in ua_l or "bingbot" in ua_l:
                    return "web_known_bot"
            
            # Skip success responses to normal paths
            if http_status in (200, 204, 206) and path and not any(bad in path.lower() for bad in ("admin", "export", "phpmyadmin", "wp-admin")):
                return "web_normal_access"

        # 2.1 Firewall / NGFW / IDS/IPS
        if program in ("firewall", "iptables", "netfilter") or ("kernel" in program and "in=" in message.lower()):
            # Allow internal->internal on standard ports
            if action in ("accept", "allow", "passed") or ("ACCEPT" in message):
                std_ports = {53, 80, 443, 123}
                if _is_private_ipv4(str(source_ip)) and _is_private_ipv4(str(dest_ip)):
                    try:
                        dp = int(dst_port) if dst_port not in (None, "") else None
                    except Exception:
                        dp = None
                    if dp in std_ports:
                        return "fw_allow_internal_std"
            # Broadcast/multicast well-known services
            lower_msg = message.lower()
            if any(pat in lower_msg for pat in (" mdns ", " 5353 ", " ssdp ", " 1900 ", " ntp ", " 123 ", " dhcp ", " 67 ", " 68 ")):
                return "fw_infra_broadcast"

        # 2.6 Syslog (Linux/Unix system logs) - Enhanced for security
        if program in ("sshd", "sudo", "cron") or ("facility" in row.index):
            # SSH patterns - NEVER collapse SSH logins (critical for lateral movement detection)
            if "sshd" in program.lower():
                # NEVER collapse successful logins - they are security events for lateral movement
                if "Accepted" in message:
                    return None  # CHANGED: Preserve SSH logins for lateral movement detection
                # Never collapse failed logins - these are security events
                if status == "failed":
                    return None
                # Never collapse connection attempts from unusual patterns
                if any(pat in message.lower() for pat in ("invalid user", "preauth", "timeout")):
                    return None
            
            # Sudo patterns - only collapse normal sudo operations
            if "sudo" in program.lower():
                if action == "sudo" and status == "success":
                    # Collapse normal sudo TTY operations but not others
                    if "TTY=pts/" in message or "TTY=tty" in message:
                        return "sudo_normal_tty"
                # Never collapse privilege escalation or auth failures
                if "session opened" in message.lower():
                    return None  # Important: privilege escalation event
                if "auth failure" in message.lower() or "invalid" in message.lower():
                    return None  # Important: security event
            
            # Cron patterns - collapse routine cron runs
            if "cron" in program.lower():
                if "INFO" in str(row.get("severity", "")) or "(CRON)" in message:
                    if "pidfile" in message.lower() or "@reboot" in message.lower():
                        return "cron_info"
                # Never collapse actual cron command execution - track what runs
                if "CMD (" in message:
                    return None  # Important: cron job execution event

        # 2.1 IDS/IPS (Suricata)
        if program == "suricata" or ("classification" in row.index and pd.notna(row.get("classification"))):
            classification = str(row.get("classification") or "").lower()
            if classification.startswith("potentially bad traffic") or classification.startswith("generic protocol command decode"):
                # often benign low-priority signatures
                return "ids_low_priority"

        # 2.5 Proxy (Squid)
        if program == "squid" or ("hierarchy_code" in row.index):
            result_code = str(row.get("result_code") or "").upper()
            url = str(row.get("url") or "")
            if url:
                lu = url.lower()
                if any(lu.endswith(ext) for ext in _STATIC_EXTENSIONS) or "/favicon.ico" in lu:
                    return "proxy_static"
            if result_code.endswith("/200") and ("HIT" in result_code or "MISS" in result_code):
                return "proxy_ok_cache"

        # 2.1 DHCP chatter - IMPROVED: Only filter DISCOVER/OFFER without user context
        # Keep REQUEST events (security-relevant) and all ACK/RELEASE events
        if program in ("dhcpd", "dhcp") or ("dhcp" in message.lower()):
            # Only filter pure DISCOVER/OFFER without any user information
            if any(tok in message for tok in ("DHCPDISCOVER", "DHCPOFFER")):
                # These are part of normal DHCP handshake - filter as noise
                if "user=" not in message:
                    return "dhcp_chatter"
            # REQUEST events are security-relevant (shows intent) - never filter
            # ACK and RELEASE events are also security-relevant - never filter

        # 2.3 Windows Security – sample 4624
        if "event_id" in row.index and pd.notna(row.get("event_id")):
            try:
                eid = int(row.get("event_id"))
                if eid == 4624:
                    user = str(row.get("username") or "").lower()
                    # service accounts pattern heuristic
                    if user.startswith("svc_") or user.startswith("service_"):
                        return "win4624_service"
                    return "win4624_success"
            except Exception:
                pass

        # 2.3 Linux – ssh success - CHANGED: preserve for lateral movement detection
        if program.startswith("sshd") or "ssh" in program:
            # REMOVED: No longer collapse SSH logins - they are security events
            pass  # SSH logins now preserved for lateral movement detection

        return None
    except Exception:
        return None

def _match_noise(message: str) -> str | None:
    """Trả về noise_key nếu message là noise, ngược lại None."""
    if not isinstance(message, str):
        return None
    msg_lower = message.lower()
    for pat in NOISE_PATTERNS:
        if re.search(pat, msg_lower, re.IGNORECASE):
            # --- Special handling ---
            if "connection from" in pat:
                m = IP_RE.search(message)
                if m:
                    return f"connection_from_{m.group(1)}"
                return "connection_from"

            # --- OpenSSH specific ---
            if pat.startswith("sshd"):
                if "failed password" in msg_lower or "invalid user" in msg_lower:
                    return None
                ip_match = IP_RE.search(message)
                user_match = re.search(r"for (?:invalid user )?(\S+)", message, re.IGNORECASE)
                ip_key = ip_match.group(1) if ip_match else None
                user_key = user_match.group(1) if user_match else None
                if "accepted" in pat.lower():
                    if user_key and ip_key:
                        return f"ssh_login_success_{user_key.lower()}_{ip_key}"
                    if user_key:
                        return f"ssh_login_success_{user_key.lower()}"
                    return "ssh_login_success"
                if "disconnected from" in pat.lower() or "received disconnect" in pat.lower():
                    return f"ssh_disconnected_{ip_key}" if ip_key else "ssh_disconnected"
                if "connection closed by" in pat.lower():
                    return f"ssh_connection_closed_{ip_key}" if ip_key else "ssh_connection_closed"
                if "server listening on" in pat.lower():
                    return "ssh_server_listening"
                if "starting session" in pat.lower():
                    return "ssh_session_start"

            # --- PAM / session ---
            if "pam_unix" in pat and "session" in pat:
                if "opened" in pat:
                    return "pam_session_opened"
                if "closed" in pat:
                    return "pam_session_closed"
                return "pam_session"
            if "systemd" in pat:
                return "systemd_state_change"
            if pat.startswith("cron"):
                return "cron_cmd"

            # --- HDFS/Hadoop ---
            if "packetresponder" in msg_lower:
                if "closing down" in msg_lower:
                    return "hdfs_packet_responder_close"
                if "ack for block" in msg_lower:
                    return "hdfs_packet_ack"
            if "received block" in msg_lower:
                return "hdfs_datanode_block_received"
            if "addstoredblock" in msg_lower:
                return "hdfs_block_add"
            if "allocateblock" in msg_lower:
                return "hdfs_block_allocate"
            if "datanode" in msg_lower and "heartbeat" in msg_lower:
                return "hdfs_datanode_heartbeat"
            if "datanode" in msg_lower and "block report" in msg_lower:
                return "hdfs_block_report"
            if "nodemanager" in msg_lower and "heartbeat" in msg_lower:
                return "yarn_nm_heartbeat"
            if "resourcemanager" in msg_lower and "heartbeat" in msg_lower:
                return "yarn_rm_heartbeat"
            if "shuffle" in msg_lower and "connection closed" in msg_lower:
                return "mr_shuffle_conn_closed"
            if "ipc server" in msg_lower and "org.apache.hadoop" in msg_lower:
                return "hadoop_ipc_server_call"
            if "namenode" in msg_lower and "safe mode is" in msg_lower:
                return "hdfs_namenode_safemode"

            # --- macOS ---
            if "airport" in msg_lower:
                return "wifi_link_change"
            if "awdl" in msg_lower:
                return "awdl_state_change"
            if "io80211" in msg_lower:
                return "wifi_state_change"
            if "iopmpowersource" in msg_lower:
                return "power_sleep_wake"
            if "applecamin" in msg_lower:
                return "camera_wake_event"
            if "bluetooth" in msg_lower:
                return "bluetooth_event"
            if "usbmsc" in msg_lower:
                return "usb_event"

            

            # --- Windows CBS/CSI ---
            if "cbs sqm" in msg_lower:
                return "win_cbs_sqm"
            if "trustedinstaller" in msg_lower:
                return "win_trustedinstaller"
            if "wcpinitialize" in msg_lower:
                return "win_csi_init"
            if "csi" in msg_lower:
                return "win_csi_trace"

            # --- Zookeeper ---
            if "sendworker leaving thread" in msg_lower:
                return "zk_sendworker_exit"
            if "interrupted while waiting for message" in msg_lower:
                return "zk_sendworker_interrupt"
            if "connection broken" in msg_lower:
                return "zk_connection_broken"
            if "received connection request" in msg_lower:
                return "zk_connection_request"

            # --- Windows Security ---
            if "event id" in msg_lower:
                if "4624" in msg_lower:
                    return "win_sec_logon_success"
                if "4798" in msg_lower:
                    return "win_sec_group_enum"

            # --- OpenSSH variants/banner ---
            if msg_lower.startswith("sshd: "):
                if "accepted" in msg_lower:
                    return None  # CHANGED: Preserve SSH logins for lateral movement detection
                if "disconnected from" in msg_lower:
                    return "ssh_disconnected"
                if "received disconnect" in msg_lower:
                    return "ssh_received_disconnect"
                if "connection closed by" in msg_lower:
                    return "ssh_connection_closed"
            if msg_lower.startswith("openssh_"):
                return "ssh_banner"

            # --- Windows benign mappings ---
            if "service entered the" in msg_lower:
                return "win_service_state_change"
            if "service was successfully sent" in msg_lower:
                return "win_service_control"
            if "task scheduler" in msg_lower:
                return "win_task_scheduler"
            if "windows defender" in msg_lower:
                return "win_defender_info"
            if "group policy successfully processed" in msg_lower:
                return "win_gpo_processed"
            if "an account was successfully logged on" in msg_lower:
                return "win_logon_success"

            return pat
    return None

def reduce_noise(df: pd.DataFrame, threshold: int = 5, window: str = "1min") -> pd.DataFrame:
    """
    Giảm nhiễu log:
      - Chỉ collapse các sự kiện "bình thường" (NOISE_PATTERNS).
      - Burst collapse: gộp log noise liên tiếp cùng noise_key.
      - Window collapse: nếu noise cùng noise_key > threshold trong window.
    Các log khác giữ nguyên, không collapse.
    """
    if df is None or not isinstance(df, pd.DataFrame):
        return pd.DataFrame(columns=["timestamp", "message", "collapsed_count", "noise_key"])

    if df.empty:
        out = df.copy()
        out["collapsed_count"] = 1
        out["noise_key"] = None
        return out

    df = df.copy()
    if "message" not in df.columns:
        df["message"] = ""
    if "timestamp" not in df.columns:
        df["timestamp"] = pd.NaT

    # Gán noise_key theo field-aware trước, rồi fallback regex-based
    try:
        df["noise_key"] = df.apply(_match_noise_fields, axis=1)
    except Exception:
        df["noise_key"] = None
    # Đừng collapse các sự kiện bảo mật quan trọng
    try:
        status_lower = df.get("status").astype(str).str.lower() if "status" in df.columns else None
        # CRITICAL: Preserve all security events - DENY/blocked firewall, failed logins, alerts
        critical_status = status_lower.isin(["failed", "failure", "blocked", "denied", "deny", "drop", "alert"]) if status_lower is not None else None
        
        # Also check 'action' column for firewall DENY events
        action_upper = df.get("action").astype(str).str.upper() if "action" in df.columns else None
        critical_action = action_upper.isin(["DENY", "DENIED", "BLOCK", "BLOCKED", "DROP"]) if action_upper is not None else None
        
        program_lower = df.get("program").astype(str).str.lower() if "program" in df.columns else None
        critical_programs = {"suricata", "modsecurity", "vpcflow", "netflow", "sysmon", "configd", "named", "zeek_dns"}
        is_critical_prog = program_lower.apply(lambda p: p in critical_programs) if program_lower is not None else None
        if critical_status is not None:
            df.loc[critical_status.fillna(False), "noise_key"] = None
        if critical_action is not None:
            df.loc[critical_action.fillna(False), "noise_key"] = None
        if is_critical_prog is not None:
            df.loc[is_critical_prog.fillna(False), "noise_key"] = None
    except Exception:
        pass
    # Fallback cho dòng chưa có noise_key bằng regex NOISE_PATTERNS
    mask_na = df["noise_key"].isna()
    if mask_na.any():
        df.loc[mask_na, "noise_key"] = df.loc[mask_na, "message"].apply(_match_noise)
    df["collapsed_count"] = 1

    # --- Tách noise / non-noise ---
    noise = df[df["noise_key"].notna()].sort_values("timestamp").copy()
    non_noise = df[df["noise_key"].isna()].sort_values("timestamp").copy()

    # --- Burst collapse ---
    keep_noise = []
    prev_row = None
    count = 0
    for _, row in noise.iterrows():
        if prev_row is None:
            prev_row = row.copy()
            count = 1
            continue
        if row["noise_key"] == prev_row["noise_key"]:
            count += 1
        else:
            out_row = prev_row.copy()
            if count > 1:
                out_row["collapsed_count"] = count
                out_row["message"] = f"{out_row['message']} [Repeated {count} times]"
            keep_noise.append(out_row)
            prev_row = row.copy()
            count = 1
    if prev_row is not None:
        out_row = prev_row.copy()
        if count > 1:
            out_row["collapsed_count"] = count
            out_row["message"] = f"{out_row['message']} [Repeated {count} times]"
        keep_noise.append(out_row)

    df_noise_burst = pd.DataFrame(keep_noise) if keep_noise else noise.iloc[0:0].copy()

    # --- Window collapse ---
    if not df_noise_burst.empty:
        df_noise_burst["minute"] = pd.to_datetime(df_noise_burst["timestamp"], errors="coerce").dt.floor(window)
        keep_groups = []
        for (key, minute), group in df_noise_burst.groupby(["noise_key", "minute"], sort=False):
            if len(group) <= threshold:
                keep_groups.append(group)
            else:
                first_row = group.iloc[0].copy()
                total = int(group["collapsed_count"].sum())
                first_row["collapsed_count"] = total
                first_row["message"] = f"{first_row['message']} [Repeated {total} times in {window}]"
                keep_groups.append(pd.DataFrame([first_row]))
        df_noise_burst = pd.concat(keep_groups, ignore_index=True, sort=False)
        df_noise_burst = df_noise_burst.drop(columns=["minute"], errors="ignore")

    # --- Ghép lại ---
    non_noise["collapsed_count"] = 1
    non_noise["noise_key"] = None

    out = pd.concat([non_noise, df_noise_burst], ignore_index=True, sort=False)
    out = out.sort_values("timestamp", na_position="first").reset_index(drop=True)

    if "collapsed_count" not in out.columns:
        out["collapsed_count"] = 1

    return out
