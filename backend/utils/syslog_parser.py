"""
Enhanced syslog parser để extract các fields từ syslog format
Ví dụ: Oct 27 08:05:19 backupsrv01 systemd[12975]: (itops) CMD ((crontab -l; echo ...
"""
import re
import pandas as pd
from typing import Dict, Any, Optional
from datetime import datetime


def parse_syslog_entry(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse một dòng syslog và trả về dict với các fields.
    
    Format: MMM DD HH:MM:SS hostname program[pid]: message
    """
    if not line or not isinstance(line, str):
        return None
    
    line = line.strip()
    if not line:
        return None
    
    # Pattern: "Oct 27 08:05:19 hostname program[pid]: message" hoặc "Oct 27 08:05:19 hostname program: message"
    pattern = r'^([A-Za-z]+)\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+([^\s]+)\s+([^\s\[]+)(?:\[(\d+)\])?\s*:\s*(.*)$'
    match = re.match(pattern, line)
    
    if not match:
        # Fallback: nếu không match pattern, trả về message thôi
        return {"message": line}
    
    month, day, hour, minute, second, hostname, program, pid, message = match.groups()
    
    # Construct timestamp (year phải infer từ log, mặc định 2025)
    try:
        ts_str = f"2025 {month} {day} {hour}:{minute}:{second}"
        timestamp = pd.to_datetime(ts_str, format="%Y %b %d %H:%M:%S", utc=True)
    except Exception:
        timestamp = None
    
    record = {
        "timestamp": timestamp,
        "hostname": hostname.strip() if hostname else None,
        "program": program.strip() if program else None,
        "pid": int(pid) if pid else None,
        "message": message.strip() if message else None,
    }
    
    # Extract username from message if possible
    # Pattern: "program[pid]: (username)" or "User/Username: ..."
    username_match = re.search(r'\(([a-zA-Z0-9_\-]+)\)|User(?:name)?[:\s]+([a-zA-Z0-9_\-]+)', message)
    if username_match:
        username = username_match.group(1) or username_match.group(2)
        record["username"] = username
    
    # Extract source_ip from "from X.X.X.X"
    ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
    if ip_match:
        record["source_ip"] = ip_match.group(1)
    
    # Extract action based on program
    action = None
    if "sshd" in program.lower():
        if "Accepted publickey" in message:
            action = "login"
        elif "Failed" in message or "failed" in message:
            action = "login_failed"
    elif "nginx" in program.lower():
        if "access" in message.lower():
            action = "http_access"
        elif "GET" in message or "POST" in message:
            action = "http_access"
    elif "systemd" in program.lower():
        if "Stopping" in message or "Stopped" in message:
            action = "service_stop"
        elif "Starting" in message or "Started" in message:
            action = "service_start"
    elif "sudo" in program.lower():
        action = "sudo"
    elif "cron" in program.lower() or "crontab" in message.lower():
        action = "cron"
    elif "scp" in program.lower():
        action = "file_transfer"
    elif "audit" in program.lower():
        action = "audit"
    
    if action:
        record["action"] = action
    
    # Extract HTTP status if present
    http_match = re.search(r'\s(\d{3})\s', message)
    if http_match:
        record["http_status"] = int(http_match.group(1))
    
    # Extract dest_ip if present
    dest_match = re.search(r'dst=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
    if dest_match:
        record["dest_ip"] = dest_match.group(1)
    
    # Extract port if present
    port_match = re.search(r'port\s+(\d+)', message)
    if port_match:
        record["dest_port"] = int(port_match.group(1))
    
    return record


def parse_syslog_dataframe(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Parse a DataFrame with 'message' column (raw syslog lines) into structured fields.
    """
    if "message" not in raw_df.columns:
        return raw_df
    
    records = []
    for msg in raw_df["message"]:
        parsed = parse_syslog_entry(msg)
        if parsed:
            records.append(parsed)
    
    if not records:
        return raw_df
    
    parsed_df = pd.DataFrame(records)
    
    # Keep original columns and add new ones
    for col in raw_df.columns:
        if col not in parsed_df.columns:
            parsed_df[col] = raw_df[col].iloc[:len(parsed_df)].reset_index(drop=True)
    
    return parsed_df

