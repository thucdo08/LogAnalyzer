# backend/app.py
# -*- coding: utf-8 -*-
import sys
import io
# Force UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from dotenv import load_dotenv
load_dotenv()
import os
import pandas as pd
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from services.preprocess import preprocess_any
# from services.preprocess import preprocess_csv
from services.analyzer import analyze_logs_with_openai, summarize_levels 
from services.postprocess import postprocess
# Lazy-import baseline/anomaly modules inside endpoints to avoid hard deps at startup
from openai import OpenAI

from services.validator import basic_validate_df
from services.filters import reduce_noise
from services.enrich import enrich_df
#from services.alert_sender import get_alert_sender_service

import tempfile, shutil
from datetime import datetime, timezone
import requests


import os, json
import pandas as pd
from flask import jsonify, request, Response
from dotenv import load_dotenv
from flask import Response
from flask import Response, request, jsonify

from services.preprocess import preprocess_any
from services.validator import basic_validate_df
#from services.filters import apply_noise_filters
# from services.enrich import enrich_df
from services.analyzer import analyze_logs_with_openai, summarize_levels
from services.postprocess import postprocess

load_dotenv()
app = Flask(__name__)
CORS(app)
app.config["JSON_AS_ASCII"] = False

# Ensure JSON-safe outputs (replace NaN/NaT with None, cast numpy types, format timestamps)
def _json_safe(value):
    import math
    import numpy as _np
    import pandas as _pd

    if value is None:
        return None
    # Basic scalar conversions
    if isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return None if math.isnan(value) else value
    # Numpy scalar
    if isinstance(value, (_np.integer,)):
        return int(value)
    if isinstance(value, (_np.floating,)):
        return None if _np.isnan(value) else float(value)
    if value is _np.nan:
        return None
    # Pandas timestamp/NaT
    if isinstance(value, (_pd.Timestamp,)):
        return value.isoformat()
    # Collections
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [ _json_safe(v) for v in value ]
    # Pandas objects
    if isinstance(value, _pd.Series):
        return _json_safe(value.to_dict())
    if isinstance(value, _pd.DataFrame):
        return _json_safe(value.to_dict(orient="records"))
    # Fallback to string
    try:
        return str(value)
    except Exception:
        return None

# Nạp RULES
RULES = {}
try:
    rules_path = os.path.join(os.path.dirname(__file__), "config", "rules.json")
    with open(rules_path, "r", encoding="utf-8") as f:
        RULES = json.load(f)
except Exception:
    RULES = {}

def _rebuild_text_events(df: pd.DataFrame):
    """Tạo lại log_text (để gọi AI) và events_per_minute từ df (đã lọc/enrich)."""
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return [], pd.DataFrame(columns=["timestamp", "events_per_minute"])
    def _fmt(row):
        # Fallback an toàn để tránh thiếu thông tin (đặc biệt với BGL)
        host_safe = (
            row.get("host")
            or row.get("Node")
            or row.get("node")
            or ""
        )
        program_safe = (
            row.get("program")
            or row.get("component")
            or row.get("Component")
            or ""
        )
        message_safe = (
            row.get("message")
            or row.get("Content")
            or row.get("event_template")
            or row.get("EventTemplate")
            or row.get("action")
            or row.get("status")
            or program_safe
            or "(no message)"
        )
        action_safe = row.get("action") or ""
        status_safe = row.get("status") or ""

        parts = [
            f"{row['timestamp']}",
            f"IP:{row.get('source_ip','')}",
            f"User:{row.get('username','')}",
            f"Action:{action_safe}",
            f"Status:{status_safe}",
            f"Message:{message_safe}",
        ]
        for extra in ["event_id","level","process","method","path","http_status","program","component","host","ip_scope","geoip_country","asn_org"]:
            if extra in df.columns:
                val = row.get(extra, None)
                if pd.notna(val):
                    parts.append(f"{extra}:{val}")
        return " - ".join(parts)

    logs_text = df.apply(_fmt, axis=1).tolist()
    df_idx = df.set_index("timestamp").sort_index()
    events_pm = df_idx.resample("1min").size().reset_index(name="events_per_minute")
    return logs_text, events_pm


def _get_logs_for_alert(df: pd.DataFrame, alert: dict, lookback_minutes: int = 30, max_logs: int = 100) -> pd.DataFrame:
    """
    Lấy logs liên quan đến 1 alert để phân tích AI.
    Strategy:
    - Nếu alert có 'subject' là username -> lọc logs của user đó
    - Nếu là IP-related -> lọc logs của IP đó
    - Limit: tối đa max_logs dòng để tránh token overhead (default 100, khớp với số lượng logs liên quan)
    """
    if df is None or df.empty:
        return pd.DataFrame()
    
    df_work = df.copy()
    subject = alert.get("subject", "")
    
    if not subject:
        return df_work.tail(max_logs)
    
    # Strategy 1: Lọc logs của user/username này (nếu subject là username)
    if "username" in df_work.columns:
        user_logs = df_work[df_work["username"].astype(str).str.lower() == str(subject).lower()]
        if not user_logs.empty:
            return user_logs.tail(max_logs)
    
    # Strategy 2: Lọc logs của source_ip/destination_ip này
    if "source_ip" in df_work.columns or "destination_ip" in df_work.columns:
        ip_logs = df_work[
            (df_work.get("source_ip", pd.Series()).astype(str) == str(subject)) |
            (df_work.get("destination_ip", pd.Series()).astype(str) == str(subject))
        ]
        if not ip_logs.empty:
            return ip_logs.tail(max_logs)
    
    # Strategy 3: Lọc logs của host/device này
    if "host" in df_work.columns:
        host_logs = df_work[df_work["host"].astype(str).str.lower() == str(subject).lower()]
        if not host_logs.empty:
            return host_logs.tail(max_logs)
    
    # Fallback: trả về logs gần nhất
    return df_work.tail(max_logs)

@app.post("/anomaly/raw")
def anomaly_raw():
    """
    Bước 2: sinh cảnh báo thô dựa trên baseline (Z-score/Moving Average...).
    Input: multipart file + optional from/to; enrich để có ip_scope/geoip nếu cấu hình.
    Output: { ok, alerts: [ {type, subject, severity, score, text, evidence}, ... ] }
    """
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Thiếu file"}), 400
        f = request.files["file"]
        if f is None or f.filename == "":
            return jsonify({"ok": False, "error": "File rỗng"}), 400

        t_from = request.form.get("from")
        t_to   = request.form.get("to")

        # 1) Ingest + normalize
        _, df_raw, _ = preprocess_any(f, filename=f.filename, start_iso=t_from, end_iso=t_to)

        # 2) Reduce noise and enrich (to enable ip_scope/geoip)
        df_used = reduce_noise(df_raw, threshold=5)
        enrich_cfg = {
            "mask_pii": True,
            "geoip_mmdb": RULES.get("geoip_mmdb"),
            "asn_mmdb": RULES.get("asn_mmdb"),
        }
        df_used = enrich_df(df_used, enrich_cfg)

        # 3) Generate raw anomalies using stored baselines
        from services.anomaly import generate_raw_anomalies
        # Get log_type: try from form parameter, else detect from df
        log_type = request.form.get("log_type", "generic")
        if log_type == "generic" and "program" in df_used.columns:
            programs = df_used["program"].dropna().astype(str).str.lower().unique().tolist()
            log_type_map = {
                "firewall": "firewall",
                "router_ios": "router",
                "named": "dns",
                "winevent": "windows_eventlog",
                "security": "windows_eventlog",
                "system": "windows_eventlog",
                "sysmon": "windows_eventlog",  # ← Sysmon is Windows Event Log channel, NOT EDR
                "dhcpd": "dhcp",
                "apache": "apache",
                "squid": "proxy",
                "suricata": "ids",
                "edr_network": "edrnetwork",
                "edr_sysmon": "edr",  # ← Only edr_sysmon (from EDR agent) → edr
                "syslog": "syslog",
                # Linux/Unix programs → syslog
                "sshd": "linuxsyslog",
                "sudo": "linuxsyslog",
                "cron": "linuxsyslog",
                "kernel": "linuxsyslog",
                "systemd": "linuxsyslog",
                "auth": "linuxsyslog",
            }
            for prog in programs:
                for key, val in log_type_map.items():
                    if key in prog:
                        log_type = val
                        break
                if log_type != "generic":
                    break
        
        # Load baselines from MongoDB (PRIMARY) or config/baselines/ (FALLBACK)
        base_dir = os.path.join(os.path.dirname(__file__), "config", "baselines")
        print(f"Anomaly raw: using log_type={log_type}, baselines_dir={base_dir}")
        alerts = generate_raw_anomalies(df_used, baselines_dir=base_dir, log_type=log_type)

        # Filter alerts by min_score (default 3.5 to reduce noise)
        min_score = float(request.form.get("min_score", "3.5"))
        alerts_filtered = [a for a in alerts if a.get("score", 0) >= min_score]

        # Ensure all alerts have valid severity (CRITICAL, WARNING, INFO)
        valid_severities = {"CRITICAL", "WARNING", "INFO"}
        for a in alerts_filtered:
            if "severity" not in a or a.get("severity") not in valid_severities:
                # Infer severity from score if missing
                score = a.get("score", 0)
                if score >= 6.0:
                    a["severity"] = "CRITICAL"
                elif score >= 4.0:
                    a["severity"] = "WARNING"
                else:
                    a["severity"] = "INFO"

        # Build summary
        from collections import Counter
        severity_counts = Counter(a.get("severity") for a in alerts_filtered)
        type_counts = Counter(a.get("type") for a in alerts_filtered)
        subjects = [a.get("subject") for a in alerts_filtered if a.get("subject")]
        
        summary = {
            "total_alerts": len(alerts_filtered),
            "severity_breakdown": dict(severity_counts),
            "type_breakdown": dict(type_counts),
            "top_subjects": list(set(subjects))[:10],
        }

        # Save single consolidated report
        try:
            import time
            custom_out = request.form.get("output_dir")
            alerts_dir = (
                custom_out if custom_out else os.path.join(os.path.dirname(__file__), "config", "alerts")
            )
            os.makedirs(alerts_dir, exist_ok=True)
            
            ts = int(time.time() * 1000)
            fname = f"anomaly_report_{ts}.json"
            fpath = os.path.join(alerts_dir, fname)
            
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
                "alerts": alerts_filtered,
            }
            
            with open(fpath, "w", encoding="utf-8") as fo:
                json.dump(report, fo, ensure_ascii=False, indent=2)
            
            saved_path = fpath
        except Exception as ex:
            saved_path = None
            print(f"Error saving report: {ex}")

        payload = {
            "ok": True,
            "summary": summary,
            "alerts": alerts_filtered,
            "report_path": saved_path,
        }
        return jsonify(_json_safe(payload))
    except Exception as e:
        import traceback
        print("anomaly_raw error:", repr(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({"ok": False, "error": f"Anomaly lỗi: {e}"}), 500

@app.post("/anomaly/prompt")
def anomaly_prompt():
    """
    Bước 3: nhận 1 alert (JSON) hoặc sinh prompt từ alert và gọi AI để phân tích rủi ro.
    Input JSON body: { alert: {...} } hoặc { prompt: "..." }
    """
    try:
        body = request.get_json(silent=True) or {}
        prompt = body.get("prompt")
        if not prompt:
            alert = body.get("alert") or {}
            from services.anomaly import build_prompt_for_alert
            from services.analyzer import build_detailed_prompt_from_alert
            prompt = build_detailed_prompt_from_alert(alert)

        from services.analyzer import analyze_alert_prompt
        data, used = analyze_alert_prompt(prompt)
        return jsonify(_json_safe({"ok": True, "used_openai": used, "report": data, "prompt": prompt}))
    except Exception as e:
        import traceback
        print("anomaly_prompt error:", repr(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({"ok": False, "error": f"Prompt lỗi: {e}"}), 500

@app.post("/anomaly/batch-analyze")
def anomaly_batch_analyze():
    """
    Bước 4: Nhận danh sách alerts (từ report JSON) và gửi từng cái cho AI phân tích.
    Input JSON body: { alerts: [...] } hoặc file path
    Output: { ok, results: [{ alert, ai_analysis }, ...], summary: {...} }
    """
    try:
        body = request.get_json(silent=True) or {}
        alerts = body.get("alerts", [])
        
        if not alerts:
            # Try load from file if provided
            report_file = body.get("report_file")
            if report_file and os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as f:
                    report = json.load(f)
                    alerts = report.get("alerts", [])
        
        if not alerts:
            return jsonify({"ok": False, "error": "Thiếu alerts"}), 400
        
        from services.analyzer import build_detailed_prompt_from_alert, analyze_alert_prompt
        
        results = []
        for alert in alerts:
            try:
                prompt = build_detailed_prompt_from_alert(alert)
                ai_report, used = analyze_alert_prompt(prompt)
                results.append({
                    "alert_type": alert.get("type"),
                    "subject": alert.get("subject"),
                    "severity": alert.get("severity"),
                    "score": alert.get("score"),
                    "text": alert.get("text"),
                    "ai_analysis": ai_report,
                })
            except Exception as ae:
                print(f"Error analyzing alert {alert.get('subject')}: {ae}")
                results.append({
                    "alert_type": alert.get("type"),
                    "subject": alert.get("subject"),
                    "severity": alert.get("severity"),
                    "score": alert.get("score"),
                    "text": alert.get("text"),
                    "ai_analysis": {
                        "summary": "Lỗi phân tích",
                        "risks": ["Không thể kết nối AI"],
                        "risk_level": "Trung bình",
                        "actions": ["Giám sát thêm"],
                    },
                })
        
        # Ensure all results have valid severity
        valid_severities = {"CRITICAL", "WARNING", "INFO"}
        for r in results:
            if "severity" not in r or r.get("severity") not in valid_severities:
                score = r.get("score", 0)
                if score >= 6.0:
                    r["severity"] = "CRITICAL"
                elif score >= 4.0:
                    r["severity"] = "WARNING"
                else:
                    r["severity"] = "INFO"

        # Build summary
        from collections import Counter
        type_counts = Counter(r.get("alert_type") for r in results)
        severity_counts = Counter(r.get("severity") for r in results)
        
        summary = {
            "total_alerts": len(results),
            "type_breakdown": dict(type_counts),
            "severity_breakdown": dict(severity_counts),
        }
        
        payload = {
            "ok": True,
            "summary": summary,
            "results": results,
        }
        return jsonify(_json_safe(payload))
    except Exception as e:
        import traceback
        print("anomaly_batch_analyze error:", repr(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({"ok": False, "error": f"Batch analyze lỗi: {e}"}), 500

@app.post("/analyze")
def analyze():
    """
    BƯỚC 1-4 HOÀN CHỈNH: Thu thập → Tiền xử lý → Phát hiện Bất thường → Phân tích AI
    
    Input: multipart file (log) + optional from/to time
    Output: {
        ok: bool,
        step2_summary: {...},  # raw anomalies summary
        step3_results: [...],  # AI-analyzed alerts
        saved_report_path: str,
    }
    """
    try:
        # === BƯỚC 1: Nhận file log thô ===
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Thiếu file"}), 400
        f = request.files["file"]
        if f is None or f.filename == "":
            return jsonify({"ok": False, "error": "File rỗng"}), 400

        t_from = request.form.get("from")
        t_to   = request.form.get("to")
        min_score = float(request.form.get("min_score", "3.5"))

        print(f"\n{'='*60}")
        print(f"BƯỚC 1: Thu thập log thô từ {f.filename}")
        print(f"{'='*60}")
        
        # === BƯỚC 2: Tiền xử lý + Lọc nhiễu + Enrich ===
        print(f"\nBƯỚC 2: Tiền xử lý, lọc nhiễu, enrich")
        _, df_raw, _ = preprocess_any(f, filename=f.filename, start_iso=t_from, end_iso=t_to)
        print(f"  → Sau preprocess: {len(df_raw)} dòng")

        df_used = reduce_noise(df_raw, threshold=5)
        print(f"  → Sau lọc nhiễu: {len(df_used)} dòng")

        enrich_cfg = {
            "mask_pii": True,
            "geoip_mmdb": RULES.get("geoip_mmdb"),
            "asn_mmdb": RULES.get("asn_mmdb"),
        }
        df_used = enrich_df(df_used, enrich_cfg)
        print(f"  → Sau enrich: {len(df_used)} dòng")

        # === BƯỚC 3: Phát hiện Bất thường (Anomaly Detection) ===
        print(f"\nBƯỚC 3: Phát hiện Bất thường từ Baseline")
        from services.anomaly import generate_raw_anomalies
        # Detect log_type from program column
        log_type = request.form.get("log_type", "generic")
        if log_type == "generic" and "program" in df_used.columns:
            programs = df_used["program"].dropna().astype(str).str.lower().unique().tolist()
            log_type_map = {
                "firewall": "firewall",
                "router_ios": "router",
                "named": "dns",
                "winevent": "windows_eventlog",
                "security": "windows_eventlog",
                "system": "windows_eventlog",
                "sysmon": "windows_eventlog",  # ← Sysmon is Windows Event Log channel, NOT EDR
                "dhcpd": "dhcp",
                "apache": "apache",
                "squid": "proxy",
                "suricata": "ids",
                "edr_network": "edrnetwork",
                "edr_sysmon": "edr",  # ← Only edr_sysmon (from EDR agent) → edr
                "syslog": "syslog",
                # Linux/Unix programs → syslog
                "sshd": "linuxsyslog",
                "sudo": "linuxsyslog",
                "cron": "linuxsyslog",
                "kernel": "linuxsyslog",
                "systemd": "linuxsyslog",
                "auth": "linuxsyslog",
            }
            for prog in programs:
                for key, val in log_type_map.items():
                    if key in prog:
                        log_type = val
                        break
                if log_type != "generic":
                    break
        
        # Load baselines from MongoDB (PRIMARY) or config/baselines/ (FALLBACK)
        base_dir = os.path.join(os.path.dirname(__file__), "config", "baselines")
        print(f"  → Log type: {log_type}, baselines_dir={base_dir}")
        all_alerts = generate_raw_anomalies(df_used, baselines_dir=base_dir, log_type=log_type)
        print(f"  → Tổng cảnh báo thô: {len(all_alerts)}")

        # Lọc theo min_score
        alerts_filtered = [a for a in all_alerts if a.get("score", 0) >= min_score]
        print(f"  → Sau lọc (min_score={min_score}): {len(alerts_filtered)}")

        # Ensure all alerts have valid severity
        valid_severities = {"CRITICAL", "WARNING", "INFO"}
        for a in alerts_filtered:
            if "severity" not in a or a.get("severity") not in valid_severities:
                score = a.get("score", 0)
                if score >= 6.0:
                    a["severity"] = "CRITICAL"
                elif score >= 4.0:
                    a["severity"] = "WARNING"
                else:
                    a["severity"] = "INFO"

        # Summary bước 2
        from collections import Counter
        severity_counts = Counter(a.get("severity") for a in alerts_filtered)
        type_counts = Counter(a.get("type") for a in alerts_filtered)
        subjects = [a.get("subject") for a in alerts_filtered if a.get("subject")]
        
        step2_summary = {
            "total_alerts": len(alerts_filtered),
            "severity_breakdown": dict(severity_counts),
            "type_breakdown": dict(type_counts),
            "top_subjects": list(set(subjects))[:10],
        }

        # Lưu report cảnh báo thô (bước 2 output)
        try:
            import time
            custom_out = request.form.get("output_dir")
            alerts_dir = (
                custom_out if custom_out else os.path.join(os.path.dirname(__file__), "config", "alerts")
            )
            os.makedirs(alerts_dir, exist_ok=True)
            
            ts = int(time.time() * 1000)
            fname = f"anomaly_report_{ts}.json"
            fpath = os.path.join(alerts_dir, fname)
            
            step2_report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": step2_summary,
                "alerts": alerts_filtered,
            }
            
            with open(fpath, "w", encoding="utf-8") as fo:
                json.dump(step2_report, fo, ensure_ascii=False, indent=2)
            
            saved_report_path = fpath
            print(f"  → Lưu report cảnh báo thô: {fpath}")
        except Exception as ex:
            saved_report_path = None
            print(f"  ⚠️ Error saving report: {ex}")

        # === BƯỚC 4: Phân tích & Ra quyết định (AI Analysis) ===
        print(f"\nBƯỚC 4: Gửi cảnh báo thô qua AI để phân tích chi tiết")
        print(f"        (Lấy logs liên quan → Gọi AI → Enrich alert)")
        from services.analyzer import build_detailed_prompt_from_alert, analyze_alert_prompt
        
        # === GROUP ALERTS BY SUBJECT (user/IP) ===
        # Group alerts by subject so we analyze all behaviors of one user together
        alerts_by_subject = {}
        for alert in alerts_filtered:
            subject = alert.get('subject', '(unknown)')
            if subject not in alerts_by_subject:
                alerts_by_subject[subject] = []
            alerts_by_subject[subject].append(alert)
        
        print(f"  → Grouped {len(alerts_filtered)} alerts into {len(alerts_by_subject)} subjects")
        
        step3_results = []
        subject_idx = 0
        for subject, alerts_group in alerts_by_subject.items():
            subject_idx += 1
            try:
                print(f"\n  [{subject_idx}/{len(alerts_by_subject)}] Phân tích user/IP: '{subject}' ({len(alerts_group)} alerts)")
                
                # === BƯỚC 3a: Lấy logs liên quan (tất cả logs của user/IP này) ===
                # Use the first alert as template to get logs (up to 100 logs per group)
                first_alert = alerts_group[0]
                related_logs_df = _get_logs_for_alert(df_used, first_alert, lookback_minutes=30, max_logs=100)
                logs_text, _ = _rebuild_text_events(related_logs_df)
                print(f"       → Lấy {len(logs_text)} logs liên quan (max 100 per group)")
                
                # === BƯỚC 3b: Tạo prompt chi tiết từ TẤT CẢ cảnh báo của user này + logs ===
                # Build a combined prompt with all alert types for this subject
                alert_types = list(set(a.get("type") for a in alerts_group))
                alert_summary = "\n".join([
                    f"  - {a.get('type')}: {a.get('text', '')[:100]}"
                    for a in sorted(alerts_group, key=lambda x: x.get('score', 0), reverse=True)
                ])
                
                prompt = f"""Phân tích hoạt động bất thường của '{subject}':

Các loại cảnh báo được phát hiện ({len(alerts_group)} tổng cộng):
{alert_summary}

Yêu cầu:
1. Phân tích bằng TIẾNG VIỆT HOÀN TOÀN (không sử dụng tiếng Anh).
2. Tìm mối liên hệ giữa các hành vi này.
3. Đánh giá mức độ rủi ro tổng thể.
4. Đề xuất hành động cụ thể.

Mức độ rủi ro phải là MỘT trong những giá trị sau (chọn đúng):
- "Thấp" (nếu rủi ro nhỏ)
- "Trung bình" (nếu rủi ro vừa phải)
- "Cao" (nếu rủi ro lớn)
- "Cực kỳ nguy cấp" (nếu rủi ro rất lớn)

Trả lời CHÍNH XÁC theo format JSON này (không thêm bất cứ thứ gì khác):
{{
  "summary": "Tóm tắt phân tích bằng tiếng Việt",
  "risks": ["Rủi ro 1 bằng tiếng Việt", "Rủi ro 2 bằng tiếng Việt"],
  "risk_level": "Chọn từ: Thấp, Trung bình, Cao, hoặc Cực kỳ nguy cấp",
  "actions": ["Hành động 1 bằng tiếng Việt", "Hành động 2 bằng tiếng Việt"]
}}"""
                
                if logs_text:
                    logs_context = "\n".join(logs_text[:50])  # Max 50 logs để không quá dài
                    prompt += f"\n\nLogs liên quan ({len(logs_text)} entries):\n{logs_context}"
                
                # === BƯỚC 3c: Gửi qua AI để phân tích (CHỈ 1 LẦN cho tất cả alerts của user) ===
                print(f"       → Gọi AI để phân tích tất cả {len(alerts_group)} alerts cùng lúc...")
                ai_report, used_openai = analyze_alert_prompt(prompt)
                
                # === BƯỚC 3d: Enrich TẤT CẢ alerts của user này với kết quả AI ===
                # Tính toán stats từ logs (critical_count, warning_count, samples)
                critical_count = sum(1 for log in logs_text if any(
                    kw in log.lower() for kw in ["critical", "error", "failed", "denied", "blocked"]
                ))
                warning_count = sum(1 for log in logs_text if any(
                    kw in log.lower() for kw in ["warning", "retry", "timeout", "throttle"]
                ))
                
                # Add grouped result with all alerts
                grouped_result = {
                    "subject": subject,
                    "alert_count": len(alerts_group),
                    "alert_types": alert_types,
                    "alerts": alerts_group,  # Include all individual alerts for reference
                    "severity_max": max(a.get("severity") for a in alerts_group) if alerts_group else "INFO",
                    "score_max": max(a.get("score", 0) for a in alerts_group) if alerts_group else 0,
                    "related_logs_count": len(logs_text),
                    "enriched": {
                        "critical_count": critical_count,
                        "warning_count": warning_count,
                        "samples": logs_text[:5] if logs_text else [],
                    },
                    "ai_analysis": ai_report,
                }
                step3_results.append(grouped_result)
                print(f"      [OK] Hoàn thành - Phân tích {len(alerts_group)} alerts cho '{subject}', risk_level: {ai_report.get('risk_level')}")
                
            except Exception as ae:
                print(f"      [ERROR] Lỗi phân tích '{subject}': {ae}")
                import traceback
                print(f"      Traceback: {traceback.format_exc()}")
                # Add error result for this subject's alerts
                step3_results.append({
                    "subject": subject,
                    "alert_count": len(alerts_group),
                    "alert_types": list(set(a.get("type") for a in alerts_group)),
                    "alerts": alerts_group,
                    "severity_max": max(a.get("severity") for a in alerts_group) if alerts_group else "INFO",
                    "score_max": max(a.get("score", 0) for a in alerts_group) if alerts_group else 0,
                    "enriched": {
                        "critical_count": 0,
                        "warning_count": 0,
                        "samples": [],
                    },
                    "ai_analysis": {
                        "summary": "Lỗi phân tích",
                        "risks": ["Không thể kết nối AI hoặc lỗi xử lý"],
                        "risk_level": "Trung bình",
                        "actions": ["Giám sát thêm"],
                    },
                })

        # === FLATTEN step3_results for frontend ===
        # Backend groups alerts by subject for AI analysis efficiency,
        # but frontend expects individual alert objects with score/severity
        flattened_results = []
        for grouped_item in step3_results:
            ai_analysis = grouped_item.get("ai_analysis", {})
            # Enrich each individual alert with group's AI analysis
            for alert in grouped_item.get("alerts", []):
                flattened_results.append({
                    "type": alert.get("type"),
                    "subject": alert.get("subject"),
                    "severity": alert.get("severity"),  # ← Alert's own severity
                    "score": alert.get("score"),        # ← Alert's own score
                    "text": alert.get("text"),
                    "evidence": alert.get("evidence"),
                    "ai_analysis": ai_analysis,  # Share group's AI analysis
                })
        
        # Summary bước 4
        step4_summary = {
            "total_analyzed": len(flattened_results),
            "by_risk_level": dict(Counter(r.get("ai_analysis", {}).get("risk_level") for r in step3_results)),
        }

        print(f"\n{'='*60}")
        print(f"HOÀN THÀNH QUY TRÌNH 4 BƯỚC")
        print(f"  Bước 2 (Raw Anomalies): {step2_summary['total_alerts']} alerts")
        print(f"  Bước 4 (AI Analysis): {step4_summary['total_analyzed']} alerts đã phân tích")
        print(f"{'='*60}\n")

        # === BƯỚC 5: Gửi kết quả (grouped by subject) tới N8N Webhook ===
        # Format: [{ subject, alert_types, alert_count, risk_level, severity, score, summary, events, risk_analysis, recommendation }, ...]
        n8n_payload = []
        for grouped_item in step3_results:
            ai_analysis = grouped_item.get("ai_analysis", {})
            
            # Lấy top 2 events từ alerts
            sample_alerts = grouped_item.get("alerts", [])[:2]
            events = [
                f"[{a.get('type')}] {a.get('text', '')[:100]}"
                for a in sample_alerts
            ]
            if len(grouped_item.get("alerts", [])) > 2:
                events.append(f"+{len(grouped_item.get('alerts', [])) - 2} more alerts...")
            
            n8n_item = {
                "subject": grouped_item.get("subject"),
                "alert_types": ", ".join(grouped_item.get("alert_types", [])),
                "alert_count": grouped_item.get("alert_count", 0),
                "risk_level": ai_analysis.get("risk_level", "Trung bình"),
                "severity": grouped_item.get("severity_max", "INFO"),
                "score": grouped_item.get("score_max", 0),
                "events": events,
                "summary": ai_analysis.get("summary", "Không có tóm tắt"),
                "risk_analysis": " | ".join(ai_analysis.get("risks", [])),
                "recommendation": " | ".join(ai_analysis.get("actions", [])),
            }
            n8n_payload.append(n8n_item)
        
        # Gửi tới N8N webhook (nếu cấu hình)
        n8n_webhook_url = os.getenv("N8N_WEBHOOK_URL")
        if n8n_webhook_url:
            try:
                print(f"[N8N] Gửi {len(n8n_payload)} kết quả phân tích tới N8N webhook...")
                response = requests.post(
                    n8n_webhook_url,
                    json={"results": n8n_payload},
                    timeout=30,
                    headers={"Content-Type": "application/json"}
                )
                if response.status_code == 200:
                    print(f"[N8N] ✅ Webhook executed successfully")
                else:
                    print(f"[N8N] ⚠️ Webhook returned {response.status_code}: {response.text[:100]}")
            except Exception as ex:
                print(f"[N8N] ❌ Error sending to webhook: {ex}")
        else:
            print(f"[N8N] ⚠️ N8N_WEBHOOK_URL not configured, skipping webhook")

        # === Response ===
        payload = {
            "ok": True,
            "step2_summary": step2_summary,
            "step3_results": flattened_results,  # ← Use flattened results with score/severity!
            "saved_report_path": saved_report_path,
            "step4_summary": step4_summary,
        }
        return jsonify(_json_safe(payload))

    except Exception as e:
        import traceback
        print("Analyze error:", repr(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({"ok": False, "error": f"Analyze lỗi: {e}"}), 500


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/ai/status")
def ai_status():
    from services.analyzer import _make_openai_client
    ok_env = bool(os.getenv("OPENAI_API_KEY"))
    ok_call = False
    err = None
    try:
        client = _make_openai_client()
        if client:
            client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content":"ping"}],
                max_tokens=1,
                temperature=0
            )
            ok_call = True
    except Exception as e:
        err = str(e)
    return {"ok_env": ok_env, "ok_call": ok_call, "error": err}


@app.route("/export", methods=["GET", "POST"])
def export_csv():
    if request.method == "GET":
        df = app.config.get("LAST_DF")
        if df is None or not hasattr(df, "to_csv") or df.empty:
            return Response("No data", status=404)
        csv_data = df.to_csv(index=False)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=logs_export.csv"}
        )

    # POST: nhận file để export ngay (raw-only)
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "Thiếu file"}), 400
        f = request.files["file"]
        if not f or f.filename == "":
            return jsonify({"ok": False, "error": "File rỗng"}), 400

        t_from = request.form.get("from")
        t_to   = request.form.get("to")

        # Chỉ preprocess (chuẩn hoá), không lọc, không enrich
        logs_text, df, _ = preprocess_any(f, filename=f.filename, start_iso=t_from, end_iso=t_to)

        out = df.copy()
        out.insert(0, "log_index", range(1, len(out) + 1))

        csv_bytes = out.to_csv(index=False).encode("utf-8")
        return Response(
            csv_bytes,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=log_analysis_raw.csv"}
        )
    except Exception as e:
        print("Export error:", repr(e))
        return jsonify({"ok": False, "error": f"Export lỗi: {e}"}), 500




# ==== Append/Merge helpers for baseline saving ====

def _safe_load_json_df(path: str) -> pd.DataFrame:
    try:
        if not os.path.exists(path):
            return pd.DataFrame()
        return pd.read_json(path, orient="records")
    except Exception:
        return pd.DataFrame()

def _safe_atomic_write_text(path: str, text: str, encoding="utf-8"):
    dname = os.path.dirname(path)
    os.makedirs(dname, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding=encoding, delete=False, dir=dname) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    shutil.move(tmp_path, path)

def _merge_by_key(old_df: pd.DataFrame, new_df: pd.DataFrame, key_col: str) -> pd.DataFrame:
    """
    Merge theo khóa:
    - Bản ghi mới với key trùng sẽ ghi đè bản ghi cũ cùng key.
    - Các key khác giữ nguyên.
    """
    if new_df is None or new_df.empty:
        return old_df.copy()
    if old_df is None or old_df.empty:
        return new_df.copy()
    if key_col not in new_df.columns:
        return old_df.copy()
    if key_col not in old_df.columns:
        old_df = old_df.copy()
        old_df[key_col] = pd.NA

    # Đồng bộ cột
    all_cols = sorted(set(old_df.columns).union(set(new_df.columns)))
    old_df = old_df.reindex(columns=all_cols)
    new_df = new_df.reindex(columns=all_cols)

    # Loại bản ghi cũ trùng key rồi nối bản ghi mới
    new_keys = new_df[key_col].dropna().astype(str).unique()
    kept_old = old_df[~old_df[key_col].astype(str).isin(new_keys)]
    merged = pd.concat([kept_old, new_df], ignore_index=True)

    # Nếu vẫn còn trùng, giữ bản ghi cuối cùng theo key
    merged = merged.dropna(subset=[key_col]).drop_duplicates(subset=[key_col], keep="last")
    return merged

def _append_global_snapshot(out_path: str, snap: dict):
    """
    Lưu GLOBAL baseline dạng mảng snapshot (append).
    """
    now = datetime.now(timezone.utc).isoformat()
    snap_with_ts = {"trained_at": now, **snap}
    arr = []
    if os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    arr = data
                elif isinstance(data, dict):
                    arr = [data]
        except Exception:
            arr = []
    arr.append(snap_with_ts)
    _safe_atomic_write_text(out_path, json.dumps(arr, ensure_ascii=False, indent=2))

def _joblib_merge_dict(out_path: str, new_dict: dict):
    """
    joblib dict merge: load cũ (nếu có) -> update -> dump,
    không xóa các key cũ khác.
    """
    old = {}  # <== QUAN TRỌNG: init sớm để tránh UnboundLocalError
    try:
        import joblib
        if os.path.exists(out_path):
            try:
                old = joblib.load(out_path)
            except Exception:
                old = {}
        if not isinstance(old, dict):
            old = {}
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        old.update(new_dict or {})
        joblib.dump(old, out_path)
    except Exception as e:
        print("joblib merge error:", e)


def _json_merge_map(out_path: str, new_map: dict):
    """
    Merge dict JSON: load cũ (nếu có) rồi update key-level bằng new_map.
    Không xóa key cũ khác nhóm.
    """
    old = {}  # <== init sớm
    try:
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8") as f:
                old = json.load(f)
                if not isinstance(old, dict):
                    old = {}
    except Exception:
        old = {}

    if isinstance(new_map, dict):
        for k, v in (new_map or {}).items():
            old[k] = v

    _safe_atomic_write_text(out_path, json.dumps(old, ensure_ascii=False, indent=2))


def _json_merge_groups(out_path: str, new_groups: dict):
    """
    Merge kiểu groups: { group: {users:[], source_ips:[], hosts:[]} }
    Các list sẽ được union (không trùng).
    """
    old = {}  # <== init sớm
    try:
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    old = loaded
    except Exception:
        pass

    old = old or {}
    for g, val in (new_groups or {}).items():
        tgt = old.get(g, {"users": [], "source_ips": [], "hosts": []})
        for key in ("users", "source_ips", "hosts"):
            s_old = set(tgt.get(key, []) or [])
            s_new = set((val or {}).get(key, []) or [])
            tgt[key] = sorted(s_old.union(s_new))
        old[g] = tgt

    _safe_atomic_write_text(out_path, json.dumps(old, ensure_ascii=False, indent=2))


def _detect_log_type_from_df(df: pd.DataFrame) -> str:
    """
    Phát hiện log_type từ DataFrame sau khi preprocess.
    Ưu tiên:
    1. Kiểm tra các cột đặc trưng (Channel, EventID, etc.)
    2. Kiểm tra message/content patterns để phân biệt Windows EventLog vs EDR Sysmon
    3. Kiểm tra program column
    4. Kiểm tra fields trong message
    """
    if df is None or df.empty:
        return None
    
    # Get message column
    message_col = None
    if "message" in df.columns:
        message_col = "message"
    elif "Message" in df.columns:
        message_col = "Message"
    
    # === LEVEL 1: Column Check (Most Reliable) ===
    # EDR has destination_ip column (network connection)
    if "destination_ip" in df.columns or "destination_port" in df.columns:
        return "edr"
    
    # Windows EventLog has special columns
    if "channel" in df.columns or "Channel" in df.columns or "EventID" in df.columns:
        return "windows_eventlog"
    
    # === LEVEL 2: Message Pattern Check (Distinguish Windows EventLog vs EDR Sysmon) ===
    if message_col is not None:
        sample = df[message_col].dropna().astype(str).head(50)
        sample_list = sample.tolist()
        
        # Check for EDR Sysmon pattern: "Sysmon: EventID=..." (without Host= at start)
        edr_hits = sum(1 for msg in sample_list if msg.lstrip().startswith("Sysmon:") or "Sysmon: EventID=" in msg)
        
        # Check for Windows EventLog pattern: "Host=... Channel=..." or "Host=... EventID=..."
        windows_hits = sum(1 for msg in sample_list if any(x in msg for x in ["Channel=", "EventID=", "TargetFilename="]) and ("Host=" in msg or "Image=" not in msg))
        
        threshold = max(3, len(sample_list) // 4)  # > 25% matches
        
        # EDR Sysmon has characteristic "Sysmon:" prefix
        if edr_hits >= threshold:
            return "edr"
        
        # Windows EventLog has "Host=" + Windows-specific fields
        if windows_hits >= threshold:
            return "windows_eventlog"
    
    # === LEVEL 3: Program Column Mapping (with EDR/Windows distinction) ===
    if "program" in df.columns:
        programs = df["program"].dropna().astype(str).str.lower().unique().tolist()
        
        # For "sysmon" program, need to check message content to distinguish
        if "sysmon" in programs:
            # Re-check message to see if it's EDR or Windows EventLog
            if message_col is not None:
                sample = df[message_col].dropna().astype(str).head(30)
                
                # EDR pattern: "Sysmon: EventID=3 ... Image=... DestinationIp=..."
                edr_indicators = sum(1 for msg in sample if ("DestinationIp=" in msg or "SrcIp=" in msg) and "Image=" in msg)
                
                # Windows pattern: "Host=... Channel=Sysmon" or key-value pairs with Channel
                windows_indicators = sum(1 for msg in sample if "Host=" in msg or "Channel=" in msg)
                
                if edr_indicators > windows_indicators and edr_indicators > 0:
                    return "edr"
                elif windows_indicators > edr_indicators and windows_indicators > 0:
                    return "windows_eventlog"
        
        # Standard program mapping
        log_type_map = {
            "firewall": "firewall",
            "router_ios": "router",
            "named": "dns",
            "dnsmasq": "dns",
            "winevent": "windows_eventlog",
            "security": "windows_eventlog",
            "system": "windows_eventlog",
            "sysmon": "windows_eventlog",  # ← Default: Sysmon is Windows Event Log channel (fallback if above checks fail)
            "dhcpd": "dhcp",
            "apache": "apache",
            "httpd": "apache",
            "squid": "proxy",
            "suricata": "ids",
            "edr_network": "edrnetwork",
            "edr_sysmon": "edr",
            "syslog": "syslog",
            # Linux/Unix programs
            "sshd": "linuxsyslog",
            "sudo": "linuxsyslog",
            "cron": "linuxsyslog",
            "kernel": "linuxsyslog",
            "systemd": "linuxsyslog",
            "auth": "linuxsyslog",
        }
        
        for prog in programs:
            for key, val in log_type_map.items():
                if key in prog:
                    return val
    
    # === LEVEL 4: Fallback Pattern Matching ===
    if message_col is not None:
        sample = df[message_col].dropna().astype(str).head(50)
        
        # Detect Linux syslog patterns
        syslog_hits = sum(1 for msg in sample if any(
            pattern in msg for pattern in ["sshd[", "sudo[", "cron[", "kernel:", "systemd["]
        ))
        if syslog_hits > len(sample) / 4:
            return "linuxsyslog"
        
        # Detect firewall patterns
        firewall_hits = sum(1 for msg in sample if "action=" in msg.lower() or "proto=" in msg.lower())
        if firewall_hits > len(sample) / 4:
            return "firewall"
        
        # Detect Apache patterns
        apache_hits = sum(1 for msg in sample if "GET " in msg or "POST " in msg or "HTTP/" in msg)
        if apache_hits > len(sample) / 4:
            return "apache"
    
    return None



# ===================== Baseline TRAIN endpoint (append/merge) =====================
@app.post("/baseline/train")
def baseline_train():
    """
    Train baseline và LƯU GỘP (append/merge) vào MongoDB (không tạo file).
    Tự động detect log_type từ file content.
    NOTE: config/baselines/ file creation is DISABLED - MongoDB is primary storage
    
    Hỗ trợ:
      - file | files (multipart)
      - form field 'group' (mặc định gán group nếu thiếu)
      - form field 'group_map' (JSON rule list) để map group theo source_ip/username
      - form field 'log_type' (optional: explicit override)
    """
    try:
        # Lazy imports
        try:
            from services.preprocess import preprocess_any
            from services.baseline import (
                build_user_baselines, build_device_baselines,
                build_group_baselines, build_global_baseline,
                apply_group_mapping, extract_group_membership
            )
            from services.database import (
                save_user_stats, save_device_stats, save_group_stats, save_global_stats,
                save_group_members, save_user_to_group, save_device_to_group
            )
            import joblib
        except Exception as ie:
            return jsonify({"ok": False, "error": f"Thiếu phụ thuộc để train baseline: {ie}"}), 500

        # === Nhận files ===
        files = request.files.getlist("files") or ([request.files.get("file")] if "file" in request.files else [])
        if not files or not files[0]:
            return jsonify({"ok": False, "error": "Thiếu file lịch sử để train"}), 400

        # === Tham số phân nhóm ===
        default_group = request.form.get("group")  # ví dụ "Sales"
        group_map_raw = request.form.get("group_map")
        group_rules = None
        if group_map_raw:
            try:
                group_rules = json.loads(group_map_raw)
                if not isinstance(group_rules, list):
                    group_rules = None
            except Exception:
                group_rules = None

        # === Detect log type from files (after preprocess) ===
        frames = []
        detected_type = None
        
        for f in files:
            try:
                _, df_part, _ = preprocess_any(f, filename=f.filename)
                frames.append(df_part)
                
                # Detect log type từ lần xử lý đầu tiên
                if detected_type is None:
                    detected_type = _detect_log_type_from_df(df_part)
            except Exception as fe:
                print("Baseline train: skip file due to error:", f.filename, fe)
        
        if not frames:
            return jsonify({"ok": False, "error": "Không đọc được dữ liệu hợp lệ"}), 400

        df_hist = pd.concat(frames, ignore_index=True, sort=False)
        df_hist = df_hist.dropna(subset=["timestamp"]).sort_values("timestamp")

        # Use explicit log_type from form if provided, else use detected, else default to generic
        log_type = request.form.get("log_type") or detected_type or "generic"
        print(f"Baseline train: log_type={log_type}, detected={detected_type}, rows={len(df_hist)}")

        # === Áp nhóm nếu người dùng truyền ===
        if default_group or group_rules:
            df_hist = apply_group_mapping(df_hist, rules=group_rules, default_group=default_group)

        # === Train ===
        user_stats, user_models = build_user_baselines(df_hist)
        device_stats, device_models = build_device_baselines(df_hist)
        # Group baseline (không raise dù thiếu cột)
        try:
            group_stats, group_models = build_group_baselines(df_hist, group_col="group", default_group=default_group)
        except Exception:
            group_stats, group_models = pd.DataFrame(), {}
        
        global_stats = build_global_baseline(df_hist)

        # === SAVE TO MONGODB (PRIMARY) ===
        mongo_success = False
        try:
            # Save statistics to MongoDB
            print(f"[MONGO] Saving baselines to MongoDB: log_type={log_type}")
            save_user_stats(user_stats, log_type=log_type)
            save_device_stats(device_stats, log_type=log_type)
            save_group_stats(group_stats, log_type=log_type)
            save_global_stats(global_stats, log_type=log_type)
            
            # Save member/group data to MongoDB
            print(f"[MONGO] Saving member mappings to MongoDB")
            members = extract_group_membership(df_hist, group_col="group")
            save_group_members(members.get("groups", {}), log_type=log_type)
            save_user_to_group(members.get("user_to_group", {}), log_type=log_type)
            save_device_to_group(members.get("device_to_group", {}), log_type=log_type)
            
            print(f"[MONGO] Successfully saved baselines to MongoDB")
            mongo_success = True
            
        except Exception as db_error:
            print(f"[MONGO] Warning: Failed to save to MongoDB: {db_error}")
            import traceback
            print("Traceback:", traceback.format_exc())

        # === BACKUP TO FILES (SECONDARY - config/baselines/) ===
        backup_success = False
        try:
            print(f"[BACKUP] Creating backup files in config/baselines/")
            base_root = os.path.join(os.path.dirname(__file__), "config", "baselines")
            out_dir = base_root
            os.makedirs(out_dir, exist_ok=True)
            
            # 1) USER STATS (merge theo 'username')
            user_stats_path = os.path.join(out_dir, "user_stats.json")
            old_user = _safe_load_json_df(user_stats_path)
            if "username" not in user_stats.columns:
                user_stats = user_stats.copy()
                user_stats["username"] = "(unknown)"
            merged_user = _merge_by_key(old_user, user_stats, key_col="username")
            _safe_atomic_write_text(user_stats_path, merged_user.to_json(orient="records", force_ascii=False))
            print(f"[BACKUP]   ✓ user_stats.json ({len(merged_user)} records)")
            
            # 2) DEVICE STATS (merge theo 'host' nếu có, else 'source_ip', else append)
            device_stats_path = os.path.join(out_dir, "device_stats.json")
            old_dev = _safe_load_json_df(device_stats_path)
            dev_key = "host" if "host" in device_stats.columns else ("source_ip" if "source_ip" in device_stats.columns else None)
            if dev_key:
                merged_dev = _merge_by_key(old_dev, device_stats, key_col=dev_key)
            else:
                merged_dev = pd.concat([old_dev, device_stats], ignore_index=True)
            _safe_atomic_write_text(device_stats_path, merged_dev.to_json(orient="records", force_ascii=False))
            print(f"[BACKUP]   ✓ device_stats.json ({len(merged_dev)} records)")
            
            # 3) GROUP STATS (merge theo 'group')
            group_stats_path = os.path.join(out_dir, "group_stats.json")
            old_group = _safe_load_json_df(group_stats_path)
            if not group_stats.empty:
                if "group" not in group_stats.columns:
                    if "department" in group_stats.columns:
                        group_stats = group_stats.rename(columns={"department": "group"})
                    else:
                        group_stats = group_stats.copy()
                        group_stats["group"] = "(unknown)"
                merged_group = _merge_by_key(old_group, group_stats, key_col="group")
            else:
                merged_group = old_group
            _safe_atomic_write_text(group_stats_path, merged_group.to_json(orient="records", force_ascii=False))
            print(f"[BACKUP]   ✓ group_stats.json ({len(merged_group)} records)")
            
            # 4) GLOBAL BASELINE (append snapshot)
            global_path = os.path.join(out_dir, "global_baseline.json")
            _append_global_snapshot(global_path, global_stats)
            print(f"[BACKUP]   ✓ global_baseline.json")
            
            # 5) MODELS (update dict, không xoá model cũ)
            _joblib_merge_dict(os.path.join(out_dir, "user_models.joblib"),   user_models)
            _joblib_merge_dict(os.path.join(out_dir, "device_models.joblib"), device_models)
            _joblib_merge_dict(os.path.join(out_dir, "group_models.joblib"),  group_models)
            print(f"[BACKUP]   ✓ user/device/group_models.joblib")
            
            # 6) MEMBERSHIP EXPORT (ai thuộc nhóm nào)
            members = extract_group_membership(df_hist, group_col="group")
            members_dir = os.path.join(out_dir, "members")
            os.makedirs(members_dir, exist_ok=True)
            _json_merge_groups(os.path.join(members_dir, "group_members.json"), members.get("groups", {}))
            _json_merge_map(os.path.join(members_dir, "user_to_group.json"),   members.get("user_to_group", {}))
            _json_merge_map(os.path.join(members_dir, "device_to_group.json"), members.get("device_to_group", {}))
            print(f"[BACKUP]   ✓ group_members/user_to_group/device_to_group.json")
            
            print(f"[BACKUP] ✓ Successfully created backup files")
            backup_success = True
            
        except Exception as backup_error:
            print(f"[BACKUP] ⚠ Warning: Failed to create backup files: {backup_error}")
            import traceback
            print("Traceback:", traceback.format_exc())

        # === RETURN STATUS ===
        status_msg = []
        if mongo_success:
            status_msg.append("MongoDB: ✓")
        else:
            status_msg.append("MongoDB: ⚠")
        
        if backup_success:
            status_msg.append("Backup: ✓")
        else:
            status_msg.append("Backup: ⚠")

        return jsonify({
            "ok": mongo_success,  # Consider it OK only if MongoDB save succeeded
            "rows": int(len(df_hist)),
            "log_type": log_type,
            "storage": "MongoDB Atlas (Primary) + config/baselines/ (Backup)",
            "status": " | ".join(status_msg),
            "message": "Baseline trained and saved to MongoDB (and backed up to files)"
        })

    except Exception as e:
        import traceback
        print("Baseline train error:", repr(e))
        print("Traceback:", traceback.format_exc())
        return jsonify({"ok": False, "error": f"Baseline train lỗi: {e}"}), 500


# ===================== Membership viewer (DISABLED - config/baselines/ no longer created) =====================
# @app.get("/baseline/groups")
# def baseline_groups():
#     """
#     Xem nhanh membership đã lưu: group_members / user_to_group / device_to_group
#     DISABLED: Tất cả baselines bây giờ được lưu trong MongoDB, không phải config/baselines/
#     """
#     try:
#         base_root = os.path.join(os.path.dirname(__file__), "config", "baselines")
#         
#         out = {}
#         members_dir = os.path.join(base_root, "members")
#         
#         for name in ["group_members.json", "user_to_group.json", "device_to_group.json"]:
#             p = os.path.join(members_dir, name)
#             if os.path.exists(p):
#                 with open(p, "r", encoding="utf-8") as f:
#                     out[name] = json.load(f)
#             else:
#                 out[name] = None
#         
#         # Also show baseline files info
#         out["baseline_files"] = []
#         for fname in ["user_stats.json", "device_stats.json", "group_stats.json", "global_baseline.json"]:
#             fpath = os.path.join(base_root, fname)
#             if os.path.exists(fpath):
#                 out["baseline_files"].append(fname)
#         
#         return jsonify({"ok": True, "baselines_location": f"config/baselines/", **out})
#     except Exception as e:
#         return jsonify({"ok": False, "error": str(e)}), 500


# ===================== Baseline Members Endpoint =====================

@app.get("/baseline/members")
def baseline_members():
    """
    Lấy member/group mapping từ MongoDB.
    Query params: ?log_type=linuxsyslog (mặc định: generic)
    """
    try:
        from services.database import (
            load_group_members, load_user_to_group, load_device_to_group,
            group_members_col, user_to_group_col, device_to_group_col
        )
        
        log_type = request.args.get("log_type", "generic")
        
        # Load từ MongoDB
        group_members = load_group_members(log_type=log_type)
        user_to_group = load_user_to_group(log_type=log_type)
        device_to_group = load_device_to_group(log_type=log_type)
        
        status = {
            "log_type": log_type,
            "timestamp": datetime.utcnow().isoformat(),
            "collections": {
                "group_members": group_members_col.count_documents({"log_type": log_type}),
                "user_to_group": user_to_group_col.count_documents({"log_type": log_type}),
                "device_to_group": device_to_group_col.count_documents({"log_type": log_type})
            },
            "data": {
                "group_members": group_members,
                "user_to_group": user_to_group,
                "device_to_group": device_to_group
            }
        }
        
        return jsonify(status)
        
    except Exception as e:
        import traceback
        print(f"Error loading baseline members: {e}")
        print(traceback.format_exc())
        return jsonify({
            "error": f"Failed to load baseline members: {e}",
            "timestamp": datetime.utcnow().isoformat()
        }), 500


# ===================== Baseline Status Endpoint =====================

@app.get("/baseline/status")
def baseline_status():
    """
    Kiểm tra status và số bản ghi trong MongoDB Atlas.
    Returns: số lượng document trong từng collection (user_stats, device_stats, group_stats, global_stats)
    """
    try:
        from services.database import (
            user_stats_col, device_stats_col, group_stats_col, global_stats_col,
            group_members_col, user_to_group_col, device_to_group_col
        )
        
        status = {
            "connection": "Connected to MongoDB",
            "database": "log_analysis",
            "collections": {
                "user_stats": user_stats_col.count_documents({}),
                "device_stats": device_stats_col.count_documents({}),
                "group_stats": group_stats_col.count_documents({}),
                "global_stats": global_stats_col.count_documents({}),
                "group_members": group_members_col.count_documents({}),
                "user_to_group": user_to_group_col.count_documents({}),
                "device_to_group": device_to_group_col.count_documents({})
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Sample documents
        user_sample = user_stats_col.find_one()
        device_sample = device_stats_col.find_one()
        group_sample = group_stats_col.find_one()
        global_sample = global_stats_col.find_one()
        
        status["samples"] = {
            "user_stats_sample": _json_safe(user_sample) if user_sample else None,
            "device_stats_sample": _json_safe(device_sample) if device_sample else None,
            "group_stats_sample": _json_safe(group_sample) if group_sample else None,
            "global_stats_sample": _json_safe(global_sample) if global_sample else None,
        }
        
        return jsonify(status)
        
    except Exception as e:
        import traceback
        print(f"Error checking baseline status: {e}")
        print(traceback.format_exc())
        return jsonify({
            "error": f"Failed to check baseline status: {e}",
            "timestamp": datetime.utcnow().isoformat()
        }), 500


# ==================== Alert Endpoints ====================

@app.route('/send-analysis-alerts', methods=['POST'])
def send_analysis_alerts():
    """
    Gửi alerts từ analysis results tới N8N, Telegram, Zalo
    
    Request JSON:
    {
        "results": [
            {
                "subject": "user/ip",
                "alert_type": "privilege_escalation_detected",
                "risk_level": "Cực kỳ nguy cấp",
                "score": 9.0,
                "summary": "...",
                "risk": "...",
                "action": "...",
                "alert_count": 4
            }
        ]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'results' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required field: results'
            }), 400
        
        alert_service = get_alert_sender_service()
        results = alert_service.send_analysis_alerts(data['results'])
        
        return jsonify({
            'status': 'success',
            'message': 'Alerts sent to N8N, Telegram, Zalo',
            'details': results
        }), 200
        
    except Exception as e:
        print(f"Error in send_analysis_alerts: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/send-raw-anomalies', methods=['POST'])
def send_raw_anomalies():
    """
    Gửi raw anomaly alerts tới N8N, Telegram, Zalo
    
    Request JSON:
    {
        "anomalies": [
            {
                "severity": "CRITICAL",
                "alert_type": "privilege_escalation_detected",
                "subject": "user/ip",
                "details": {...}
            }
        ]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'anomalies' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required field: anomalies'
            }), 400
        
        alert_service = get_alert_sender_service()
        results = alert_service.send_raw_anomaly_alerts(data['anomalies'])
        
        return jsonify({
            'status': 'success',
            'message': 'Raw anomalies sent to all channels',
            'details': results
        }), 200
        
    except Exception as e:
        print(f"Error in send_raw_anomalies: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/send-telegram', methods=['POST'])
def send_telegram():
    """
    Gửi message tới Telegram
    
    Request JSON:
    {
        "message": "Nội dung tin nhắn",
        "severity": "CRITICAL|WARNING|INFO"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required field: message'
            }), 400
        
        alert_service = get_alert_sender_service()
        result = alert_service.send_to_telegram(
            data['message'],
            data.get('severity', 'INFO')
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error in send_telegram: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/send-zalo', methods=['POST'])
def send_zalo():
    """
    Gửi message tới Zalo
    
    Request JSON:
    {
        "message": "Nội dung tin nhắn",
        "severity": "CRITICAL|WARNING|INFO"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required field: message'
            }), 400
        
        alert_service = get_alert_sender_service()
        result = alert_service.send_to_zalo(
            data['message'],
            data.get('severity', 'INFO')
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error in send_zalo: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)