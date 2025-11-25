# backend/services/analyzer.py
import os
import json
from typing import List, Dict, Tuple
import pandas as pd

import re

# ---------- Heuristic fallback (đơn giản, đủ chạy khi không có API key) ----------
CRIT_KWS = ["kernel panic", "panic:", "segfault", "oops", "oom-killer", "out of memory"]
WARN_KWS = ["error", "failed", "timeout", "retry", "throttle", "denied"]

def _heuristic_analyze(logs):
    out = []
    for i, log in enumerate(logs, 1):
        s = str(log).lower()
        if any(k in s for k in CRIT_KWS):
            level = "CRITICAL"
            summary = "Critical system error detected."
            suggestion = "Inspect system immediately (dmesg/syslog), mitigate impact."
        elif any(k in s for k in WARN_KWS):
            level = "WARNING"
            summary = "Warning/error observed."
            suggestion = "Investigate root cause; check recent changes/hardware."
        else:
            level = "INFO"
            summary = "No critical anomaly."
            suggestion = "No action."
        out.append({"log_index": i, "level": level, "summary": summary, "suggestion": suggestion})
    return out

# ---------- OpenAI client factory (SDK v1.x). KHÔNG truyền proxies= vào OpenAI(...) ----------
def _make_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
        import httpx
        proxy = (os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
                 or os.getenv("https_proxy") or os.getenv("http_proxy"))
        if proxy:
            http_client = httpx.Client(proxies=proxy, timeout=30.0)
            return OpenAI(api_key=api_key, http_client=http_client)
        return OpenAI(api_key=api_key)
    except Exception as e:
        print(f"⚠️ Cannot construct OpenAI client: {e}")
        return None

# ---------- HÀM CHÍNH: gọi AI, trả items ----------
def analyze_logs_with_openai(logs):
    """
    Input:  logs -> list[str] (mỗi phần tử là 1 dòng log đã chuẩn hoá)
    Output: (items, used_openai: bool)
            items = [{log_index, level, summary, suggestion}, ...]
    """
    # Trường hợp không có dữ liệu
    if not logs:
        return ([], False)

    client = _make_openai_client()
    if client is None:
        print("🔎 OPENAI_API_KEY missing or client init failed → heuristic.")
        return (_heuristic_analyze(logs), False)

    try:
        # Đánh số để model refer đúng dòng
        numbered = [f"Log {i+1}: {t}" for i, t in enumerate(logs)]

        schema = {
            "name": "log_array",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "log_index":  {"type": "integer"},
                                "level":      {"type": "string", "enum": ["INFO","WARNING","CRITICAL"]},
                                "summary":    {"type": "string"},
                                "suggestion": {"type": "string"}
                            },
                            "required": ["log_index","level","summary","suggestion"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["items"],
                "additionalProperties": False
            }
        }

        prompt = (
            "You are a security analyst. For each log line, classify severity (INFO|WARNING|CRITICAL), "
            "write a short summary (with port) and a concrete suggestion. Respond ONLY with JSON matching the schema.\n\n"
            + "\n".join(numbered)
        )

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={"type": "json_schema", "json_schema": schema},
        )

        content = resp.choices[0].message.content
        # Parse JSON an toàn (nếu có rác trắng)
        try:
            data = json.loads(content)
        except Exception:
            # fallback: cố lấy phần {...} lớn nhất
            start = content.find("{")
            end = content.rfind("}")
            data = json.loads(content[start:end+1])

        items = data.get("items", [])
        # Bảo vệ: nếu model trả thiếu/sai, tự sửa để không vỡ pipeline
        if not isinstance(items, list) or not items:
            items = []
        # Đảm bảo log_index tồn tại & đúng range 1..N
        n = len(logs)
        fixed = []
        for i, it in enumerate(items or []):
            try:
                idx = int(it.get("log_index", i+1))
            except Exception:
                idx = i + 1
            if idx < 1 or idx > n:
                idx = i + 1
            level = str(it.get("level","INFO")).upper()
            if level not in ("INFO","WARNING","CRITICAL"):
                level = "INFO"
            fixed.append({
                "log_index": idx,
                "level": level,
                "summary": it.get("summary") or "No critical anomaly.",
                "suggestion": it.get("suggestion") or "No action."
            })

        # Nếu sau khi fix vẫn rỗng (model lỗi), dùng heuristic
        if not fixed:
            fixed = _heuristic_analyze(logs)

        return (fixed, True)

    except Exception as e:
        print(f"⚠️ OpenAI call failed → heuristic. Error: {e}")
        return (_heuristic_analyze(logs), False)


def summarize_levels(results: List[Dict]) -> Dict[str, int]:
    ser = pd.Series([r["level"] for r in results])
    counts = ser.value_counts().to_dict()
    return counts


def build_detailed_prompt_from_alert(alert: Dict) -> str:
    """
    Build a detailed Vietnamese prompt from raw anomaly alert with context.
    """
    alert_type = alert.get("type", "unknown")
    subject = alert.get("subject", "N/A")
    text = alert.get("text", "")
    ctx = alert.get("prompt_ctx", {})
    
    user = ctx.get("user")
    group = ctx.get("group")
    behavior = ctx.get("behavior", {})
    time_str = ctx.get("time")
    baseline = ctx.get("baseline", {})
    evidence = alert.get("evidence", {})
    
    prompt = "Phân tích sự kiện bất thường sau:\n\n"
    
    if user:
        prompt += f"- Người dùng: {user}"
        if group:
            prompt += f" (Phòng ban: {group})"
        prompt += "\n"
    
    # Chi tiết hành vi theo loại
    if alert_type == "new_user":
        events = evidence.get("events", 0)
        prompt += f"- Hành vi: Người dùng MỚI xuất hiện trong hệ thống với {events} sự kiện.\n"
    elif alert_type == "foreign_country_access":
        countries = evidence.get("countries", [])
        events = evidence.get("events", 0)
        prompt += f"- Hành vi: Truy cập từ các quốc gia nước ngoài: {', '.join(countries)} ({events} sự kiện).\n"
    elif alert_type == "off_hours_access":
        hours = evidence.get("hours", [])
        events = evidence.get("events", 0)
        prompt += f"- Hành vi: Truy cập ngoài giờ làm việc vào lúc {hours}h ({events} sự kiện).\n"
    
    if time_str:
        prompt += f"- Thời gian: {time_str}.\n"
    
    # Baseline info
    if baseline:
        if alert_type == "new_user":
            prompt += f"- Dữ liệu cơ sở: Người dùng không tồn tại trong hệ thống quản lý.\n"
        elif alert_type == "off_hours_access":
            working_hours = baseline.get("working_hours", "6h-22h")
            prompt += f"- Dữ liệu cơ sở: Giờ làm việc bình thường là {working_hours}.\n"
        elif alert_type == "foreign_country_access":
            prompt += f"- Dữ liệu cơ sở: Người dùng thường chỉ truy cập từ Việt Nam.\n"
    
    # Risk score
    severity = alert.get("severity", "WARNING")
    score = alert.get("score", 0)
    prompt += f"- Mức độ cảnh báo: {severity} (Điểm: {score:.1f}).\n"
    
    prompt += (
        "\nYêu cầu phân tích:\n"
        "1. Tóm tắt sự kiện một cách súc tích.\n"
        "2. Liệt kê các chỉ số rủi ro tiềm ẩn.\n"
        "3. Đánh giá mức độ rủi ro (Thấp/Trung bình/Cao/Cực kỳ nguy cấp).\n"
        "4. Đề xuất hành động cụ thể (Giám sát thêm, Xác minh danh tính, Tạm khóa tài khoản, v.v.).\n"
        "Trả lời CHỈ bằng JSON."
    )
    
    return prompt


def analyze_alert_prompt(prompt: str) -> Tuple[Dict, bool]:
    """
    Given a detailed Vietnamese prompt for a single alert, ask the model to return structured risk analysis.
    Output: ({summary, risks, risk_level, actions}, used_openai)
    """
    client = _make_openai_client()
    if client is None:
        # Heuristic fallback
        return ({
            "summary": "Không thể gọi AI. Đề xuất giám sát thêm.",
            "risks": ["Thiếu ngữ cảnh mô hình"],
            "risk_level": "Trung bình",
            "actions": ["Giám sát thêm"],
        }, False)

    schema = {
        "name": "risk_report",
        "schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "risks": {"type": "array", "items": {"type": "string"}},
                "risk_level": {"type": "string", "enum": ["Thấp","Trung bình","Cao","Cực kỳ nguy cấp"]},
                "actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary","risks","risk_level","actions"],
            "additionalProperties": False,
        }
    }

    msg = (
        prompt
        + "\n\nHãy trả lời CHỈ bằng JSON đúng schema."
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": msg}],
            temperature=0,
            response_format={"type": "json_schema", "json_schema": schema},
        )
        content = resp.choices[0].message.content
        import json
        try:
            data = json.loads(content)
        except Exception:
            start = content.find("{")
            end = content.rfind("}")
            data = json.loads(content[start:end+1])
        return (data, True)
    except Exception as e:
        print(f"⚠️ analyze_alert_prompt failed: {e}")
        return ({
            "summary": "Lỗi khi gọi AI.",
            "risks": ["Không phân tích được"],
            "risk_level": "Trung bình",
            "actions": ["Giám sát thêm"],
        }, False)