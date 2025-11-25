# services/validator.py
import pandas as pd

def basic_validate_df(df: pd.DataFrame):
    issues = []
    info = {}

    cols = {c.lower(): c for c in df.columns}
    has_ts = "timestamp" in cols or "time" in cols or "@timestamp" in cols
    ts_col = cols.get("timestamp") or cols.get("time") or cols.get("@timestamp")

    if not has_ts:
        issues.append("Thiếu cột timestamp/time/@timestamp.")
    else:
        s = pd.to_datetime(df[ts_col], errors="coerce")
        bad = s.isna().sum()
        if bad > 0:
            issues.append(f"{bad} dòng không parse được thời gian.")
        info["time_range"] = (str(s.min()), str(s.max()))

    # tỉ lệ null các cột quan trọng
    for k in ["message","source_ip","username","action","status"]:
        if k in cols:
            nulls = df[cols[k]].isna().sum()
            if nulls > 0:
                issues.append(f"Cột {k}: {nulls} giá trị trống.")
    info["rows"] = len(df)
    info["columns"] = list(df.columns)
    return {"ok": len(issues)==0, "issues": issues, "info": info}
