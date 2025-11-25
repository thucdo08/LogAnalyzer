import pandas as pd
from ipaddress import ip_address
from .alert import send_slack

def _is_private(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except Exception:
        return False

def postprocess(df_ai: pd.DataFrame, df_log: pd.DataFrame, df_ctx: pd.DataFrame = None):
    """
    Hậu xử lý kết quả AI:
      - Nâng cấp theo burst failed/phút (tính trên df_ctx gốc chưa dedup)
      - Nâng CRITICAL cho success từ IP public trong 2 phút sau failed cùng IP/user
      - Gửi Slack cho CRITICAL (nếu cấu hình)
      - Trả về:
          df_final: df_log (đã lọc/dedup/enrich) + [level, summary, suggestion, level_upgraded, upgrade_reason]
          summary_series: value_counts của level_upgraded
    """

    # --- ÉP KIỂU AN TOÀN, TRÁNH BOOL-AMBIGUOUS ---
    if df_ai is None or not isinstance(df_ai, pd.DataFrame):
        df_ai = pd.DataFrame()
    if df_log is None or not isinstance(df_log, pd.DataFrame):
        df_log = pd.DataFrame()
    if df_ctx is not None and not isinstance(df_ctx, pd.DataFrame):
        df_ctx = None

    df_ai = df_ai.reset_index(drop=True).copy()
    df_log = df_log.reset_index(drop=True).copy()

    for c in ["level", "summary", "suggestion"]:
        if c not in df_ai.columns:
            df_ai[c] = pd.Series(dtype="object")

    # Cột nâng cấp & lý do
    df_ai["level_upgraded"] = df_ai["level"].astype(str).str.upper()
    if "upgrade_reason" not in df_ai.columns:
        df_ai["upgrade_reason"] = ""

    # ===== 1) BURST FAILED / MIN (tính trên df_ctx nếu có, else df_log) =====
    base = df_ctx.copy() if df_ctx is not None else df_log.copy()

    if "timestamp" not in base.columns:
        base["timestamp"] = pd.NaT
    base["minute"] = pd.to_datetime(base["timestamp"], errors="coerce").dt.floor("min")

    if "status" in base.columns:
        failed_mask = base["status"].astype(str).str.lower().eq("failed")
    else:
        failed_mask = pd.Series([False] * len(base), index=base.index)

    warn_ips, crit_ips = set(), set()
    if len(base) > 0 and failed_mask.any():
        burst = (
            base.loc[failed_mask]
                .groupby(["source_ip", "username", "minute"])
                .size()
                .reset_index(name="fails")
        )
        warn_ips = set(burst.loc[burst["fails"] >= 3, "source_ip"])
        crit_ips = set(burst.loc[burst["fails"] >= 5, "source_ip"])

    # Áp dụng burst NÂNG CHỈ cho dòng status=failed
    for i in df_ai.index:
        ip = ""
        status_lower = ""
        if i in df_log.index:
            if "source_ip" in df_log.columns:
                ip = str(df_log.loc[i, "source_ip"])
            if "status" in df_log.columns:
                status_lower = str(df_log.loc[i, "status"]).lower()

        if status_lower == "failed":
            if ip in crit_ips and df_ai.loc[i, "level_upgraded"] != "CRITICAL":
                df_ai.loc[i, "level_upgraded"] = "CRITICAL"
                df_ai.loc[i, "upgrade_reason"] = "burst_failed>=5"
            elif ip in warn_ips and df_ai.loc[i, "level_upgraded"] == "INFO":
                df_ai.loc[i, "level_upgraded"] = "WARNING"
                df_ai.loc[i, "upgrade_reason"] = "burst_failed>=3"

    # ===== 2) SUCCESS sau FAILED từ IP public trong 2 phút =====
    needed = {"timestamp", "source_ip", "username", "status"}
    if needed.issubset(set(base.columns)):
        seq = base[list(needed)].copy()
        seq["timestamp"] = pd.to_datetime(seq["timestamp"], errors="coerce")

        for i in df_ai.index:
            if i not in df_log.index:
                continue
            if "status" not in df_log.columns:
                continue
            if str(df_log.loc[i, "status"]).lower() != "success":
                continue

            ip = str(df_log.loc[i, "source_ip"]) if "source_ip" in df_log.columns else ""
            if _is_private(ip):
                continue

            t = pd.to_datetime(df_log.loc[i, "timestamp"], errors="coerce") if "timestamp" in df_log.columns else pd.NaT
            user = str(df_log.loc[i, "username"]) if "username" in df_log.columns else ""
            if pd.isna(t):
                continue

            recent_failed = seq[
                (seq["status"].astype(str).str.lower() == "failed")
                & (seq["source_ip"] == ip)
                & (seq["username"] == user)
                & (seq["timestamp"] >= t - pd.Timedelta(minutes=2))
                & (seq["timestamp"] < t)
            ]
            if len(recent_failed) >= 1:
                df_ai.loc[i, "level_upgraded"] = "CRITICAL"
                df_ai.loc[i, "upgrade_reason"] = "success_after_failed_public_ip"

    # ===== 3) GỬI CẢNH BÁO CRITICAL (không làm vỡ pipeline nếu lỗi) =====
    try:
        crit_rows = df_ai.index[df_ai["level_upgraded"] == "CRITICAL"]
        for i in crit_rows:
            summary = str(df_ai.loc[i, "summary"])
            suggestion = str(df_ai.loc[i, "suggestion"])
            reason = str(df_ai.loc[i, "upgrade_reason"] or "")
            msg = f"[CRITICAL] {summary}\nGợi ý: {suggestion}"
            if reason:
                msg += f"\nLý do: {reason}"
            send_slack(msg)
    except Exception:
        pass

    # ===== 4) HỢP NHẤT & THỐNG KÊ =====
    keep = ["level", "summary", "suggestion", "level_upgraded", "upgrade_reason"]
    df_ai = df_ai.reindex(columns=keep)
    df_final = pd.concat([df_log.reset_index(drop=True), df_ai.reset_index(drop=True)], axis=1)

    if "collapsed_count" not in df_final.columns:
        df_final["collapsed_count"] = 1

    summary_series = df_final["level_upgraded"].value_counts(dropna=True)
    return df_final, summary_series

def sessionize(df: pd.DataFrame, by=("source_ip", "username"), gap="15min") -> pd.DataFrame:
    if df.empty or not set(by).issubset(df.columns) or "timestamp" not in df.columns:
        return df
    out = df.sort_values("timestamp").copy()
    out["__diff"] = out.groupby(list(by))["timestamp"].diff().gt(pd.Timedelta(gap)).fillna(True)
    out["__grp"] = out.groupby(list(by))["__diff"].cumsum()
    out["session_id"] = out[list(by)].astype(str).agg("-".join, axis=1) + "-" + out["__grp"].astype(str)
    return out.drop(columns=["__diff", "__grp"])