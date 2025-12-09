# backend/services/baseline.py
# --------------------------------------------
# Baseline cá nhân / thiết bị / NHÓM / TOÀN CỤC
# - Cung cấp model IsolationForest cho từng entity (user/device/group)
# - Cung cấp thống kê toàn cục để áp các rule kiểu "upload > 1GB/h"
# --------------------------------------------

from __future__ import annotations

import re
import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Any

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ---------- Tiện ích chung ----------

def _ensure_ts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Đảm bảo có cột timestamp (UTC, tz-aware) và không NaT.
    """
    if "timestamp" not in df.columns:
        raise ValueError("DataFrame must contain 'timestamp' column for baseline building")
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.dropna(subset=["timestamp"]).reset_index(drop=True)
    return out


def _safe_col(df: pd.DataFrame, name: str) -> pd.Series:
    """
    Truy cập cột an toàn: nếu không tồn tại trả về Series None có cùng chiều dài.
    """
    return df[name] if name in df.columns else pd.Series([None] * len(df), index=df.index)


# ---------- Trích đặc trưng theo NGƯỜI DÙNG ----------

def _daily_user_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate per-user-per-day features robustly (presence-optional columns).
    Trả về DataFrame index (username, date) với numeric features.
    """
    df = df.copy()
    # Chuẩn hóa user
    users = _safe_col(df, "username").astype(str)
    users = users.where(users.str.len() > 0, other="(unknown)")
    df["username"] = users

    # Ngày (UTC)
    df["date"] = df["timestamp"].dt.tz_convert("UTC").dt.date

    # Tín hiệu/feature (tự chịu lỗi thiếu cột)
    is_login = (_safe_col(df, "action").astype(str).str.lower() == "login")
    is_failed = (_safe_col(df, "status").astype(str).str.lower() == "failed")
    is_ssh = _safe_col(df, "program").astype(str).str.contains("ssh", case=False, na=False)
    http_status = pd.to_numeric(_safe_col(df, "http_status"), errors="coerce")

    grp = df.groupby(["username", "date"], dropna=False)

    def _count_login_fail(g: pd.DataFrame) -> int:
        a = g.get("action", pd.Series(index=g.index)).astype(str).str.lower()
        s = g.get("status", pd.Series(index=g.index)).astype(str).str.lower()
        return int(((a == "login") & (s == "failed")).sum())

    def _count_ssh_events(g: pd.DataFrame) -> int:
        prog = g.get("program", pd.Series(index=g.index)).astype(str)
        return int(prog.str.contains("ssh", case=False, na=False).sum())

    def _count_http_4xx(g: pd.DataFrame) -> int:
        hs = pd.to_numeric(g.get("http_status", pd.Series(index=g.index)), errors="coerce")
        return int(hs.between(400, 499).sum())

    def _count_http_5xx(g: pd.DataFrame) -> int:
        hs = pd.to_numeric(g.get("http_status", pd.Series(index=g.index)), errors="coerce")
        return int(hs.between(500, 599).sum())

    feat = pd.DataFrame({
        "events": grp.size(),
        "unique_src_ips": grp["source_ip"].nunique(dropna=True) if "source_ip" in df.columns else 0,
        "login_fail": grp.apply(_count_login_fail),
        "ssh_events": grp.apply(_count_ssh_events),
        "http_4xx": grp.apply(_count_http_4xx),
        "http_5xx": grp.apply(_count_http_5xx),
    })

    for c in feat.columns:
        feat[c] = pd.to_numeric(feat[c], errors="coerce").fillna(0).astype(int)

    return feat


def _user_hour_profile(df: pd.DataFrame) -> pd.DataFrame:
    """
    Thống kê giờ hoạt động của user (p10/p90).
    """
    df = df.copy()
    df["hour"] = df["timestamp"].dt.tz_convert("UTC").dt.hour

    users = _safe_col(df, "username").astype(str)
    users = users.where(users.str.len() > 0, other="(unknown)")
    df["username"] = users

    grp = df.groupby("username")
    prof = grp["hour"].agg([
        "count", "mean", "std",
        (lambda s: s.quantile(0.1)),
        (lambda s: s.quantile(0.9))
    ])
    prof = prof.rename(columns={"<lambda_0>": "p10", "<lambda_1>": "p90", "count": "events"})
    return prof.reset_index()


# ---------- Isolation Forest model ----------

@dataclass
class EntityModel:
    scaler: StandardScaler
    model: IsolationForest
    features: Tuple[str, ...]


def _fit_isolation_forest(feat_df: pd.DataFrame) -> Optional[EntityModel]:
    """
    Train IsolationForest trên các cột số trong feat_df.
    """
    if feat_df is None or feat_df.empty:
        return None
    # Loại cột key (username/date/group/... nếu có)
    drop_keys = [c for c in ("username", "date", "group", "department") if c in feat_df.columns]
    Xcols = [c for c in feat_df.columns if c not in drop_keys]
    if not Xcols:
        return None

    X = feat_df[Xcols].astype(float).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit(Xs)
    return EntityModel(scaler=scaler, model=model, features=tuple(Xcols))


def _score_isolation_forest(model: EntityModel, feat_row: pd.Series) -> float:
    """
    Đổi score_samples (cao = bình thường) thành anomaly_score (cao = bất thường).
    """
    x = feat_row[model.features].astype(float).values.reshape(1, -1)
    xs = model.scaler.transform(x)
    return -float(model.model.score_samples(xs)[0])


# ---------- Baseline THEO NGƯỜI DÙNG ----------

def build_user_baselines(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, EntityModel]]:
    """
    Trả về:
      - user_stats: thống kê theo user (mean/std các đặc trưng theo ngày + profile giờ)
      - user_models: dict username -> IsolationForest
    """
    df = _ensure_ts(df)
    daily = _daily_user_features(df)

    ug = daily.groupby(level=0)
    user_stats = ug.agg(["mean", "std"]).fillna(0)
    user_stats.columns = [f"{a}_{b}" for a, b in user_stats.columns]
    user_stats = user_stats.reset_index().rename(columns={"index": "username"})

    hours = _user_hour_profile(df)
    user_stats = user_stats.merge(hours, on="username", how="left", suffixes=("", "_hour"))

    user_models: Dict[str, EntityModel] = {}
    for username, d in daily.reset_index().groupby("username"):
        m = _fit_isolation_forest(d.drop(columns=["username"]))
        if m is not None:
            user_models[str(username)] = m

    return user_stats, user_models


# ---------- Baseline THEO THIẾT BỊ / HOST / IP ----------

def _daily_device_features(df: pd.DataFrame, device_col: str) -> pd.DataFrame:
    df = df.copy()
    df["date"] = df["timestamp"].dt.tz_convert("UTC").dt.date

    grp = df.groupby([device_col, "date"], dropna=False)

    def _count_http_5xx(g: pd.DataFrame) -> int:
        hs = pd.to_numeric(g.get("http_status", pd.Series(index=g.index)), errors="coerce")
        return int(hs.between(500, 599).sum())

    feat = pd.DataFrame({
        "events": grp.size(),
        "unique_users": grp["username"].nunique(dropna=True) if "username" in df.columns else 0,
        "unique_src_ips": grp["source_ip"].nunique(dropna=True) if "source_ip" in df.columns else 0,
        "http_5xx": grp.apply(_count_http_5xx),
    })
    for c in feat.columns:
        feat[c] = pd.to_numeric(feat[c], errors="coerce").fillna(0).astype(int)
    return feat


def build_device_baselines(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, EntityModel]]:
    """
    Model theo 'host' nếu có, nếu không dùng 'source_ip'.
    Trả về device_stats, device_models.
    """
    df = _ensure_ts(df)
    device_col = "host" if "host" in df.columns else "source_ip"
    dv = _daily_device_features(df, device_col=device_col)

    dg = dv.groupby(level=0)
    device_stats = dg.agg(["mean", "std"]).fillna(0)
    device_stats.columns = [f"{a}_{b}" for a, b in device_stats.columns]
    device_stats = device_stats.reset_index().rename(columns={"index": device_col})

    device_models: Dict[str, EntityModel] = {}
    for devid, d in dv.reset_index().groupby(device_col):
        m = _fit_isolation_forest(d.drop(columns=[device_col]))
        if m is not None:
            device_models[str(devid)] = m

    return device_stats, device_models


# ---------- Baseline THEO NHÓM (role/department/position/...) ----------

def build_group_baselines(df: pd.DataFrame, group_col: str = "group") -> Tuple[pd.DataFrame, Dict[str, EntityModel]]:
    """
    Xây dựng baseline cho từng NHÓM (ví dụ: 'department', 'role', 'position'...).
    - Cần một cột group_col trong df (có thể nạp từ preprocessing hoặc enrich).
    - Dựa trên đặc trưng người dùng theo ngày, rồi gom theo group.
    Trả về:
      - group_stats: mean/std theo group cho các đặc trưng tổng hợp/ngày
      - group_models: IsolationForest theo group
    """
    if group_col not in df.columns:
        raise ValueError(f"Thiếu cột '{group_col}' để xây dựng baseline nhóm")

    df = _ensure_ts(df)

    # Tạo daily features theo user trước, rồi map user -> group
    daily_user = _daily_user_features(df).reset_index()  # ['username','date', features...]

    # Chuẩn hóa group
    user_group_map = (
        df[["username", group_col]]
        .dropna(subset=["username"])
        .drop_duplicates()
        .copy()
    )
    user_group_map["username"] = user_group_map["username"].astype(str)
    user_group_map[group_col] = user_group_map[group_col].fillna("(unknown)").astype(str)

    merged = daily_user.merge(user_group_map, on="username", how="left")
    merged[group_col] = merged[group_col].fillna("(unknown)")

    # Aggregate theo (group, date)
    grp = merged.groupby([group_col, "date"], dropna=False)
    agg = pd.DataFrame({
        "events": grp["events"].sum(),
        "unique_users": grp["username"].nunique(dropna=True),
        "unique_src_ips": grp["unique_src_ips"].sum() if "unique_src_ips" in merged.columns else 0,
        "login_fail": grp["login_fail"].sum() if "login_fail" in merged.columns else 0,
        "ssh_events": grp["ssh_events"].sum() if "ssh_events" in merged.columns else 0,
        "http_4xx": grp["http_4xx"].sum() if "http_4xx" in merged.columns else 0,
        "http_5xx": grp["http_5xx"].sum() if "http_5xx" in merged.columns else 0,
    })
    for c in agg.columns:
        agg[c] = pd.to_numeric(agg[c], errors="coerce").fillna(0).astype(int)

    # Thống kê mean/std theo group
    gg = agg.groupby(level=0)
    group_stats = gg.agg(["mean", "std"]).fillna(0)
    group_stats.columns = [f"{a}_{b}" for a, b in group_stats.columns]
    group_stats = group_stats.reset_index().rename(columns={"index": group_col})

    # Train IF theo group
    group_models: Dict[str, EntityModel] = {}
    for gid, gdf in agg.reset_index().groupby(group_col):
        m = _fit_isolation_forest(gdf.drop(columns=[group_col]))
        if m is not None:
            group_models[str(gid)] = m

    return group_stats, group_models


# ---------- Baseline TOÀN CỤC ----------

def build_global_baseline(df: pd.DataFrame) -> Dict[str, float]:
    """
    Xây dựng thống kê toàn cục cho toàn hệ thống (áp dụng Global Policy).
    Ví dụ: events/hour mean/std; tổng bytes/hour trung bình; max burst...
    """
    df = _ensure_ts(df)

    # Events per hour
    events_per_hour = (
        df.set_index("timestamp")
          .sort_index()
          .resample("1H")
          .size()
          .astype(int)
    )

    # Bytes per hour (nếu có)
    bytes_series = pd.to_numeric(_safe_col(df, "bytes"), errors="coerce").fillna(0)
    df_b = df.copy()
    df_b["bytes"] = bytes_series
    bytes_per_hour = (
        df_b.set_index("timestamp")
           .sort_index()
           .resample("1H")["bytes"]
           .sum()
    )

    # Upload/download heuristic: nếu có cột 'direction' và 'bytes'
    # direction: 'upload'/'download' (nếu thiếu, coi như tổng)
    if "direction" in df_b.columns:
        up_per_hour = (
            df_b[df_b["direction"].astype(str).str.lower().eq("upload")]
            .set_index("timestamp")
            .resample("1H")["bytes"]
            .sum()
        )
    else:
        up_per_hour = bytes_per_hour  # fallback: dùng tổng bytes như một xấp xỉ

    # Helper function to safely convert values to float, handling NaN/None
    def _safe_float(val) -> float:
        if val is None or (isinstance(val, float) and np.isnan(val)):
            return 0.0
        return float(val)

    return {
        "events_per_hour_mean": _safe_float(events_per_hour.mean()) if len(events_per_hour) else 0.0,
        "events_per_hour_std": _safe_float(events_per_hour.std()) if len(events_per_hour) else 0.0,
        "bytes_per_hour_mean": _safe_float(bytes_per_hour.mean()) if len(bytes_per_hour) else 0.0,
        "bytes_per_hour_std": _safe_float(bytes_per_hour.std()) if len(bytes_per_hour) else 0.0,
        "upload_bytes_per_hour_p95": _safe_float(up_per_hour.quantile(0.95)) if len(up_per_hour) else 0.0,
        "max_events_per_hour": int(events_per_hour.max()) if len(events_per_hour) else 0,
        "max_bytes_per_hour": _safe_float(bytes_per_hour.max()) if len(bytes_per_hour) else 0.0,
    }


# ---------- Baseline bundle (KHÔNG chia theo loại log) ----------

def build_baseline_bundle(df: pd.DataFrame) -> Dict[str, Any]:
    """
    API cấp cao: tạo bundle baseline KHÔNG phụ thuộc 'log_type'.
    Trả về dict JSON-safe:
      {
        "user":   <DataFrame: user_stats>,
        "device": <DataFrame: device_stats>,
        "group":  <DataFrame: group_stats hoặc DataFrame rỗng>,
        "global": <dict các thống kê toàn cục>,
      }
    """
    df = _ensure_ts(df)

    # USER
    user_stats, _ = build_user_baselines(df)

    # DEVICE
    device_stats, _ = build_device_baselines(df)

    # GROUP (ưu tiên 'group', nếu không dùng 'department' nếu có)
    group_stats = pd.DataFrame()
    if "group" in df.columns or "department" in df.columns:
        group_col = "group" if "group" in df.columns else "department"
        try:
            group_stats, _ = build_group_baselines(df, group_col=group_col)
        except Exception:
            group_stats = pd.DataFrame()

    # GLOBAL
    global_stats = build_global_baseline(df)

    result: Dict[str, Any] = {
        "user": user_stats,
        "device": device_stats,
        "group": group_stats,
        "global": global_stats,
    }
    return result


# ---------- Một số baseline tiện ích bổ sung (tùy dùng) ----------

@dataclass
class BaselineStats:
    mean: float
    std: float
    count: int

    def to_dict(self) -> Dict[str, Any]:
        return {"mean": float(self.mean), "std": float(self.std), "count": int(self.count)}


def compute_user_file_download_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Baseline số file DOWNLOAD theo ngày cho từng user (ví dụ dùng với proxy/web).
    Kỳ vọng: timestamp, username, action hoặc message chứa 'download'.
    Trả về: username, daily_mean, daily_std, days
    """
    if df is None or df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["username", "daily_mean", "daily_std", "days"])

    tmp = df.copy()
    tmp["date"] = tmp["timestamp"].dt.tz_convert("UTC").dt.date

    # Heuristic: action==download hoặc message chứa 'download'
    is_download = (
        _safe_col(tmp, "action").astype(str).str.contains("download", case=False, na=False)
        | _safe_col(tmp, "message").astype(str).str.contains("download|tải xuống", case=False, na=False)
    )
    tmp = tmp[is_download]
    if tmp.empty:
        return pd.DataFrame(columns=["username", "daily_mean", "daily_std", "days"])

    tmp["username"] = _safe_col(tmp, "username").fillna("<unknown>").astype(str)
    daily = tmp.groupby(["username", "date"]).size().reset_index(name="files_downloaded")

    stats = (
        daily.groupby("username")["files_downloaded"]
        .agg(["mean", "std", "count"])
        .reset_index()
        .rename(columns={"mean": "daily_mean", "std": "daily_std", "count": "days"})
    )
    stats["daily_std"] = stats["daily_std"].fillna(0.0)
    return stats


def compute_user_login_time_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Baseline khung giờ làm việc điển hình của user (p10 giờ bắt đầu, p90 giờ kết thúc) theo ngày.
    Trả về: username, start_p10, end_p90, days
    """
    if df is None or df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["username", "start_p10", "end_p90", "days"])

    tmp = df.copy()
    # Chuyển về Asia/Ho_Chi_Minh rồi tính giờ cục bộ
    ts_local = tmp["timestamp"].dt.tz_convert("Asia/Ho_Chi_Minh")
    tmp["local_hour"] = ts_local.dt.hour
    tmp["date"] = ts_local.dt.date

    is_login = (
        _safe_col(tmp, "action").astype(str).str.contains("logon|login|đăng nhập", case=False, na=False)
        | _safe_col(tmp, "message").astype(str).str.contains("logon|login|đăng nhập", case=False, na=False)
    )
    tmp = tmp[is_login]
    if tmp.empty:
        return pd.DataFrame(columns=["username", "start_p10", "end_p90", "days"])

    tmp["username"] = _safe_col(tmp, "username").fillna("<unknown>").astype(str)
    per_day = (
        tmp.groupby(["username", "date"])
        .agg(first_hour=("local_hour", "min"), last_hour=("local_hour", "max"))
        .reset_index()
    )

    def q(series: pd.Series, p: float) -> float:
        return float(series.quantile(p)) if len(series) else np.nan

    agg = per_day.groupby("username").agg(
        start_p10=("first_hour", lambda s: q(s, 0.10)),
        end_p90=("last_hour", lambda s: q(s, 0.90)),
        days=("date", "count"),
    ).reset_index()

    return agg


def build_group_baselines(
    df: pd.DataFrame,
    group_col: str = "group",
    default_group: Optional[str] = None
) -> Tuple[pd.DataFrame, Dict[str, "EntityModel"]]:
    """
    Xây dựng baseline theo NHÓM.
    - Nếu thiếu cột group_col:
        + Nếu default_group != None → tạo cột group_col = default_group cho tất cả bản ghi.
        + Ngược lại → cho tất cả rơi vào '(unknown)'.
    - Nếu group_col tồn tại nhưng NaN → fill bằng default_group hoặc '(unknown)'.
    - Nếu không có username → gom trực tiếp theo (group, date).
    """
    df = _ensure_ts(df).copy()

    if group_col not in df.columns:
        df[group_col] = default_group if default_group else "(unknown)"
    else:
        df[group_col] = df[group_col].fillna(default_group if default_group else "(unknown)").astype(str)

    if "username" in df.columns and df["username"].notna().any():
        # có username → build daily user features rồi map user -> group
        daily_user = _daily_user_features(df).reset_index()  # ['username','date', features...]
        user_group_map = (
            df[["username", group_col]]
            .dropna(subset=["username"])
            .drop_duplicates()
            .copy()
        )
        user_group_map["username"] = user_group_map["username"].astype(str)
        merged = daily_user.merge(user_group_map, on="username", how="left")
        merged[group_col] = merged[group_col].fillna(default_group if default_group else "(unknown)")
        base = merged
    else:
        # không có username → gom trực tiếp theo group/date
        tmp = df.copy()
        tmp["date"] = tmp["timestamp"].dt.tz_convert("UTC").dt.date
        grp = tmp.groupby([group_col, "date"], dropna=False)
        base = pd.DataFrame({
            "events": grp.size(),
            "unique_users": grp["username"].nunique(dropna=True) if "username" in tmp.columns else 1,
            "unique_src_ips": grp["source_ip"].nunique(dropna=True) if "source_ip" in tmp.columns else 0,
            "login_fail": 0,
            "ssh_events": 0,
            "http_4xx": 0,
            "http_5xx": 0,
        }).reset_index()

    # Thống kê mean/std theo group
    g = base.groupby(group_col)
    use_cols = [c for c in ["events","unique_users","unique_src_ips","login_fail","ssh_events","http_4xx","http_5xx"] if c in base.columns]
    group_stats = g[use_cols].agg(["mean","std"]).fillna(0)
    group_stats.columns = [f"{a}_{b}" for a,b in group_stats.columns]
    group_stats = group_stats.reset_index()

    # Train IsolationForest theo group (nếu bạn đã có _fit_isolation_forest / EntityModel)
    group_models: Dict[str, EntityModel] = {}
    try:
        for gid, gdf in base.groupby(group_col):
            cols = [c for c in ["events","unique_users","unique_src_ips","login_fail","ssh_events","http_4xx","http_5xx"] if c in gdf.columns]
            if not cols:
                continue
            m = _fit_isolation_forest(gdf[cols])
            if m is not None:
                group_models[str(gid)] = m
    except NameError:
        # Nếu file của bạn chưa có EntityModel/_fit_isolation_forest thì bỏ qua model
        group_models = {}

    return group_stats, group_models


def apply_group_mapping(
    df: pd.DataFrame,
    rules: Optional[List[Dict[str, str]]] = None,
    default_group: Optional[str] = None
) -> pd.DataFrame:
    """
    Ánh xạ group cho từng bản ghi theo danh sách rule:
      rules: [
        {"match_col": "source_ip"|"username",
         "type": "prefix"|"regex"|"exact",
         "match": "10.10.10."|"...",
         "group": "Sales"}
      ]
    Nếu không khớp rule nào → gán default_group (nếu có) hoặc '(unknown)' nếu vẫn bị trống.
    """
    df = df.copy()
    if "group" not in df.columns:
        df["group"] = None

    def _apply_rules_to_value(val: str, rules: List[Dict[str,str]]) -> Optional[str]:
        v = "" if pd.isna(val) else str(val)
        for r in rules:
            col = r.get("match_col", "source_ip")
            typ = r.get("type", "prefix").lower()
            pat = str(r.get("match", ""))
            grp = str(r.get("group", "(unknown)"))
            # so khớp
            ok = False
            if typ == "prefix":
                ok = v.startswith(pat)
            elif typ == "exact":
                ok = (v == pat)
            elif typ == "regex":
                try:
                    ok = bool(re.search(pat, v))
                except re.error:
                    ok = False
            if ok:
                return grp
        return None

    if rules:
        # Áp theo từng bản ghi
        def _assign_group(row):
            # Ưu tiên match theo cột khai báo trong rule
            for r in rules:
                col = r.get("match_col", "source_ip")
                if col in row:
                    grp = _apply_rules_to_value(row[col], [r])
                    if grp:
                        return grp
            return row.get("group", None)

        df["group"] = df.apply(_assign_group, axis=1)

    # Điền mặc định
    df["group"] = df["group"].fillna(default_group if default_group else "(unknown)").astype(str)
    return df

def extract_group_membership(df: pd.DataFrame, group_col: str = "group") -> Dict[str, Any]:
    """
    Từ dataframe đã được apply_group_mapping (đÃ có cột 'group'),
    tạo ra:
      - groups: { group_name: { "users": [...], "source_ips": [...], "hosts": [...] } }
      - user_to_group: { username: group }
      - device_to_group: { <host_or_source_ip>: group }
    Với device: ưu tiên 'host'; nếu thiếu thì dùng 'source_ip' hoặc 'ip_address' (DHCP logs).
    Username rỗng/NaN sẽ bị loại khỏi map user_to_group.
    """
    out = {
        "groups": {},
        "user_to_group": {},
        "device_to_group": {}
    }
    if df is None or df.empty or group_col not in df.columns:
        return out

    d = df.copy()
    d[group_col] = d[group_col].astype(str).fillna("(unknown)")
    # chuẩn hóa cột để dùng
    if "username" not in d.columns:
        d["username"] = None
    if "host" not in d.columns:
        d["host"] = None
    if "source_ip" not in d.columns:
        d["source_ip"] = None
    # NEW: Handle ip_address column from DHCP logs
    if "ip_address" not in d.columns:
        d["ip_address"] = None

    # --- Liệt kê theo group ---
    for g, gdf in d.groupby(group_col):
        users = (
            gdf["username"]
            .dropna()
            .astype(str)
            .replace({"", "nan", "None"}, pd.NA)
            .dropna()
            .unique()
            .tolist()
        )
        # Extract IPs from both source_ip and ip_address columns
        ips = []
        # From source_ip column
        if "source_ip" in gdf.columns:
            source_ips = (
                gdf["source_ip"]
                .dropna()
                .astype(str)
                .replace({"", "nan", "None"}, pd.NA)
                .dropna()
                .unique()
                .tolist()
            )
            ips.extend(source_ips)
        # From ip_address column (DHCP logs)
        if "ip_address" in gdf.columns:
            ip_addrs = (
                gdf["ip_address"]
                .dropna()
                .astype(str)
                .replace({"", "nan", "None"}, pd.NA)
                .dropna()
                .unique()
                .tolist()
            )
            ips.extend(ip_addrs)
        # Remove duplicates and sort
        ips = sorted(set(ips))
        
        hosts = (
            gdf["host"]
            .dropna()
            .astype(str)
            .replace({"", "nan", "None"}, pd.NA)
            .dropna()
            .unique()
            .tolist()
        )
        out["groups"][g] = {
            "users": users,
            "source_ips": ips,
            "hosts": hosts
        }

    # --- user_to_group (lọc username hợp lệ) ---
    u_map = (
        d[["username", group_col]]
        .dropna(subset=["username"])
        .copy()
    )
    u_map["username"] = u_map["username"].astype(str)
    u_map = u_map[~u_map["username"].isin(["", "nan", "None"])]
    for row in u_map.drop_duplicates(subset=["username"]).itertuples(index=False):
        out["user_to_group"][row.username] = getattr(row, group_col)

    # --- device_to_group ---
    # Ưu tiên host, nếu không có thì dùng source_ip hoặc ip_address. Dùng "đa số" nếu một device thấy nhiều group.
    # Host
    if d["host"].notna().any():
        maj = (
            d.dropna(subset=["host"])
             .assign(_one=1)
             .groupby(["host", group_col])["_one"].sum()
             .reset_index()
        )
        majors = maj.sort_values(["host", "_one"], ascending=[True, False]).drop_duplicates("host")
        for r in majors.itertuples(index=False):
            out["device_to_group"][r.host] = getattr(r, group_col)
    # Source IP
    if d["source_ip"].notna().any():
        maj = (
            d.dropna(subset=["source_ip"])
             .assign(_one=1)
             .groupby(["source_ip", group_col])["_one"].sum()
             .reset_index()
        )
        majors = maj.sort_values(["source_ip", "_one"], ascending=[True, False]).drop_duplicates("source_ip")
        for r in majors.itertuples(index=False):
            out["device_to_group"][r.source_ip] = getattr(r, group_col)
    # IP Address (from DHCP logs)
    if d["ip_address"].notna().any():
        maj = (
            d.dropna(subset=["ip_address"])
             .assign(_one=1)
             .groupby(["ip_address", group_col])["_one"].sum()
             .reset_index()
        )
        majors = maj.sort_values(["ip_address", "_one"], ascending=[True, False]).drop_duplicates("ip_address")
        for r in majors.itertuples(index=False):
            out["device_to_group"][r.ip_address] = getattr(r, group_col)

    return out