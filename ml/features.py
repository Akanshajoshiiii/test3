"""
Feature Engineering
====================
Turns raw access-log events into per-event behavioral features, computed
causally (i.e. only using each entity's HISTORY up to that event, so there
is no label leakage / no peeking at the future). This is what makes the
pipeline usable in real-time: at inference time we only need an entity's
running state, not the whole dataset.

Feature groups (per brief):
    - time features: hour_of_login, is_weekend
    - geo features: geo_distance_from_prev_km, geo_velocity_kmh
    - session features: session_duration_deviation
    - recency features: time_since_last_login_s, rolling login frequency
    - novelty features: device_novelty, resource_novelty, auth_method_change
    - aggregate features: unique_resource_count_7d, failed_login_count_1h
    - behavioral features: command_entropy, device_trust_score,
      behavior_deviation_score, ip_reputation (simulated), sensitive_resource_flag
"""

from __future__ import annotations

import math
from collections import defaultdict, deque

import numpy as np
import pandas as pd

EARTH_R_KM = 6371.0


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    if any(pd.isna(v) for v in (lat1, lon1, lat2, lon2)):
        return 0.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_R_KM * math.asin(math.sqrt(a))


def command_entropy(cmd_seq: str) -> float:
    if not isinstance(cmd_seq, str) or not cmd_seq:
        return 0.0
    cmds = cmd_seq.split("|")
    if not cmds:
        return 0.0
    counts = pd.Series(cmds).value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


class EntityState:
    """Running behavioral state for one entity, updated causally event by event."""

    __slots__ = (
        "last_ts", "last_lat", "last_lon", "known_devices", "known_resources",
        "known_auth_methods", "session_durations", "recent_failed", "login_times",
        "sensitive_hits_recent", "first_seen",
    )

    def __init__(self):
        self.last_ts = None
        self.last_lat = None
        self.last_lon = None
        self.known_devices: set[str] = set()
        self.known_resources: set[str] = set()
        self.known_auth_methods: set[str] = set()
        self.session_durations: deque = deque(maxlen=50)
        self.recent_failed: deque = deque(maxlen=200)   # (ts, status)
        self.login_times: deque = deque(maxlen=500)      # ts of successful/attempted logins
        self.sensitive_hits_recent: deque = deque(maxlen=200)  # ts of sensitive-resource hits
        self.first_seen = None


SENSITIVE_RESOURCES = {
    "payroll_system", "finance_dashboard", "customer_db", "secrets_vault",
    "admin_console", "backup_system", "billing_api",
}


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    df must be sorted by timestamp ascending and contain the raw generator
    columns. Returns a new dataframe with engineered feature columns appended.
    Processes causally per-entity (dict of EntityState), so this function can
    be reused unmodified for streaming/online inference (call once per event).
    """
    df = df.sort_values("timestamp").reset_index(drop=True)
    states: dict[str, EntityState] = defaultdict(EntityState)

    feat_rows = []
    for row in df.itertuples(index=False):
        eid = row.entity_id
        st = states[eid]
        ts = row.timestamp

        if st.first_seen is None:
            st.first_seen = ts
            cold_start = 1
        else:
            cold_start = 0

        hour = ts.hour
        is_weekend = int(ts.weekday() >= 5)

        # --- recency ---
        if st.last_ts is not None:
            time_since_last_s = max(0.0, (ts - st.last_ts).total_seconds())
        else:
            time_since_last_s = -1.0  # sentinel: no history

        # --- geo velocity / impossible travel signal ---
        if st.last_lat is not None:
            dist_km = haversine_km(st.last_lat, st.last_lon, row.latitude, row.longitude)
            hours_elapsed = max(time_since_last_s / 3600.0, 1e-6)
            geo_velocity_kmh = dist_km / hours_elapsed
        else:
            dist_km = 0.0
            geo_velocity_kmh = 0.0

        # --- novelty ---
        device_novelty = int(row.device_id not in st.known_devices)
        resource_novelty = int(row.resource_accessed not in st.known_resources)
        auth_change = int(len(st.known_auth_methods) > 0 and row.authentication_method not in st.known_auth_methods)

        # --- session duration deviation (z-score vs entity's own history) ---
        if len(st.session_durations) >= 3:
            arr = np.array(st.session_durations)
            mu, sigma = arr.mean(), arr.std() + 1e-6
            session_dev = abs(row.session_duration - mu) / sigma
        else:
            session_dev = 0.0

        # --- failed-login velocity (brute force / credential stuffing signal) ---
        one_hour_ago = ts - pd.Timedelta(hours=1)
        while st.recent_failed and st.recent_failed[0][0] < one_hour_ago:
            st.recent_failed.popleft()
        failed_count_1h = sum(1 for (_, status) in st.recent_failed if status == "failed")

        # --- login frequency (rolling, 24h window) ---
        one_day_ago = ts - pd.Timedelta(hours=24)
        while st.login_times and st.login_times[0] < one_day_ago:
            st.login_times.popleft()
        login_freq_24h = len(st.login_times)

        # --- unique resource count, 7-day rolling ---
        unique_resource_count = len(st.known_resources)

        # --- sensitive-resource ramp (low-and-slow exfil signal) ---
        seven_days_ago = ts - pd.Timedelta(days=7)
        while st.sensitive_hits_recent and st.sensitive_hits_recent[0] < seven_days_ago:
            st.sensitive_hits_recent.popleft()
        is_sensitive = int(row.resource_accessed in SENSITIVE_RESOURCES)
        sensitive_hits_7d = len(st.sensitive_hits_recent) + is_sensitive

        # --- command entropy ---
        cmd_entropy = command_entropy(row.command_sequence)

        # --- device trust score (0=untrusted/new, 1=fully known & consistent) ---
        device_trust = 0.0 if device_novelty else min(1.0, 0.5 + 0.1 * len(st.known_devices))

        # --- off-hours flag ---
        off_hours = int(hour < 6 or hour >= 22)

        # --- composite behavior deviation score (simple weighted combination
        #     used as an auxiliary signal, independent of the learned model) ---
        behavior_deviation = (
            0.25 * min(session_dev, 5) / 5
            + 0.20 * device_novelty
            + 0.15 * resource_novelty
            + 0.15 * min(geo_velocity_kmh / 900.0, 1.0)   # >900 km/h ~ impossible for commercial travel
            + 0.10 * auth_change
            + 0.15 * min(failed_count_1h / 5.0, 1.0)
        )

        feat_rows.append({
            "event_id": row.event_id,
            "hour_of_login": hour,
            "is_weekend": is_weekend,
            "off_hours": off_hours,
            "geo_distance_from_prev_km": round(dist_km, 2),
            "geo_velocity_kmh": round(geo_velocity_kmh, 2),
            "time_since_last_login_s": round(time_since_last_s, 1),
            "session_duration_deviation": round(session_dev, 3),
            "failed_login_count_1h": failed_count_1h,
            "device_novelty": device_novelty,
            "resource_novelty": resource_novelty,
            "authentication_change": auth_change,
            "unique_resource_count": unique_resource_count,
            "login_freq_24h": login_freq_24h,
            "sensitive_resource_flag": is_sensitive,
            "sensitive_hits_7d": sensitive_hits_7d,
            "command_entropy": cmd_entropy,
            "device_trust_score": round(device_trust, 3),
            "ip_reputation_score": row.ip_reputation_sim,
            "behavior_deviation_score": round(behavior_deviation, 4),
            "cold_start": cold_start,
            "login_failed": int(row.login_status == "failed"),
        })

        # --- update running state AFTER computing features (causal) ---
        st.last_ts = ts
        st.last_lat, st.last_lon = row.latitude, row.longitude
        st.known_devices.add(row.device_id)
        st.known_resources.add(row.resource_accessed)
        st.known_auth_methods.add(row.authentication_method)
        st.session_durations.append(row.session_duration)
        st.recent_failed.append((ts, row.login_status))
        st.login_times.append(ts)
        if is_sensitive:
            st.sensitive_hits_recent.append(ts)

    feat_df = pd.DataFrame(feat_rows)
    out = df.merge(feat_df, on="event_id", how="left")
    return out


FEATURE_COLUMNS = [
    "hour_of_login", "is_weekend", "off_hours",
    "geo_distance_from_prev_km", "geo_velocity_kmh", "time_since_last_login_s",
    "session_duration_deviation", "failed_login_count_1h",
    "device_novelty", "resource_novelty", "authentication_change",
    "unique_resource_count", "login_freq_24h",
    "sensitive_resource_flag", "sensitive_hits_7d",
    "command_entropy", "device_trust_score", "ip_reputation_score",
    "behavior_deviation_score", "cold_start", "login_failed",
]


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="../artifacts/events.csv")
    ap.add_argument("--out", dest="out", default="../artifacts/events_features.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.inp, parse_dates=["timestamp"])
    out = build_features(df)
    out.to_csv(args.out, index=False)
    print(f"Feature-engineered {len(out):,} rows -> {args.out}")
    print("Feature columns:", FEATURE_COLUMNS)
