"""
Synthetic Behavioral Access-Log Generator
==========================================
Generates a realistic, labeled dataset of login/access events for training
and evaluating the behavioral anomaly detection pipeline.

DESIGN / ASSUMPTIONS (documented, as required by the brief)
-------------------------------------------------------------
1. Population: a mix of human users, service accounts, and edge devices.
   Each entity gets a stable "behavioral profile" (habitual login hours,
   home countries/cities, known devices, typical resources, browsers,
   session-duration distribution) sampled once at generation time. All
   subsequent NORMAL events for that entity are drawn from its own profile
   plus Gaussian/Poisson noise -- this is what "normal" means for us.
2. Attacks are injected as short *episodes* attached to a victim entity
   (or, for credential stuffing, a single attacking IP hitting many
   entities), at a controlled overall rate of 0.5%-3% of sessions
   (CLI-configurable via --attack-rate), matching the brief's guidance
   on realistic class imbalance.
3. Ground truth (`label`, `attack_type`) is retained in the output but is
   intended to be *hidden at inference time* -- the detection stage only
   ever sees the feature columns, never the label. It exists purely for
   supervised classifier training and evaluation.
4. Timestamps span a configurable historical window (default: 60 days)
   at whatever entity count / event volume requested, so the pipeline can
   build rolling/behavioral-history features before attacks appear.
5. No third-party dependency (e.g. Faker) is required -- entity names,
   IPs and geo-coordinates are synthesized directly so the generator runs
   in network-restricted / offline environments.

Usage:
    python generator.py --n-events 60000 --n-entities 600 --attack-rate 0.02 \
        --seed 42 --out ../artifacts/events.csv
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Reference data (self-contained, no external dependency)
# --------------------------------------------------------------------------- #

CITIES = [
    # (city, country, lat, lon)
    ("New York", "USA", 40.7128, -74.0060),
    ("San Francisco", "USA", 37.7749, -122.4194),
    ("Chicago", "USA", 41.8781, -87.6298),
    ("London", "UK", 51.5074, -0.1278),
    ("Manchester", "UK", 53.4808, -2.2426),
    ("Berlin", "Germany", 52.5200, 13.4050),
    ("Frankfurt", "Germany", 50.1109, 8.6821),
    ("Mumbai", "India", 19.0760, 72.8777),
    ("Bengaluru", "India", 12.9716, 77.5946),
    ("Delhi", "India", 28.7041, 77.1025),
    ("Singapore", "Singapore", 1.3521, 103.8198),
    ("Tokyo", "Japan", 35.6762, 139.6503),
    ("Sydney", "Australia", -33.8688, 151.2093),
    ("Sao Paulo", "Brazil", -23.5505, -46.6333),
    ("Toronto", "Canada", 43.6532, -79.3832),
    ("Dubai", "UAE", 25.2048, 55.2708),
    ("Lagos", "Nigeria", 6.5244, 3.3792),
    ("Moscow", "Russia", 55.7558, 37.6173),
    ("Beijing", "China", 39.9042, 116.4074),
    ("Paris", "France", 48.8566, 2.3522),
]

# A short list of "high risk" / bulletproof-hosting-associated countries used
# purely to synthesize a plausible simulated IP-reputation score. This is a
# modeling convenience for the synthetic data, not a real threat-intel feed.
HIGH_RISK_COUNTRIES = {"Russia", "Nigeria", "China"}

RESOURCES = [
    "hr_portal", "payroll_system", "finance_dashboard", "customer_db",
    "source_code_repo", "ci_cd_pipeline", "email_server", "vpn_gateway",
    "file_share_engineering", "file_share_finance", "crm_system",
    "admin_console", "backup_system", "kubernetes_dashboard",
    "billing_api", "analytics_warehouse", "secrets_vault",
    "iot_gateway_control", "device_firmware_update", "network_switch_config",
]

SENSITIVE_RESOURCES = {
    "payroll_system", "finance_dashboard", "customer_db", "secrets_vault",
    "admin_console", "backup_system", "billing_api",
}

AUTH_METHODS = ["password", "mfa_token", "sso_saml", "certificate", "biometric", "api_key"]
PROTOCOLS = ["https", "ssh", "rdp", "vpn", "grpc", "mqtt"]
OS_LIST = ["Windows 11", "macOS 15", "Ubuntu 24.04", "iOS 18", "Android 15", "RHEL 9", "FirmwareOS 3.2"]
BROWSERS = ["Chrome", "Edge", "Safari", "Firefox", "None (headless/API)", "None (device-agent)"]
ENTITY_TYPES = ["user", "service_account", "edge_device"]
ENTITY_TYPE_WEIGHTS = [0.72, 0.13, 0.15]

ATTACK_TYPES = [
    "brute_force",
    "credential_stuffing",
    "impossible_travel",
    "device_spoofing",
    "lateral_movement",
    "low_and_slow_exfiltration",
    "insider_drift",
]


def rand_ip(rng: random.Random, country: str | None = None) -> str:
    """Synthesize a plausible-looking public IPv4 address."""
    # avoid reserved/private ranges
    first = rng.choice([i for i in range(1, 224) if i not in (10, 127, 169, 172, 192)])
    return f"{first}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def rand_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))


def rand_entity_name(rng: random.Random, etype: str, idx: int) -> str:
    if etype == "user":
        first = rng.choice(["alex", "priya", "wei", "sofia", "omar", "maria", "liam",
                             "chen", "fatima", "noah", "ana", "kenji", "ivan", "grace",
                             "raj", "elena", "yusuf", "julia", "hassan", "mei"])
        last_initial = rng.choice(string.ascii_lowercase)
        return f"{first}.{last_initial}{idx:03d}"
    if etype == "service_account":
        svc = rng.choice(["ci-runner", "backup-agent", "billing-svc", "etl-worker",
                           "monitoring-bot", "deploy-bot", "sync-service"])
        return f"svc-{svc}-{idx:03d}"
    dev = rng.choice(["gateway", "camera", "hvac-ctrl", "badge-reader", "sensor-hub", "plc"])
    return f"edge-{dev}-{idx:03d}"


@dataclass
class EntityProfile:
    entity_id: str
    entity_type: str
    home_cities: list[tuple] = field(default_factory=list)          # 1-2 habitual locations
    known_devices: list[dict] = field(default_factory=list)         # device_id, fingerprint, os, mac
    typical_resources: list[str] = field(default_factory=list)      # resources this entity normally touches
    preferred_auth: str = "password"
    preferred_browser: str = "Chrome"
    preferred_protocol: str = "https"
    active_hours: tuple = (9, 18)          # habitual login-hour window (local business hours)
    weekday_bias: float = 0.9              # probability a normal login happens on a weekday
    session_mean_s: float = 900.0          # typical session duration (seconds)
    session_std_s: float = 240.0
    login_freq_per_day: float = 3.0        # historical login frequency baseline
    ip_pool: list[str] = field(default_factory=list)                # small set of habitual IPs/subnets


def build_profile(rng: random.Random, entity_id: str, etype: str) -> EntityProfile:
    n_homes = 1 if etype != "user" else rng.choice([1, 1, 1, 2])
    homes = rng.sample(CITIES, k=n_homes)
    n_devices = {"user": rng.choice([1, 2, 2, 3]), "service_account": 1, "edge_device": 1}[etype]
    devices = []
    for _ in range(n_devices):
        devices.append({
            "device_id": f"dev-{rng.randint(10000,99999)}",
            "os": rng.choice(OS_LIST) if etype != "edge_device" else "FirmwareOS 3.2",
            "mac": rand_mac(rng),
            "fingerprint": f"fp-{rng.randint(100000,999999)}",
        })
    n_res = {"user": rng.randint(2, 5), "service_account": rng.randint(1, 3), "edge_device": rng.randint(1, 2)}[etype]
    typical = rng.sample(RESOURCES, k=n_res)
    active_start = rng.randint(6, 10) if etype == "user" else 0
    active_len = rng.randint(8, 11) if etype == "user" else 24
    ip_pool = [rand_ip(rng) for _ in range(rng.choice([1, 1, 2]))]
    return EntityProfile(
        entity_id=entity_id,
        entity_type=etype,
        home_cities=homes,
        known_devices=devices,
        typical_resources=typical,
        preferred_auth=rng.choice(AUTH_METHODS) if etype == "user" else rng.choice(["api_key", "certificate"]),
        preferred_browser=rng.choice(BROWSERS[:4]) if etype == "user" else "None (headless/API)",
        preferred_protocol="https" if etype != "edge_device" else rng.choice(["mqtt", "https"]),
        active_hours=(active_start, (active_start + active_len) % 24 or 24),
        weekday_bias=0.92 if etype == "user" else 0.6,
        session_mean_s=rng.uniform(300, 1800) if etype == "user" else rng.uniform(30, 300),
        session_std_s=rng.uniform(60, 300),
        login_freq_per_day=rng.uniform(1, 6) if etype == "user" else rng.uniform(10, 60),
        ip_pool=ip_pool,
    )


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def sample_normal_hour(rng: random.Random, profile: EntityProfile) -> int:
    start, end = profile.active_hours
    span = (end - start) % 24 or 24
    # Gaussian around the middle of the active window, wrapped into 0-23, with light noise
    hour = int(rng.gauss(start + span / 2, span / 4)) % 24
    if rng.random() < 0.05:  # 5% off-hours noise
        hour = rng.randint(0, 23)
    return hour


def make_event(
    rng: random.Random,
    entity: EntityProfile,
    ts: datetime,
    label: str,
    attack_type: str,
    *,
    ip: str | None = None,
    city_row=None,
    device: dict | None = None,
    resource: str | None = None,
    login_status: str = "success",
    session_duration: float | None = None,
    command_sequence: list[str] | None = None,
    auth_method: str | None = None,
    protocol: str | None = None,
) -> dict:
    city_row = city_row or rng.choice(entity.home_cities)
    city, country, lat, lon = city_row
    device = device or rng.choice(entity.known_devices)
    resource = resource or rng.choice(entity.typical_resources)
    auth_method = auth_method or entity.preferred_auth
    protocol = protocol or entity.preferred_protocol
    if session_duration is None:
        session_duration = max(5.0, rng.gauss(entity.session_mean_s, entity.session_std_s))
    if command_sequence is None:
        depth = rng.randint(1, 6)
        command_sequence = [rng.choice(["read", "list", "download", "write", "execute", "delete", "config_change"])
                             for _ in range(depth)]

    ip_reputation = rng.uniform(0.0, 0.15)
    if country in HIGH_RISK_COUNTRIES:
        ip_reputation += rng.uniform(0.2, 0.4)
    if label != "normal":
        ip_reputation += rng.uniform(0.1, 0.5)
    ip_reputation = float(min(1.0, ip_reputation))

    return {
        "entity_id": entity.entity_id,
        "entity_type": entity.entity_type,
        "timestamp": ts.isoformat(),
        "source_ip": ip or rng.choice(entity.ip_pool),
        "country": country,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "resource_accessed": resource,
        "authentication_method": auth_method,
        "device_id": device["device_id"],
        "device_fingerprint": device["fingerprint"],
        "operating_system": device["os"],
        "browser": entity.preferred_browser,
        "session_duration": round(session_duration, 1),
        "command_sequence": "|".join(command_sequence),
        "protocol": protocol,
        "login_status": login_status,
        "ip_reputation_sim": round(ip_reputation, 3),
        "label": label,
        "attack_type": attack_type,
    }


# --------------------------------------------------------------------------- #
# Attack episode generators -- each returns a list of event dicts
# --------------------------------------------------------------------------- #

def gen_brute_force(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Repeated failed logins, same source IP, short interval, occasional final success."""
    attacker_ip = rand_ip(rng)
    n = rng.randint(8, 25)
    events = []
    cur = ts
    for i in range(n):
        success = (i == n - 1) and rng.random() < 0.35
        events.append(make_event(
            rng, entity, cur, "anomaly", "brute_force",
            ip=attacker_ip, login_status="success" if success else "failed",
            session_duration=rng.uniform(2, 15),
        ))
        cur += timedelta(seconds=rng.uniform(2, 20))
    return events


def gen_credential_stuffing(rng, attacker_ip: str, victims: list[EntityProfile], ts: datetime) -> list[dict]:
    """One attacker IP, many entities, high failure rate."""
    events = []
    cur = ts
    for entity in victims:
        success = rng.random() < 0.08
        events.append(make_event(
            rng, entity, cur, "anomaly", "credential_stuffing",
            ip=attacker_ip, login_status="success" if success else "failed",
            session_duration=rng.uniform(2, 10),
        ))
        cur += timedelta(seconds=rng.uniform(1, 8))
    return events


def gen_impossible_travel(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Same entity, two geographically distant logins within an implausible time gap."""
    home = rng.choice(entity.home_cities)
    far_candidates = [c for c in CITIES if haversine_km(home[2], home[3], c[2], c[3]) > 4000]
    far = rng.choice(far_candidates) if far_candidates else rng.choice(CITIES)
    e1 = make_event(rng, entity, ts, "anomaly", "impossible_travel", city_row=home, ip=rand_ip(rng))
    gap_minutes = rng.uniform(10, 90)  # too short to physically travel that distance
    e2 = make_event(rng, entity, ts + timedelta(minutes=gap_minutes), "anomaly", "impossible_travel",
                     city_row=far, ip=rand_ip(rng))
    return [e1, e2]


def gen_device_spoofing(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Known user, unknown fingerprint/MAC, different OS than any known device."""
    known_os = {d["os"] for d in entity.known_devices}
    spoof_os = rng.choice([o for o in OS_LIST if o not in known_os] or OS_LIST)
    spoof_device = {
        "device_id": f"dev-{rng.randint(10000,99999)}",
        "os": spoof_os,
        "mac": rand_mac(rng),
        "fingerprint": f"fp-{rng.randint(100000,999999)}",
    }
    return [make_event(rng, entity, ts, "anomaly", "device_spoofing",
                        device=spoof_device, ip=rand_ip(rng))]


def gen_lateral_movement(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Compromised entity accessing many unusual internal resources, never touched before."""
    unusual = [r for r in RESOURCES if r not in entity.typical_resources]
    n = rng.randint(5, 12)
    picks = rng.sample(unusual, k=min(n, len(unusual)))
    events = []
    cur = ts
    for r in picks:
        events.append(make_event(rng, entity, cur, "anomaly", "lateral_movement",
                                  resource=r, session_duration=rng.uniform(20, 200)))
        cur += timedelta(minutes=rng.uniform(1, 15))
    return events


def gen_low_and_slow(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Gradual, off-hours, increasing access to sensitive resources over several days."""
    events = []
    days = rng.randint(4, 10)
    cur_day = ts
    for d in range(days):
        n_today = 1 + d // 3  # slow ramp
        for _ in range(n_today):
            hour = rng.choice([0, 1, 2, 3, 4, 23])  # off-hours
            when = cur_day.replace(hour=hour, minute=rng.randint(0, 59)) + timedelta(days=d)
            res = rng.choice(list(SENSITIVE_RESOURCES))
            events.append(make_event(rng, entity, when, "anomaly", "low_and_slow_exfiltration",
                                      resource=res, session_duration=rng.uniform(600, 2400)))
    return events


def gen_insider_drift(rng, entity: EntityProfile, ts: datetime) -> list[dict]:
    """Slow, gradual privilege/behavioral expansion -- ambiguous edge case for FP tuning."""
    events = []
    weeks = rng.randint(3, 6)
    cur = ts
    expanding_pool = [r for r in RESOURCES if r not in entity.typical_resources]
    for w in range(weeks):
        n_new = min(1 + w // 2, len(expanding_pool))
        newly_touched = expanding_pool[:n_new]
        for r in newly_touched:
            when = cur + timedelta(days=w * 7 + rng.randint(0, 6),
                                    hours=rng.randint(*[h % 24 for h in entity.active_hours]) if entity.active_hours[0] < 24 else 10)
            events.append(make_event(rng, entity, when, "anomaly", "insider_drift",
                                      resource=r, session_duration=rng.uniform(200, 1200)))
    return events


# --------------------------------------------------------------------------- #
# Main generation loop
# --------------------------------------------------------------------------- #

def generate(n_events: int, n_entities: int, attack_rate: float, days: int, seed: int) -> pd.DataFrame:
    rng = random.Random(seed)
    np.random.seed(seed)

    start = datetime.utcnow() - timedelta(days=days)

    entities: list[EntityProfile] = []
    for i in range(n_entities):
        etype = rng.choices(ENTITY_TYPES, weights=ENTITY_TYPE_WEIGHTS, k=1)[0]
        eid = rand_entity_name(rng, etype, i)
        entities.append(build_profile(rng, eid, etype))

    users_only = [e for e in entities if e.entity_type == "user"]

    n_attack_events_target = int(n_events * attack_rate)
    n_normal_target = n_events - n_attack_events_target

    rows: list[dict] = []

    # ---- normal traffic -----------------------------------------------
    while len(rows) < n_normal_target:
        entity = rng.choice(entities)
        day_offset = rng.randint(0, days - 1)
        hour = sample_normal_hour(rng, entity)
        day = start + timedelta(days=day_offset)
        if rng.random() > entity.weekday_bias and day.weekday() < 5:
            continue  # occasionally skip to bias weekday/weekend realistically
        ts = day.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
        login_status = "success" if rng.random() > 0.03 else "failed"  # small organic failure noise
        rows.append(make_event(rng, entity, ts, "normal", "none", login_status=login_status))

    # ---- attack episodes -------------------------------------------------
    attack_budget = n_attack_events_target

    def make_episode(atype, ts):
        if atype == "brute_force":
            entity = rng.choice(entities)
            return gen_brute_force(rng, entity, ts)
        if atype == "credential_stuffing":
            attacker_ip = rand_ip(rng)
            victims = rng.sample(users_only, k=min(rng.randint(15, 40), len(users_only)))
            return gen_credential_stuffing(rng, attacker_ip, victims, ts)
        if atype == "impossible_travel":
            entity = rng.choice(users_only)
            return gen_impossible_travel(rng, entity, ts)
        if atype == "device_spoofing":
            entity = rng.choice(entities)
            return gen_device_spoofing(rng, entity, ts)
        if atype == "lateral_movement":
            entity = rng.choice(entities)
            return gen_lateral_movement(rng, entity, ts)
        if atype == "low_and_slow_exfiltration":
            entity = rng.choice(users_only)
            return gen_low_and_slow(rng, entity, ts)
        entity = rng.choice(users_only)  # insider_drift
        return gen_insider_drift(rng, entity, ts)

    # 1) Guarantee a minimum number of EPISODES per attack type first, so
    #    that low-event-count episode types (e.g. impossible_travel has only
    #    2 events/episode, device_spoofing has 1) still get enough labeled
    #    examples for the classifier to learn from and be evaluated on --
    #    otherwise a purely event-count-weighted random budget starves them
    #    in favor of large episodes like credential_stuffing.
    MIN_EPISODES_PER_TYPE = 40
    for atype in ATTACK_TYPES:
        for _ in range(MIN_EPISODES_PER_TYPE):
            day_offset = rng.randint(0, max(days - 12, 1))
            ts = start + timedelta(days=day_offset, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            ep = make_episode(atype, ts)
            rows.extend(ep)
            attack_budget -= len(ep)

    # 2) Spend any remaining budget on random episodes across all types.
    while attack_budget > 0:
        atype = rng.choice(ATTACK_TYPES)
        day_offset = rng.randint(0, max(days - 12, 1))
        ts = start + timedelta(days=day_offset, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        ep = make_episode(atype, ts)
        rows.extend(ep)
        attack_budget -= len(ep)

    rng.shuffle(rows)
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.insert(0, "event_id", [f"evt_{i:07d}" for i in range(len(df))])

    return df, entities


def entities_to_json(entities: list[EntityProfile]) -> dict:
    out = {}
    for e in entities:
        out[e.entity_id] = {
            "entity_type": e.entity_type,
            "home_cities": [c[0] for c in e.home_cities],
            "known_device_ids": [d["device_id"] for d in e.known_devices],
            "typical_resources": e.typical_resources,
            "active_hours": e.active_hours,
            "login_freq_per_day": e.login_freq_per_day,
        }
    return out


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic behavioral access-log dataset")
    ap.add_argument("--n-events", type=int, default=60000)
    ap.add_argument("--n-entities", type=int, default=600)
    ap.add_argument("--attack-rate", type=float, default=0.02, help="fraction of events that are attack episodes (0.5%-3% recommended)")
    ap.add_argument("--days", type=int, default=60)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=str, default="../artifacts/events.csv")
    ap.add_argument("--profiles-out", type=str, default="../artifacts/entity_profiles.json")
    args = ap.parse_args()

    df, entities = generate(args.n_events, args.n_entities, args.attack_rate, args.days, args.seed)

    import os
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    with open(args.profiles_out, "w") as f:
        json.dump(entities_to_json(entities), f, indent=2)

    print(f"Generated {len(df):,} events across {args.n_entities} entities")
    print(df["label"].value_counts())
    print(df["attack_type"].value_counts())
    print(f"Saved -> {args.out}")


if __name__ == "__main__":
    main()
