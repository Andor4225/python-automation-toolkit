# wf_postreduce.py
# One-stop post-processor + reducer for your wireless forensics JSON

from datetime import datetime, timezone
from math import sqrt, exp
from collections import Counter

# =========================
# Config (tune as needed)
# =========================
# Typical indoor RSSI at 1m per band (dBm)
BAND_1M_RSSI = {"2.4": -40.0, "5": -45.0, "6": -47.0}
# Default path-loss exponent per band (indoors, drywall)
PATH_LOSS_N = {"2.4": 3.0, "5": 3.2, "6": 3.2}
# Optional per-band calibration offsets (dB): measured - reference
CALIB_OFFSETS = {"2.4": 0.0, "5": 0.0, "6": 0.0}

# Distance sanity
MIN_RSSI_SAMPLES_FOR_DISTANCE = 5
MAX_REASONABLE_DISTANCE_FT = 160.0

# Event → severity weight
SEVERITY_WEIGHTS = {
    "deauth": 5,
    "disassoc": 5,
    "beacon_flood": 2,
    "probe_scan": 1,
    "scan": 1,
    "_default": 1,
}

# Proximity multiplier
PROX_MULT_BY_ZONE = {"immediate": 2.0, "close": 1.5, "neighbor": 1.2, "distant": 1.0, "unknown": 1.0}

# Risk score thresholds
RISK_THRESHOLDS = [
    ("LOW", 0),
    ("MEDIUM", 10),
    ("HIGH", 25),
    ("CRITICAL", 60),
]

TOP_TIME_FIELDS = (
    "report_start", "report_end", "generated_at",
    "analysis_start", "analysis_end", "last_updated",
    "period_start", "period_end"
)

# =========================
# Timestamp normalization
# =========================
def _parse_ts_any(ts):
    """Accept epoch s/ms/us or ISO; return aware UTC dt or None."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        t = float(ts)
        if t > 1e14:      # microseconds
            t /= 1e6
        elif t > 1e11:    # milliseconds
            t /= 1e3
        return datetime.fromtimestamp(max(0.0, t), tz=timezone.utc)
    if isinstance(ts, str):
        s = ts.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s).astimezone(timezone.utc)
        except Exception:
            return None
    return None

def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _norm_time_field(obj, key):
    if key in obj:
        dt = _parse_ts_any(obj[key])
        if dt is None or dt.year <= 1971:
            obj[key] = None
        else:
            obj[key] = _iso(dt)

# =========================
# RSSI helpers (unified)
# =========================
def _stats_from_list(vals):
    if not vals:
        return None
    avg = sum(vals) / len(vals)
    mx = max(vals)
    var = sum((x - avg) ** 2 for x in vals) / max(1, len(vals) - 1)
    return {"avg": avg, "max": mx, "std": sqrt(var), "count": len(vals)}

def extract_rssi_stats(dev):
    """
    Returns {"avg","max","std","count"} or None.
    Accepts rssi_statistics, rssi_samples, avg_signal_strength/max_signal_strength,
    or single rssi / radiotap.dbm_antsignal. Filters < -100 dBm.
    """
    rs = dev.get("rssi_statistics")
    if rs and int(rs.get("count", 0)) > 0:
        return {
            "avg": float(rs["avg"]),
            "max": int(rs["max"]),
            "std": float(rs.get("std", 0.0)),
            "count": int(rs["count"]),
        }

    samples = [x for x in (dev.get("rssi_samples") or []) if x is not None]
    try:
        samples = [float(x) for x in samples if float(x) > -100]
    except Exception:
        samples = []
    s = _stats_from_list(samples)
    if s:
        return s

    if dev.get("avg_signal_strength") is not None:
        return {
            "avg": float(dev["avg_signal_strength"]),
            "max": int(dev.get("max_signal_strength", dev["avg_signal_strength"])),
            "std": float(dev.get("std_signal_strength", 0.0)),
            "count": int(dev.get("rssi_count", 1)),
        }
    if dev.get("rssi") is not None:
        val = float(dev["rssi"])
        return {"avg": val, "max": int(val), "std": 0.0, "count": 1}
    rt = dev.get("radiotap") or {}
    if rt.get("dbm_antsignal") is not None:
        val = float(rt["dbm_antsignal"])
        return {"avg": val, "max": int(val), "std": 0.0, "count": 1}
    return None

def _band_from_meta(dev):
    """Infer band from channel or frequency."""
    ch = dev.get("channel") or dev.get("wlan_channel")
    freq = dev.get("freq") or dev.get("frequency")
    try:
        if freq:
            f = float(freq)
            if f >= 5925: return "6"
            if f >= 4900: return "5"
            return "2.4"
        if ch:
            ch = int(ch)
            if 1 <= ch <= 14: return "2.4"
            if ch >= 180:     return "6"  # 6 GHz channel numbers (HE 6E)
            if 32 <= ch <= 173: return "5"
    except Exception:
        pass
    return "2.4"

def _proximity_zone(distance_ft):
    if distance_ft is None:
        return "unknown"
    if distance_ft <= 12: return "immediate"
    if distance_ft <= 25: return "close"
    if distance_ft <= 60: return "neighbor"
    return "distant"

def summarize_rssi(dev, *, calib_offsets=None, path_loss_n=None):
    """
    Writes dev['rssi_summary'] = {...}
    Uses unified stat extractor + band-aware distance. Does NOT fabricate distance when insufficient.
    """
    stats = extract_rssi_stats(dev)
    if not stats:
        dev["rssi_summary"] = {"count": 0, "zone": "unknown", "confidence": 0.0, "distance_ft": None}
        return

    avg, mx, std, cnt = stats["avg"], stats["max"], stats["std"], stats["count"]
    band = _band_from_meta(dev)
    offsets = calib_offsets or CALIB_OFFSETS
    n_map = path_loss_n or PATH_LOSS_N
    n = n_map.get(band, 3.0)
    ref_1m = BAND_1M_RSSI.get(band, -45.0)

    # Calibrated RSSI
    rssi = avg + float(offsets.get(band, 0.0))

    # Confidence: tighter RSSI spread + more samples → higher
    conf_spread = max(0.0, 1.0 - (std / 8.0))
    conf_count = 1.0 - exp(-cnt / 12.0)
    confidence = max(0.0, min(1.0, 0.5 * conf_spread + 0.5 * conf_count))

    # Distance only if enough samples
    distance_ft = None
    if cnt >= MIN_RSSI_SAMPLES_FOR_DISTANCE:
        # Free-space-ish log-distance model
        distance_m = 10 ** ((ref_1m - rssi) / (10.0 * n))
        distance_ft = distance_m * 3.28084
        if distance_ft > MAX_REASONABLE_DISTANCE_FT:
            distance_ft = None  # clamp absurd results

    zone = _proximity_zone(distance_ft)

    dev["rssi_summary"] = {
        "avg": round(avg, 1),
        "max": int(mx),
        "std": round(std, 2),
        "count": int(cnt),
        "band": band,
        "distance_ft": None if distance_ft is None else round(distance_ft, 1),
        "confidence": round(confidence, 2),
        "zone": zone,
    }

def mirror_proximity_into_rssi(dev):
    """
    If upstream wrote proximity analysis separately, mirror its zone/conf/distance into rssi_summary.
    """
    prox = dev.get("proximity_analysis") or dev.get("distance_analysis") or {}
    cls = prox.get("proximity_classification") or {}
    # Pull the best available distance
    _dist = prox.get("distance_ft") or prox.get("distance") or cls.get("distance_ft")

    def _to_float(s):
        try:
            return float(s)
        except Exception:
            return None

    distance_ft = _to_float(_dist)

    rs = dev.get("rssi_summary") or {"count": 0}
    if "zone" not in rs or rs.get("zone") in (None, "unknown"):
        zone = (cls.get("zone") or prox.get("zone") or rs.get("zone") or "unknown").lower()
        rs["zone"] = zone
    # prefer existing confidence if higher
    conf = max(float(rs.get("confidence") or 0.0), float(cls.get("confidence") or prox.get("confidence") or 0.0))
    rs["confidence"] = round(conf, 2)
    # do not overwrite a computed good distance with placeholder / nonsense
    if rs.get("distance_ft") in (None, 0) and distance_ft and distance_ft <= MAX_REASONABLE_DISTANCE_FT:
        rs["distance_ft"] = round(distance_ft, 1)
    dev["rssi_summary"] = rs

def fix_distance_fallback(dev):
    """
    Remove '200 ft' and other placeholders, or too-few-sample distances.
    """
    rs = dev.get("rssi_summary") or {}
    cnt = int(rs.get("count") or (dev.get("rssi_statistics") or {}).get("count") or 0)
    dist = rs.get("distance_ft")
    looks_placeholder = (dist == 200 or dist == 200.0 or dist == "200")
    looks_absurd = dist is not None and isinstance(dist, (int, float)) and float(dist) > MAX_REASONABLE_DISTANCE_FT

    if cnt < MIN_RSSI_SAMPLES_FOR_DISTANCE or looks_placeholder or looks_absurd:
        reason = []
        if cnt < MIN_RSSI_SAMPLES_FOR_DISTANCE: reason.append(f"insufficient_rssi_samples:{cnt}")
        if looks_placeholder: reason.append("placeholder_distance_removed")
        if looks_absurd: reason.append(f"distance_out_of_bounds:{dist}")
        rs["distance_ft"] = None
        rs["zone"] = rs.get("zone") or "unknown"
        rs["confidence"] = rs.get("confidence") or 0.0
        dev["rssi_summary"] = rs
        dev["distance_note"] = ",".join(reason) if reason else "unspecified"

# =========================
# Consistency vs. movement
# =========================
def reconcile_movement_consistency(dev, std_stationary_thr=2.0, min_samples=10):
    """
    Avoid contradictions like "Very Consistent" + movement_detected:true.
    - If movement_detected == True, force label to 'Variable'.
    - Else if enough samples and std < threshold, label 'Very Consistent (stationary/stable)'.
    Writes dev['signal_consistency'].
    """
    rs = dev.get("rssi_summary") or {}
    std = float(rs.get("std") or 0.0)
    cnt = int(rs.get("count") or 0)
    movement = bool(dev.get("movement_detected")) if "movement_detected" in dev else None
    label = (dev.get("signal_consistency") or "").lower()

    if movement is True:
        dev["signal_consistency"] = "Variable"
        if "consistency_note" not in dev:
            dev["consistency_note"] = "adjusted_due_to_movement_true"
        return

    if movement is False and cnt >= min_samples and std < std_stationary_thr:
        dev["signal_consistency"] = "Very Consistent (stationary/stable)"
        return

    if not label:
        dev["signal_consistency"] = "Consistent" if std < 4.0 and cnt >= 5 else "Variable"

# =========================
# Event roll-up + scoring
# =========================
def _event_weight(ev_type: str | None) -> int:
    t = (ev_type or "").lower()
    for k, w in SEVERITY_WEIGHTS.items():
        if k != "_default" and k in t:
            return w
    return SEVERITY_WEIGHTS["_default"]

def _proximity_multiplier(rssi_summary: dict | None) -> float:
    if not rssi_summary:
        return 1.0
    zone = (rssi_summary.get("zone") or "distant").lower()
    base = PROX_MULT_BY_ZONE.get(zone, 1.0)
    conf = float(rssi_summary.get("confidence") or 0.0)
    # Smooth 0..1 curve that approaches 1 as confidence rises
    conf_adj = 0.6 + 0.4 * (1 - exp(-3.0 * conf))
    return base * conf_adj

def _device_score(dev: dict) -> int:
    events = dev.get("security_events") or []
    base = sum(_event_weight(ev.get("type")) for ev in events)
    mult = _proximity_multiplier(dev.get("rssi_summary"))
    return int(round(base * mult))

def _rollup_layer(devs):
    total = 0
    by_type = Counter()
    peak = 0
    for d in devs:
        events = d.get("security_events") or []
        total += len(events)
        by_type.update([((ev.get("type") or "unknown").lower()) for ev in events])
        peak = max(peak, _device_score(d))
    return total, dict(sorted(by_type.items(), key=lambda x: -x[1])), peak

def _count_valid_rssi(devs, min_samples=3):
    """How many devices have enough RSSI samples to be useful?"""
    n = 0
    for d in devs:
        rs = d.get("rssi_summary") or {}
        if int(rs.get("count") or 0) >= min_samples:
            n += 1
    return n

# --- TRIANGULATION READINESS (helpers) ---
def _position_counts(dev):
    """
    Returns list of (position_id, rssi_count) discovered from common shapes:
      - dev["positions"] = { "pos1": {...}, "pos2": {...}, ... }
      - dev["triangulation"]["per_position"] = { ... } or [ ... ]
      - dev["rssi_by_position"] / dev["triangulation_data"] with similar fields
    Looks for rssi_summary.count, rssi_statistics.count, or len(rssi_samples).
    """
    out = []

    def _extract_from_node(node):
        if isinstance(node, dict):
            # nested "per_position"
            if "per_position" in node and isinstance(node["per_position"], (dict, list)):
                _extract_from_node(node["per_position"])
                return
            for pid, pdata in node.items():
                if not isinstance(pdata, dict):
                    continue
                cnt = None
                rs = pdata.get("rssi_summary") or {}
                st = pdata.get("rssi_statistics") or {}
                if rs.get("count") is not None:
                    cnt = int(rs.get("count") or 0)
                elif st.get("count") is not None:
                    cnt = int(st.get("count") or 0)
                elif isinstance(pdata.get("rssi_samples"), list):
                    cnt = len(pdata["rssi_samples"])
                if cnt is not None:
                    out.append((str(pid), int(cnt)))
        elif isinstance(node, list):
            for item in node:
                if not isinstance(item, dict):
                    continue
                pid = item.get("position") or item.get("id") or item.get("name")
                rs = item.get("rssi_summary") or {}
                st = item.get("rssi_statistics") or {}
                if rs.get("count") is not None:
                    cnt = int(rs.get("count") or 0)
                elif st.get("count") is not None:
                    cnt = int(st.get("count") or 0)
                elif isinstance(item.get("rssi_samples"), list):
                    cnt = len(item["rssi_samples"])
                else:
                    cnt = None
                if pid and cnt is not None:
                    out.append((str(pid), int(cnt)))

    for key in ("positions", "rssi_by_position", "triangulation", "triangulation_data"):
        node = dev.get(key)
        if node:
            _extract_from_node(node)

    return out

def triangulation_readiness(dev, min_positions=2, min_samples_per_pos=5):
    pcs = _position_counts(dev)
    good = [(pid, cnt) for pid, cnt in pcs if cnt >= min_samples_per_pos]
    ok_positions = sorted({pid for pid, _ in good})
    return {
        "ready": len(ok_positions) >= min_positions,
        "positions_ok": len(ok_positions),
        "positions": {pid: cnt for pid, cnt in good}
    }
# --- end TRIANGULATION READINESS ---

# =========================
# Main entry point
# =========================
def apply_all(report: dict,
              *,
              calib_offsets: dict | None = None,
              path_loss_n: dict | None = None) -> dict:
    """
    Mutates report in place:
      - normalizes timestamps (report/devices/events)
      - builds/repairs rssi_summary (band-aware distance + confidence)
      - mirrors proximity info if provided separately
      - removes 200-ft placeholder / too-few-sample distances
      - reconciles movement vs. consistency labeling
      - rolls up device events to file/global counters
      - computes proximity-weighted risk score and level
      - surfaces top offenders
      - aligns summary & device_intelligence RSSI counters
      - computes triangulation readiness stats
    """
    # Normalize report-level times (expanded set)
    for k in TOP_TIME_FIELDS:
        if k in report:
            _norm_time_field(report, k)

    da = report.get("detailed_analysis") or {}
    # Devices may be dict (keyed by MAC) or list
    wifi_raw = da.get("wifi_devices") or {}
    ble_raw  = da.get("bluetooth_devices") or da.get("ble_devices") or {}

    wifi_devs = list(wifi_raw.values()) if isinstance(wifi_raw, dict) else (wifi_raw if isinstance(wifi_raw, list) else [])
    ble_devs  = list(ble_raw.values())  if isinstance(ble_raw,  dict) else (ble_raw  if isinstance(ble_raw,  list) else [])

    # Per-device normalization + RSSI + proximity + fallback fix + consistency reconciliation
    for dev in wifi_devs + ble_devs:
        for key in ("first_seen", "last_seen"):
            _norm_time_field(dev, key)
        for ev in (dev.get("security_events") or []):
            for key in ("start", "end", "timestamp"):
                _norm_time_field(ev, key)

        summarize_rssi(dev, calib_offsets=calib_offsets or CALIB_OFFSETS,
                            path_loss_n=path_loss_n or PATH_LOSS_N)
        mirror_proximity_into_rssi(dev)
        fix_distance_fallback(dev)
        reconcile_movement_consistency(dev)

        # --- TRIANGULATION READINESS (per-device flag) ---
        dev["triangulation_ready"] = triangulation_readiness(dev)
        # --- end TRIANGULATION READINESS ---

    # Roll-up Wi-Fi / BLE
    wifi_total, wifi_by_type, _ = _rollup_layer(wifi_devs)
    ble_total,  ble_by_type,  _ = _rollup_layer(ble_devs)

    wifi_rssi_ok = _count_valid_rssi(wifi_devs, min_samples=3)
    ble_rssi_ok  = _count_valid_rssi(ble_devs,  min_samples=3)

    # Write layer results (list or dict shapes) — ALWAYS include event_types on every block
    wifi_results = report.get("wifi_results", [])
    if isinstance(wifi_results, list):
        if not wifi_results:
            wifi_results.append({})
        wifi_results[0]["security_event_count"] = int(wifi_total)
        wifi_results[0]["event_types"] = wifi_by_type or {}
        # ensure every additional block has event_types (even if empty)
        for i in range(1, len(wifi_results)):
            wifi_results[i]["event_types"] = wifi_results[i].get("event_types", {}) or {}
        report["wifi_results"] = wifi_results
    elif isinstance(wifi_results, dict):
        wifi_results["security_event_count"] = int(wifi_total)
        wifi_results["event_types"] = wifi_by_type or {}
        report["wifi_results"] = wifi_results
    else:
        report["wifi_results"] = [{"security_event_count": int(wifi_total), "event_types": wifi_by_type or {}}]

    # BLE layer name varies — write to bluetooth_results
    ble_results = report.get("ble_results") or report.get("bluetooth_results") or []
    if isinstance(ble_results, list):
        if not ble_results:
            ble_results.append({})
        ble_results[0]["security_event_count"] = int(ble_total)
        ble_results[0]["event_types"] = ble_by_type or {}
        for i in range(1, len(ble_results)):
            ble_results[i]["event_types"] = ble_results[i].get("event_types", {}) or {}
        report["bluetooth_results"] = ble_results
    elif isinstance(ble_results, dict):
        ble_results["security_event_count"] = int(ble_total)
        ble_results["event_types"] = ble_by_type or {}
        report["bluetooth_results"] = ble_results
    else:
        report["bluetooth_results"] = [{"security_event_count": int(ble_total), "event_types": ble_by_type or {}}]

    # Compute offenders list (Wi-Fi drives the headline)
    offenders = []
    for d in wifi_devs:
        s = _device_score(d)
        if s:
            offenders.append({
                "mac": d.get("mac_address") or d.get("bssid") or d.get("mac") or "unknown",
                "score": s,
                "zone": (d.get("rssi_summary") or {}).get("zone") or "unknown",
                "events": len(d.get("security_events") or []),
            })
    offenders.sort(key=lambda x: -x["score"])

    # Summary + risk
    summary = report.setdefault("summary_statistics", {})
    total_events_global = int(wifi_total + ble_total)
    summary["total_security_events"] = total_events_global

    # Sum top-5 offenders for the risk headline
    overall_score = int(sum(o["score"] for o in offenders[:5]))
    summary["risk_score"] = overall_score

    lvl = "LOW"
    for name, thresh in RISK_THRESHOLDS:
        if overall_score >= thresh:
            lvl = name
    summary["risk_level"] = lvl
    if offenders:
        summary["top_offenders"] = offenders[:10]

    # Unified RSSI health counters
    summary["rssi_devices_with_valid_samples"] = {"wifi": int(wifi_rssi_ok), "ble": int(ble_rssi_ok)}
    summary["devices_with_distance"] = {
        "wifi": sum(1 for d in wifi_devs if (d.get("rssi_summary") or {}).get("distance_ft") not in (None, 0)),
        "ble":  sum(1 for d in ble_devs  if (d.get("rssi_summary") or {}).get("distance_ft") not in (None, 0)),
    }

    # --- TRIANGULATION READINESS (summary) ---
    tri_ready_wifi = sum(1 for d in wifi_devs if (d.get("triangulation_ready") or {}).get("ready"))
    tri_candidates = sorted(
        (
            {
                "mac": d.get("mac_address") or d.get("bssid") or d.get("mac") or "unknown",
                "positions_ok": (d.get("triangulation_ready") or {}).get("positions_ok", 0),
                "positions": (d.get("triangulation_ready") or {}).get("positions", {}),
            }
            for d in wifi_devs
        ),
        key=lambda x: -x["positions_ok"]
    )
    summary["triangulation_readiness"] = {
        "wifi_devices_ready": int(tri_ready_wifi),
        "top_candidates": tri_candidates[:10]
    }
    # --- end TRIANGULATION READINESS ---

    # Keep device_intelligence in sync with the same counters (so no mismatches)
    di = report.setdefault("device_intelligence", {})
    wifi_sum = di.setdefault("wifi_summary", {})
    ble_sum  = di.setdefault("ble_summary", {})
    wifi_sum["devices_with_rssi"] = int(wifi_rssi_ok)
    wifi_sum["devices_with_distance"] = summary["devices_with_distance"]["wifi"]
    wifi_sum["triangulation_ready"] = int(tri_ready_wifi)
    ble_sum["devices_with_rssi"] = int(ble_rssi_ok)
    ble_sum["devices_with_distance"] = summary["devices_with_distance"]["ble"]

    # Mirror into 'bluetooth_summary' if you also publish it
    di.setdefault("bluetooth_summary", {}).update({
        "devices_with_rssi": int(ble_rssi_ok),
        "devices_with_distance": summary["devices_with_distance"]["ble"]
    })

    return report