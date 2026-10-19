"""
Tier 2 — AI Behavioral Analysis.

Monitors user behavior patterns and detects anomalies through
baseline comparison, dynamic risk scoring, and ML-based detection.

بيربط:
- IPLogger (بيانات سلوكية من Redis)
- AnomalyDetector (ML + Statistical)
- session_profiles (in-memory baseline tracking)

Part B upgrades (2026-10-19):
- B1: Session identity correlation — profiles are keyed by
  authenticated user when a JWT is present (``user:<id>``), otherwise
  by IP (``ip:<ip>``). A user on a rotating mobile IP keeps ONE
  coherent baseline; an IP-rotating attacker can no longer look like
  N innocent strangers.
- B2: Time-decayed risk signals (15s half-life, 60s window) replace the
  fixed last-N counts, plus a z-score deviation signal against the
  session's own clean baseline.
- B4: Baseline poisoning guard — the baseline absorbs ONLY clean
  traffic (2xx/3xx), with a capped EWMA learning rate (alpha=0.1), so
  a slow attacker cannot wash "normal" to match themselves.
"""

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import time as _time

import structlog

from app.core.anomaly_detection import AnomalyDetector
from app.core.ip_logger import IPLogger

logger = structlog.get_logger()


class BehavioralAnalyzer:
    """
    Tier 2: AI Behavioral Analysis.

    بيستخدم:
    - IPLogger.get_behavioral_data (بيانات سلوكية من Redis)
    - AnomalyDetector.detect (ML + Statistical)
    - session_profiles (in-memory baseline tracking)
    """

    # ─── Heuristic limits (risk scoring) ───────────────────
    ANOMALY_THRESHOLD = 0.7

    # ─── B2: time-decay signal parameters ──────────────────
    RISK_WINDOW_SECONDS = 60.0          # ignore anything older
    RISK_HALF_LIFE_SECONDS = 15.0       # exponential decay half-life
    WEIGHTED_RATE_THRESHOLD = 40.0      # ~sustained 1.9 req/s
    WEIGHTED_RATE_RAMP_START = 25.0     # ramp begins at half-threshold
    WEIGHTED_ERROR_THRESHOLD = 8.0      # error-weight in the window
    WEIGHTED_ERROR_RAMP_START = 4.0
    ENUMERATION_WINDOW_ENTRIES = 60     # recent-entries lookback
    ENUMERATION_UNIQUE_THRESHOLD = 20   # unique endpoints in window
    ENUMERATION_MAX = 30                # full contribution at this count

    # contribution caps (sum = 1.25, clamped to 1.0)
    WEIGHT_RATE = 0.30
    WEIGHT_ERRORS = 0.25
    WEIGHT_ENUMERATION = 0.25
    WEIGHT_ADMIN = 0.15
    WEIGHT_DEVIATION = 0.30

    # ─── D5: session-drift (device/IP) parameters ──────────
    # Authenticated sessions track the dominant (IP /24, UA-finger-
    # print) pair. A NEW pair while the dominant one is established
    # is a session-takeover precursor (stolen token used from a
    # different network/device). Alert-only: it raises the risk
    # score — it never blocks by itself.
    WEIGHT_DRIFT = 0.15
    DRIFT_MIN_SAMPLES = 3            # ignore cold-start flapping
    DRIFT_MAX_PAIRS_PER_USER = 32    # bound the per-user pair store

    # ─── B4: baseline parameters (poisoning guard) ─────────
    BASELINE_ALPHA = 0.1                # max 10% adaptation per step
    BASELINE_MIN_SAMPLES = 50           # no z-signal before this
    Z_LOW = 3.0                         # start of deviation contribution
    Z_HIGH = 8.0                        # full contribution

    def __init__(self) -> None:
        # ML + Statistical detector (stays IP-keyed: forensic layer)
        self.anomaly_detector = AnomalyDetector()

        # In-memory tracking (keyed by session key, see session_key())
        self.session_profiles: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.risk_scores: Dict[str, float] = defaultdict(float)
        # B4: per-session clean-traffic baselines
        # {session_key: {"mean": float, "var": float, "samples": int}}
        self.baselines: Dict[str, Dict[str, float]] = {}
        # D5: per-user session pairs (IP /24, UA fingerprint)
        # {user_id: Counter{(ip24, ua_fp): count}}
        self.user_session_pairs: Dict[str, Dict] = defaultdict(dict)

    # ─── B1: Session identity ──────────────────────────────

    @staticmethod
    def extract_user_id(authorization_header: Optional[str]) -> Optional[str]:
        """
        Extract the authenticated user's ID from an Authorization
        header, for baseline CORRELATION ONLY.

        - Valid tokens: full decode (signature + expiry).
        - Expired tokens: signature-verified, expiry-ignored decode —
          a genuine token whose clock has lapsed still identifies the
          session owner for baselining. A FORGED token fails the
          signature check and yields None (an attacker can never claim
          someone else's identity this way).
        - Anything unparseable: None (anonymous session).
        - The identity is used ONLY for baseline correlation, never
          for access decisions (those belong to the endpoints).
        """
        if not authorization_header:
            return None
        header = authorization_header.strip()
        if not header.lower().startswith("bearer "):
            return None
        token = header[7:].strip()
        if not token:
            return None

        from app.core.security import decode_token

        payload = decode_token(token)
        if payload and payload.get("sub"):
            return str(payload["sub"])

        # Fallback for EXPIRED tokens: verify the signature (so a forged
        # token can never claim a victim's identity) but skip the expiry
        # check — a genuinely-issued token whose clock has simply lapsed
        # still tells us WHO the session belongs to, which is all the
        # baseline correlation needs. Identity here is NEVER used for
        # access decisions; that is the endpoint's job.
        try:
            from jose import jwt as _jwt

            from app.core.config import settings

            expired_payload = _jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},
            )
            sub = expired_payload.get("sub")
            return str(sub) if sub else None
        except Exception:
            return None

    @staticmethod
    def session_key(client_ip: str, user_id: Optional[str]) -> str:
        """
        B1: one behavioral identity per USER (across IPs) when
        authenticated, per IP otherwise.
        """
        return f"user:{user_id}" if user_id else f"ip:{client_ip}"

    # ─── D5: session-drift helpers ────────────────────────
    @staticmethod
    def _ip24(client_ip: str) -> str:
        """Collapse an IPv4 to its /24 so same-subnet carrier-grade
        NAT / mobile flapping doesn't read as drift. IPv6 → /48."""
        try:
            if ":" in client_ip:
                parts = client_ip.split(":")
                return ":".join(parts[:3])
            octets = client_ip.split(".")
            if len(octets) == 4:
                return ".".join(octets[:3])
        except Exception:  # noqa: BLE001
            pass
        return client_ip

    @staticmethod
    def _ua_fingerprint(user_agent: Optional[str]) -> str:
        """Stable short fingerprint of the user agent (privacy: raw UA
        never stored)."""
        if not user_agent:
            return "no-ua"
        return hashlib.sha256(user_agent[:200].encode()).hexdigest()[:12]

    def _observe_session_pair(
        self, user_id: str, client_ip: str, user_agent: Optional[str]
    ) -> None:
        """Record one (IP /24, UA) observation for a user and bound the
        per-user pair store."""
        pair = (self._ip24(client_ip), self._ua_fingerprint(user_agent))
        pairs = self.user_session_pairs[user_id]
        pairs[pair] = pairs.get(pair, 0) + 1
        if len(pairs) > self.DRIFT_MAX_PAIRS_PER_USER:
            # Drop the least-recently-seen (lowest count, then oldest
            # inserted) pair to stay bounded.
            overflow = len(pairs) - self.DRIFT_MAX_PAIRS_PER_USER
            for key in sorted(pairs, key=lambda k: pairs[k])[:overflow]:
                del pairs[key]

    def _session_drift_reason(
        self, user_id: str, client_ip: str, user_agent: Optional[str]
    ) -> Optional[str]:
        """Return a drift reason string if the current (IP/24, UA) pair
        is NOT the user's established dominant pair (None otherwise)."""
        pairs = self.user_session_pairs.get(user_id)
        if not pairs:
            return None
        total = sum(pairs.values())
        if total < self.DRIFT_MIN_SAMPLES:
            return None
        dominant = max(pairs, key=lambda k: pairs[k])
        current = (self._ip24(client_ip), self._ua_fingerprint(user_agent))
        if current == dominant:
            return None
        dom_ip, dom_ua = dominant
        cur_ip, _cur_ua = current
        if cur_ip == dom_ip and _cur_ua != dom_ua:
            return "Session drift: new device/user-agent for this user"
        if cur_ip != dom_ip and _cur_ua == dom_ua:
            return "Session drift: new network (/24) for this user"
        return "Session drift: new network AND device for this user"

    # ─── Main API ──────────────────────────────────────────

    async def analyze(
        self, client_ip: str, user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        بيحلل سلوك الجلسة (user- أو ip-based).

        بيرجع:
        - is_anomaly, score, reason/reasons, method,
          risk_score, anomaly_detected (شكل متوافق مع القديم)
        """
        skey = self.session_key(client_ip, user_id)

        # 1. ML + Statistical detection (IP-keyed forensic layer)
        behavioral_data = await IPLogger.get_behavioral_data(client_ip)
        ml_result = self.anomaly_detector.detect(
            session_id=client_ip,
            behavioral_data=behavioral_data,
        )

        # 2. Heuristic risk scoring (session-keyed, user-aware)
        profile = self.session_profiles.get(skey, [])
        now = _time.time()
        score, reasons = self._score_signals(
            profile, profile[-1] if profile else {}, now, skey
        )
        heuristic_result = {
            "score": score,
            "is_anomaly": score > self.ANOMALY_THRESHOLD,
            "reasons": reasons,
            "method": "heuristic",
        }

        # 3. اجمع النتايج
        final_result = self._merge_results(ml_result, heuristic_result)

        # 4. سجل التحذير لو فيه شذوذ
        if final_result.get("is_anomaly"):
            logger.warning(
                "behavioral_anomaly_detected",
                session=skey,
                ip=client_ip,
                score=final_result.get("score"),
                method=final_result.get("method"),
                reasons=final_result.get("reasons"),
            )

        return final_result

    async def record_activity(
        self,
        client_ip: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: float,
        user_id: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل نشاط (user-aware).

        1. AnomalyDetector — IP-keyed (forensic layer).
        2. IPLogger — IP-keyed (Redis history).
        3. session_profiles + baselines — session-keyed (B1).
        6. D5 session-pair observation — user-keyed (device/IP drift).
        """
        skey = self.session_key(client_ip, user_id)
        now_dt = datetime.now(timezone.utc)
        now_ts = now_dt.timestamp()

        # D5: observe the (IP/24, UA) pair for session-drift detection.
        if user_id:
            try:
                self._observe_session_pair(user_id, client_ip, user_agent)
            except Exception as e:
                logger.error("tier2_observe_pair_failed", error=str(e))

        # 1. سجل في AnomalyDetector (IP-keyed)
        self.anomaly_detector.record_request(
            session_id=client_ip,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

        # 2. سجل في IPLogger (Redis — IP-keyed)
        try:
            info = {
                "ip_address": client_ip,
                "user_agent": "unknown",
                "method": method,
                "path": endpoint,
                "query": "",
                "status_code": status_code,
                "response_time_ms": response_time_ms,
                "timestamp": now_dt.isoformat(),
                "unix_timestamp": now_ts,
            }
            await IPLogger.log_ip(client_ip, info)
        except Exception as e:
            logger.error("tier2_log_ip_failed", error=str(e))

        # 3. سجل في session_profiles (session-keyed — B1)
        activity = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "user_id": user_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "timestamp": now_dt.isoformat(),
            "unix_timestamp": now_ts,
        }
        profile = self.session_profiles[skey]
        profile.append(activity)
        if len(profile) > 1000:
            self.session_profiles[skey] = profile = profile[-1000:]

        # 4. B4: update the clean-traffic baseline (guard built in)
        self._maybe_update_baseline(skey, profile, activity)

        # 5. risk score الحالي
        risk_score, _reasons = self._score_signals(profile, activity, now_ts, skey)
        self.risk_scores[skey] = risk_score
        # Alias under the raw IP key so IP-based lookups (monitoring,
        # threat-assessment) still see authenticated traffic from it.
        ip_key = self.session_key(client_ip, None)
        self.risk_scores[ip_key] = max(
            self.risk_scores.get(ip_key, 0.0), risk_score
        )

        return {
            "risk_score": risk_score,
            "anomaly_detected": risk_score > self.ANOMALY_THRESHOLD,
            "reasons": self._get_anomaly_reasons(skey, activity),
        }

    async def get_session_risk(self, client_ip: str) -> float:
        """
        بترجع risk score الحالي (IP-based lookup, compatibility).
        """
        ip_key = self.session_key(client_ip, None)
        if ip_key in self.risk_scores:
            return self.risk_scores[ip_key]

        result = await self.analyze(client_ip)
        return result.get("score", 0.0)

    # ─── B2: Time-decayed risk signals ─────────────────────

    @staticmethod
    def _decay_weight(age_seconds: float, half_life: float) -> float:
        """Exponential decay weight: 1.0 at t=0, 0.5 at one half-life."""
        if age_seconds <= 0:
            return 1.0
        return 0.5 ** (age_seconds / half_life)

    def _weighted_signals(
        self, profile: List[Dict[str, Any]], now: float
    ) -> Dict[str, float]:
        """
        B2: single 60s pass over the profile computing time-decayed
        request weight, error weight, and recent unique endpoints.
        """
        hl = self.RISK_HALF_LIFE_SECONDS
        rate_weight = 0.0
        error_weight = 0.0
        window_entries = 0
        unique_endpoints = set()

        # Profile is append-ordered; walk from the tail for the window.
        for a in reversed(profile):
            ts = a.get("unix_timestamp")
            if ts is None:
                continue
            age = now - ts
            if age > self.RISK_WINDOW_SECONDS:
                break
            w = self._decay_weight(age, hl)
            rate_weight += w
            if a.get("status_code", 200) >= 400:
                error_weight += w
            if window_entries < self.ENUMERATION_WINDOW_ENTRIES:
                unique_endpoints.add(a.get("endpoint", ""))
                window_entries += 1

        return {
            "rate_weight": rate_weight,
            "error_weight": error_weight,
            "unique_endpoints": len(unique_endpoints),
        }

    def _baseline_deviation(
        self, skey: str, profile: List[Dict[str, Any]], now: float
    ) -> Optional[float]:
        """
        B2+B4: z-score of the current weighted rate against the
        session's CLEAN baseline. None while the baseline is too young
        (cold start must not flag strangers — the heuristics cover them).
        """
        base = self.baselines.get(skey)
        if not base or base["samples"] < self.BASELINE_MIN_SAMPLES:
            return None
        if not profile:
            return None
        signals = self._weighted_signals(profile, now)
        mean = base["mean"]
        std = max(base["var"] ** 0.5, 1e-6)
        return (signals["rate_weight"] - mean) / std

    def _score_signals(
        self,
        profile: List[Dict[str, Any]],
        activity: Dict[str, Any],
        now: float,
        skey: str = "",
    ) -> tuple[float, List[str]]:
        """
        B2: the single risk computation. Returns (score, reasons).

        Signals (capped contributions, clamped to 1.0):
          1. Time-decayed request rate          (0.30)
          2. Time-decayed error rate            (0.25)
          3. Endpoint enumeration in window     (0.25)
          4. Admin endpoint access              (0.15)
          5. Deviation from clean baseline (z)  (0.30)
        """
        reasons: List[str] = []
        if not profile:
            return 0.0, reasons

        signals = self._weighted_signals(profile, now)
        score = 0.0

        # 1. Request rate (time-decayed)
        rate = signals["rate_weight"]
        if rate > self.WEIGHTED_RATE_RAMP_START:
            frac = min(
                1.0,
                (rate - self.WEIGHTED_RATE_RAMP_START)
                / max(1e-6, self.WEIGHTED_RATE_THRESHOLD - self.WEIGHTED_RATE_RAMP_START),
            )
            score += self.WEIGHT_RATE * frac
            if frac >= 0.5:
                reasons.append(
                    f"High request rate: decayed weight {rate:.1f} "
                    f"over 60s (threshold {self.WEIGHTED_RATE_THRESHOLD:.0f})"
                )

        # 2. Error rate (time-decayed)
        errors = signals["error_weight"]
        if errors > self.WEIGHTED_ERROR_RAMP_START:
            frac = min(
                1.0,
                (errors - self.WEIGHTED_ERROR_RAMP_START)
                / max(1e-6, self.WEIGHTED_ERROR_THRESHOLD - self.WEIGHTED_ERROR_RAMP_START),
            )
            score += self.WEIGHT_ERRORS * frac
            reasons.append(
                f"High error rate: decayed error weight {errors:.1f} over 60s"
            )

        # 3. Endpoint enumeration (window-bounded)
        unique = signals["unique_endpoints"]
        if unique > self.ENUMERATION_UNIQUE_THRESHOLD:
            frac = min(
                1.0,
                (unique - self.ENUMERATION_UNIQUE_THRESHOLD)
                / max(
                    1e-6,
                    self.ENUMERATION_MAX - self.ENUMERATION_UNIQUE_THRESHOLD,
                ),
            )
            score += self.WEIGHT_ENUMERATION * frac
            reasons.append(
                f"Endpoint enumeration: {unique} unique endpoints in window"
            )

        # 4. Admin endpoint access (this request)
        if "/admin" in activity.get("endpoint", ""):
            score += self.WEIGHT_ADMIN
            reasons.append("Admin endpoint access")

        # 5. Deviation from the session's clean baseline (B4-guarded)
        z = self._baseline_deviation(skey, profile, now)
        if z is not None and z > self.Z_LOW:
            frac = min(1.0, (z - self.Z_LOW) / max(1e-6, self.Z_HIGH - self.Z_LOW))
            score += self.WEIGHT_DEVIATION * frac
            reasons.append(
                f"Behavioral deviation: z={z:.1f} vs clean baseline "
                f"({self.baselines.get(skey or '', {}).get('samples', 0)} samples)"
            )

        # 6. Session drift (D5) — authenticated sessions only.
        # A new (IP/24, UA) pair while a dominant one is established is
        # a session-takeover precursor. Alert-only: it raises the risk
        # score; the middleware decides whether to surface an alert.
        if skey.startswith("user:"):
            _uid = skey[len("user:"):]
            try:
                drift = self._session_drift_reason(
                    _uid,
                    activity.get("client_ip", ""),
                    activity.get("user_agent"),
                )
            except Exception:  # noqa: BLE001 — scoring must never raise
                drift = None
            if drift:
                score += self.WEIGHT_DRIFT
                reasons.append(drift)

        return min(score, 1.0), reasons

    def _calculate_risk(self, session_id: str, activity: Dict[str, Any]) -> float:
        """Compatibility wrapper — returns the risk score only."""
        profile = self.session_profiles.get(session_id, [])
        score, _reasons = self._score_signals(
            profile, activity, _time.time(), session_id
        )
        return score

    def _get_anomaly_reasons(
        self,
        session_id: str,
        activity: Dict[str, Any],
    ) -> List[str]:
        """Compatibility wrapper — returns the reasons only."""
        profile = self.session_profiles.get(session_id, [])
        _score, reasons = self._score_signals(
            profile, activity, _time.time(), session_id
        )
        return reasons

    # ─── B4: Baseline poisoning guard ──────────────────────

    def _maybe_update_baseline(
        self,
        skey: str,
        profile: List[Dict[str, Any]],
        activity: Dict[str, Any],
    ) -> None:
        """
        B4: the baseline learns ONLY from clean traffic.

        - 4xx/5xx responses (failed auth, validation rejections, scans,
          DoS attempts) NEVER shape "normal" — a slow attacker cannot
          wash the baseline to match themselves.
        - EWMA with alpha=0.1: at most 10% adaptation per clean
          request, so even an all-2xx stealth attack shifts the
          baseline far too slowly to outrun the z-threshold.
        """
        status = activity.get("status_code", 200)
        if not (200 <= status < 400):
            return

        now = activity.get("unix_timestamp") or _time.time()
        signals = self._weighted_signals(profile, now)
        rate = signals["rate_weight"]

        base = self.baselines.get(skey)
        if base is None:
            base = {"mean": rate, "var": 0.0, "samples": 1}
            self.baselines[skey] = base
            return

        alpha = self.BASELINE_ALPHA
        diff = rate - base["mean"]
        base["mean"] += alpha * diff
        base["var"] = (1.0 - alpha) * (base["var"] + alpha * diff * diff)
        base["samples"] += 1

    # ─── Result Merging ────────────────────────────────────

    @staticmethod
    def _merge_results(
        ml_result: Dict[str, Any],
        heuristic_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        بيدمج نتايج ML مع نتايج Heuristic.

        القاعدة:
        - لو ML قال إنه anomaly → ناخد ML.
        - لو Heuristic قال إنه anomaly → ناخد Heuristic.
        - لو الاتنين قالوا normal → ناخد الأعلى score.
        """
        ml_anomaly = ml_result.get("is_anomaly", False)
        heuristic_anomaly = heuristic_result.get("is_anomaly", False)

        # الحالة 1: ML قال anomaly
        if ml_anomaly:
            return {
                "is_anomaly": True,
                "score": ml_result.get("score", 0.0),
                "reason": ml_result.get("reason", "ml_anomaly"),
                "reasons": heuristic_result.get("reasons", []),
                "method": ml_result.get("method", "ml"),
                "risk_score": ml_result.get("score", 0.0),
                "anomaly_detected": True,
            }

        # الحالة 2: Heuristic قال anomaly
        if heuristic_anomaly:
            return {
                "is_anomaly": True,
                "score": heuristic_result.get("score", 0.0),
                "reason": "heuristic_anomaly",
                "reasons": heuristic_result.get("reasons", []),
                "method": "heuristic",
                "risk_score": heuristic_result.get("score", 0.0),
                "anomaly_detected": True,
            }

        # الحالة 3: الاتنين قالوا normal
        return {
            "is_anomaly": False,
            "score": max(
                ml_result.get("score", 0.0),
                heuristic_result.get("score", 0.0),
            ),
            "reason": ml_result.get("reason", "normal"),
            "reasons": heuristic_result.get("reasons", []),
            "method": ml_result.get("method", "ml"),
            "risk_score": max(
                ml_result.get("score", 0.0),
                heuristic_result.get("score", 0.0),
            ),
            "anomaly_detected": False,
        }
