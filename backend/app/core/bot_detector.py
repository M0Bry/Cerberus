"""
Bot Detector — Detects and classifies bots.

بيوفر:
- Bot detection based on multiple signals
- Good bot whitelist (Google, Bing, ...)
- Bad bot blacklist (scanners, scrapers)
- Behavioral analysis
- Redis-backed storage

الإشارات:
- User-Agent analysis
- Missing headers (Accept, Accept-Language, ...)
- Suspicious header patterns
- Known bot user-agents
- Behavioral patterns (too fast, too many 404s)
- Honeypot paths

الاستخدام:
- حماية من scrapers
- تقليل حمل الـ scanners
- Fair usage policy
"""

import re
import time
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class BotDetector:
    """
    Bot Detector.

    بيصنف الطلبات:
    - human: مستخدم حقيقي
    - good_bot: بوت مفيد (Google, Bing)
    - bad_bot: بوت ضار (scanner, scraper)
    - unknown_bot: بوت غير معروف
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Good Bots (سماح) ─────────────────────────────────
    GOOD_BOTS = [
        # Search Engines
        r"googlebot",
        r"bingbot",
        r"slurp",            # Yahoo
        r"duckduckbot",
        r"baiduspider",
        r"yandexbot",
        r"facebookexternalhit",
        r"twitterbot",
        r"linkedinbot",
        r"whatsapp",
        r"telegrambot",
        r"applebot",
        r"discordbot",
        # Monitoring
        r"uptimerobot",
        r"pingdom",
        r"statuscake",
        r"newrelicpinger",
        r"site24x7",
        # Feed Readers
        r"feedly",
        r"feedfetcher",
    ]

    # ─── Bad Bots (احجب) ──────────────────────────────────
    BAD_BOTS = [
        # Security Scanners
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"masscan",
        r"acunetix",
        r"nessus",
        r"openvas",
        r"qualys",
        r"nexpose",
        r"appscan",
        r"w3af",
        r"skipfish",
        r"wpscan",
        r"joomscan",
        r"droopescan",
        # Directory Brute Forcers
        r"dirbuster",
        r"gobuster",
        r"wfuzz",
        r"ffuf",
        r"feroxbuster",
        r"dirb",
        r"dirsearch",
        r"brutespray",
        # Password Brute Forcers
        r"hydra",
        r"medusa",
        r"patator",
        r"ncrack",
        r"crowbar",
        # Exploitation Tools
        r"metasploit",
        r"msfconsole",
        r"cobalt.?strike",
        r"empire",
        r"beef",
        r"commix",
        # Scripts/Clients
        r"curl",
        r"wget",
        r"python-requests",
        r"python-urllib",
        r"go-http-client",
        r"java/",
        r"libwww-perl",
        r"ruby",
        r"perl",
        r"okhttp",
        r"axios",
        r"node-fetch",
        # Scrapers
        r"scrapy",
        r"httrack",
        r"webcopier",
        r"wget",
        # SEO Tools
        r"ahrefsbot",
        r"semrushbot",
        r"mj12bot",
        r"dotbot",
        r"megaindex",
        r"blexbot",
    ]

    # ─── Suspicious Paths (Honeypots) ─────────────────────
    HONEYPOT_PATHS = [
        "/admin",
        "/wp-admin",
        "/wp-login",
        "/phpmyadmin",
        "/.env",
        "/.git",
        "/.htaccess",
        "/config",
        "/backup",
        "/backups",
        "/api/v1/admin",
        "/api/v1/config",
        "/robots.txt",  # scan indicator
        "/sitemap.xml",
        "/.well-known",
        "/xmlrpc.php",
        "/cgi-bin",
    ]

    # ─── Required Headers (المستخدم الحقيقي عنده) ────────
    REQUIRED_HEADERS = [
        "accept",
        "accept-language",
        "accept-encoding",
        "user-agent",
    ]

    # ─── Behavior Thresholds ──────────────────────────────
    FAST_REQUEST_THRESHOLD = 0.1     # 100ms بين الطلبات
    MAX_404_BEFORE_BAN = 20          # 20 خطأ 404 = bot
    BOT_SCORE_THRESHOLD = 50         # 50+ = bot

    # ─── Internal ──────────────────────────────────────────

    @classmethod
    def get_client(cls) -> Optional[redis.Redis]:
        """Lazy Redis client."""
        if cls._redis_client is None:
            try:
                cls._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
            except Exception as e:
                logger.error("bot_detector_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    # ─── Classification ────────────────────────────────────

    @classmethod
    def classify_user_agent(cls, user_agent: str) -> str:
        """
        بيصنف الـ User-Agent.

        Returns:
            human / good_bot / bad_bot / unknown
        """
        if not user_agent:
            return "unknown"

        ua_lower = user_agent.lower()

        # 1. Good bots?
        for pattern in cls.GOOD_BOTS:
            if re.search(pattern, ua_lower):
                return "good_bot"

        # 2. Bad bots?
        for pattern in cls.BAD_BOTS:
            if re.search(pattern, ua_lower):
                return "bad_bot"

        # 3. Human? (لازم يكون فيه Mozilla)
        if "mozilla" in ua_lower:
            return "human"

        return "unknown"

    @classmethod
    def analyze_request(cls, request) -> Dict[str, Any]:
        """
        بيحلل الطلب ويرجع score + signals.

        Returns:
            dict فيه:
            - bot_score: 0-100
            - classification: human/good_bot/bad_bot/unknown
            - signals: list of detected signals
            - is_bot: bool
            - should_block: bool
        """
        signals: List[str] = []
        score = 0

        ua = request.headers.get("user-agent", "")

        # 1. User-Agent analysis
        classification = cls.classify_user_agent(ua)

        if classification == "good_bot":
            # Good bots → سماح فوري
            return {
                "bot_score": 0,
                "classification": "good_bot",
                "signals": ["good_bot_ua"],
                "is_bot": True,
                "should_block": False,
            }

        if classification == "bad_bot":
            score += 80
            signals.append("bad_bot_ua")

        elif classification == "unknown":
            score += 30
            signals.append("unknown_ua")

        # 2. Empty User-Agent
        if not ua:
            score += 50
            signals.append("empty_ua")

        # 3. Missing required headers
        for header in cls.REQUIRED_HEADERS:
            if not request.headers.get(header):
                score += 10
                signals.append(f"missing_{header.replace('-', '_')}")

        # 4. Suspicious path
        path = request.url.path.lower()
        if path in cls.HONEYPOT_PATHS or any(
            path.startswith(hp) for hp in cls.HONEYPOT_PATHS
        ):
            score += 30
            signals.append("honeypot_path")

        # 5. HTTP version (bots غالباً HTTP/1.0)
        http_version = request.scope.get("http_version", "1.1")
        if http_version == "1.0":
            score += 15
            signals.append("http_1_0")

        # 6. Suspicious header patterns
        # بعض الـ bots بتستخدم headers غريبة
        if request.headers.get("x-forwarded-for") and request.headers.get("via"):
            score += 10
            signals.append("proxy_headers")

        # 7. Normalize
        score = min(score, 100)

        # 8. Classification النهائي
        if score >= cls.BOT_SCORE_THRESHOLD:
            final_class = "bad_bot" if score >= 80 else "unknown_bot"
            is_bot = True
            should_block = score >= 80
        else:
            final_class = "human"
            is_bot = False
            should_block = False

        return {
            "bot_score": score,
            "classification": final_class,
            "signals": signals,
            "is_bot": is_bot,
            "should_block": should_block,
            "user_agent": ua[:200],
        }

    # ─── Behavioral Detection ─────────────────────────────

    @classmethod
    async def record_request(
        cls,
        client_ip: str,
        path: str,
        status_code: int,
    ) -> None:
        """
        بيسجل طلب لتحليل السلوك.
        """
        client = cls.get_client()
        if not client:
            return

        try:
            now = time.time()
            key = f"bot:behavior:{client_ip}"

            # 1. سجل الطلب
            await client.lpush(key, f"{now}:{path}:{status_code}")
            await client.ltrim(key, 0, 99)  # آخر 100 طلب
            await client.expire(key, 600)  # 10 دقايق

            # 2. سجل 404s
            if status_code == 404:
                count_404 = await client.incr(f"bot:404:{client_ip}")
                if count_404 == 1:
                    await client.expire(f"bot:404:{client_ip}", 600)

        except Exception as e:
            logger.error("bot_detector_record_failed", error=str(e))

    @classmethod
    async def analyze_behavior(cls, client_ip: str) -> Dict[str, Any]:
        """
        بيحلل سلوك الـ IP.

        Returns:
            dict فيه:
            - is_suspicious: bool
            - signals: list
            - request_rate: طلب/ثانية
            - error_404_count: عدد 404
        """
        client = cls.get_client()
        if not client:
            return {
                "is_suspicious": False,
                "signals": [],
                "request_rate": 0.0,
                "error_404_count": 0,
            }

        try:
            signals: List[str] = []
            score = 0

            # 1. جيب آخر 100 طلب
            key = f"bot:behavior:{client_ip}"
            entries = await client.lrange(key, 0, 99)

            request_rate = 0.0
            if len(entries) >= 2:
                # فكك الـ entries
                timestamps = []
                for entry in entries:
                    try:
                        parts = entry.split(":")
                        timestamps.append(float(parts[0]))
                    except (ValueError, IndexError):
                        continue

                if len(timestamps) >= 2:
                    timestamps.sort()
                    time_span = timestamps[-1] - timestamps[0]
                    if time_span > 0:
                        request_rate = len(timestamps) / time_span

                    # لو المعدل عالي جداً (> 10 req/s)
                    if request_rate > 10:
                        score += 40
                        signals.append(f"high_rate:{request_rate:.1f}")
                    elif request_rate > 5:
                        score += 20
                        signals.append(f"medium_rate:{request_rate:.1f}")

            # 2. فحص 404s
            count_404 = await client.get(f"bot:404:{client_ip}")
            error_404_count = int(count_404) if count_404 else 0

            if error_404_count >= cls.MAX_404_BEFORE_BAN:
                score += 40
                signals.append(f"too_many_404:{error_404_count}")
            elif error_404_count >= 10:
                score += 20
                signals.append(f"many_404:{error_404_count}")

            # 3. القرار
            is_suspicious = score >= cls.BOT_SCORE_THRESHOLD

            return {
                "is_suspicious": is_suspicious,
                "bot_score": min(score, 100),
                "signals": signals,
                "request_rate": round(request_rate, 2),
                "error_404_count": error_404_count,
            }

        except Exception as e:
            logger.error("bot_detector_analyze_failed", error=str(e))
            return {
                "is_suspicious": False,
                "signals": [],
                "request_rate": 0.0,
                "error_404_count": 0,
            }

    # ─── Combined Analysis ─────────────────────────────────

    @classmethod
    async def detect(cls, request) -> Dict[str, Any]:
        """
        بيعمل تحليل شامل (static + behavioral).
        """
        # 1. Static analysis
        static = cls.analyze_request(request)

        # 2. Behavioral analysis
        client_ip = request.client.host if request.client else "unknown"
        behavioral = await cls.analyze_behavior(client_ip)

        # 3. Combine scores
        combined_score = max(
            static["bot_score"],
            behavioral.get("bot_score", 0),
        )

        # 4. Final decision
        is_bot = (
            static["is_bot"]
            or behavioral.get("is_suspicious", False)
        )

        should_block = (
            static["should_block"]
            or behavioral.get("is_suspicious", False)
        )

        # Good bots → متحجبش
        if static["classification"] == "good_bot":
            should_block = False
            is_bot = True

        return {
            "bot_score": combined_score,
            "classification": static["classification"],
            "is_bot": is_bot,
            "should_block": should_block,
            "static_signals": static["signals"],
            "behavioral_signals": behavioral.get("signals", []),
            "request_rate": behavioral.get("request_rate", 0.0),
            "error_404_count": behavioral.get("error_404_count", 0),
        }

    # ─── Utilities ─────────────────────────────────────────

    @classmethod
    async def reset(cls, client_ip: str) -> None:
        """بيمسح بيانات IP."""
        client = cls.get_client()
        if not client:
            return

        try:
            keys = [
                f"bot:behavior:{client_ip}",
                f"bot:404:{client_ip}",
            ]
            await client.delete(*keys)
            logger.info("bot_detector_reset", ip=client_ip)
        except Exception as e:
            logger.error("bot_detector_reset_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None