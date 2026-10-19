"""
Graph Analyzer — Relationship graph analysis for coordinated attacks.

بيوفر:
- Multi-entity graph (users, IPs, devices, endpoints, ASNs)
- Relationship tracking (edges with weights)
- Pattern detection:
  * Shared IP (many users on one IP)
  * Shared device (many users on one device)
  * Fan-out (one user with many IPs/devices)
  * Dense clusters (communities)
  * Bridge nodes
  * Star patterns
- Community detection (connected components + density)
- Graph-based risk scoring
- Redis-backed
- networkx integration

الفكرة:
- نبني graph من العلاقات (user ↔ IP, user ↔ device, ...)
- كل علاقة ليها weight (عدد المرات)
- نطبق graph algorithms لكشف الأنماط الخبيثة
- مناسب لـ:
  * Botnet detection
  * Coordinated attack detection
  * Account takeover rings
  * Credential stuffing
  * Fraud rings

الاستخدام:
- abuse_detector.py
- session_analyzer.py
- anomaly_detection.py
- attack_chain.py
"""

import json
import math
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
import redis.asyncio as redis
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class GraphAnalyzer:
    """
    Relationship Graph Analyzer.

    الفكرة:
    - بنخزن العلاقات في Redis
    - بنبني networkx graph عند الطلب
    - بنطبق algorithms للكشف
    """

    _redis_client: Optional[redis.Redis] = None

    # ─── Config ────────────────────────────────────────────
    GRAPH_TTL = 86400 * 7        # 7 أيام
    MAX_RELATIONSHIPS = 10000    # حد أقصى

    # ─── Node Types ────────────────────────────────────────
    NODE_USER = "user"
    NODE_IP = "ip"
    NODE_DEVICE = "device"
    NODE_ENDPOINT = "endpoint"
    NODE_ASN = "asn"

    # ─── Edge Types ────────────────────────────────────────
    EDGE_USES_IP = "uses_ip"
    EDGE_USES_DEVICE = "uses_device"
    EDGE_USES_ENDPOINT = "uses_endpoint"
    EDGE_FROM_ASN = "from_asn"

    # ─── Thresholds ────────────────────────────────────────
    SHARED_IP_MIN_USERS = 5      # IP مع 5+ users = مشبوه
    SHARED_DEVICE_MIN_USERS = 3
    FANOUT_MIN_IPS = 10          # user بـ 10+ IPs = مشبوه
    FANOUT_MIN_DEVICES = 5
    DENSE_CLUSTER_MIN_SIZE = 4
    DENSE_CLUSTER_MIN_DENSITY = 0.7

    BRIDGE_MIN_NODES = 5         # أقل عدد nodes لتحليل bridge

    # ─── Weights ──────────────────────────────────────────
    WEIGHTS = {
        "shared_ip": 35,
        "shared_device": 45,
        "fanout_ips": 30,
        "fanout_devices": 40,
        "dense_cluster": 50,
        "bridge_node": 35,
        "star_pattern": 40,
        "many_shared_ips": 30,
    }

    # ─── Risk Thresholds ──────────────────────────────────
    THRESHOLDS = {
        "low": 30,
        "medium": 50,
        "high": 70,
        "critical": 85,
    }

    # ═══════════════════════════════════════════════════════
    #  Internal Helpers
    # ═══════════════════════════════════════════════════════

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
                logger.error("graph_analyzer_redis_init_failed", error=str(e))
                return None
        return cls._redis_client

    @staticmethod
    def _edges_key(node_type: str, node_value: str) -> str:
        """Key للعلاقات من node."""
        return f"graph:{node_type}:{node_value}:edges"

    @staticmethod
    def _node_key(node_type: str, node_value: str) -> str:
        """Key للـ node metadata."""
        return f"graph:{node_type}:{node_value}"

    @staticmethod
    def _node_id(node_type: str, node_value: str) -> str:
        """ID فريد للـ node في الـ graph."""
        return f"{node_type}:{node_value}"

    # ═══════════════════════════════════════════════════════
    #  Recording Relationships
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def record_relationship(
        cls,
        from_type: str,
        from_value: str,
        to_type: str,
        to_value: str,
        *,
        weight: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        بيسجل علاقة بين node و node.
        """
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            if not from_value or not to_value:
                return {"success": False, "error": "missing_values"}

            if from_type not in (
                cls.NODE_USER, cls.NODE_IP, cls.NODE_DEVICE,
                cls.NODE_ENDPOINT, cls.NODE_ASN,
            ):
                return {"success": False, "error": "invalid_from_type"}

            if to_type not in (
                cls.NODE_USER, cls.NODE_IP, cls.NODE_DEVICE,
                cls.NODE_ENDPOINT, cls.NODE_ASN,
            ):
                return {"success": False, "error": "invalid_to_type"}

            now = time.time()

            # 1. خزّن العلاقة (في كل الاتجاهين للسهولة)
            from_key = cls._edges_key(from_type, from_value)
            to_key = cls._edges_key(to_type, to_value)

            edge_data = json.dumps({
                "type": to_type,
                "value": to_value,
                "weight": weight,
                "metadata": metadata or {},
                "last_seen": now,
            })

            reverse_edge_data = json.dumps({
                "type": from_type,
                "value": from_value,
                "weight": weight,
                "metadata": metadata or {},
                "last_seen": now,
            })

            await client.hincrby(from_key, f"{to_type}:{to_value}", weight)
            await client.hset(from_key, f"_meta:{to_type}:{to_value}", edge_data)
            await client.expire(from_key, cls.GRAPH_TTL)

            await client.hincrby(to_key, f"{from_type}:{from_value}", weight)
            await client.hset(to_key, f"_meta:{from_type}:{from_value}", reverse_edge_data)
            await client.expire(to_key, cls.GRAPH_TTL)

            # 2. سجل في metadata الـ nodes
            from_node_key = cls._node_key(from_type, from_value)
            await client.hset(from_node_key, "last_seen", str(now))
            await client.hincrby(from_node_key, "total_edges", 1)
            await client.expire(from_node_key, cls.GRAPH_TTL)

            to_node_key = cls._node_key(to_type, to_value)
            await client.hset(to_node_key, "last_seen", str(now))
            await client.hincrby(to_node_key, "total_edges", 1)
            await client.expire(to_node_key, cls.GRAPH_TTL)

            return {
                "success": True,
                "from": cls._node_id(from_type, from_value),
                "to": cls._node_id(to_type, to_value),
            }

        except Exception as e:
            logger.error("graph_record_relationship_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Building Graph
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def build_graph_from_node(
        cls,
        start_type: str,
        start_value: str,
        *,
        max_depth: int = 2,
        min_weight: int = 1,
    ) -> nx.Graph:
        """
        بيبني graph حول node معينة (BFS).
        """
        client = cls.get_client()
        G = nx.Graph()

        if not client:
            return G

        start_id = cls._node_id(start_type, start_value)

        # BFS
        visited: Set[str] = set()
        queue: List[Tuple[str, str, int]] = [(start_type, start_value, 0)]
        visited.add(start_id)

        G.add_node(start_id, type=start_type, value=start_value)

        while queue:
            node_type, node_value, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # جيب العلاقات
            edges_key = cls._edges_key(node_type, node_value)
            edges = await client.hgetall(edges_key)

            node_id = cls._node_id(node_type, node_value)

            for key, val in edges.items():
                if key.startswith("_meta:"):
                    continue

                # key = "user:admin_1"
                try:
                    target_type, target_value = key.split(":", 1)
                except ValueError:
                    continue

                weight = int(val)
                if weight < min_weight:
                    continue

                target_id = cls._node_id(target_type, target_value)

                # ضيف node و edge
                if not G.has_node(target_id):
                    G.add_node(
                        target_id,
                        type=target_type,
                        value=target_value,
                    )

                G.add_edge(node_id, target_id, weight=weight)

                # كمل BFS
                if target_id not in visited:
                    visited.add(target_id)
                    queue.append((target_type, target_value, depth + 1))

        return G

    # ═══════════════════════════════════════════════════════
    #  Pattern Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def detect_shared_ip(
        G: nx.Graph,
        ip_node: str,
        min_users: int = 5,
    ) -> Dict[str, Any]:
        """بيكشف IP مشترك بين users كتير."""
        if not G.has_node(ip_node):
            return {"detected": False, "confidence": 0}

        neighbors = list(G.neighbors(ip_node))
        users = [
            n for n in neighbors
            if G.nodes[n].get("type") == "user"
        ]

        count = len(users)

        if count >= min_users:
            extra = min(count - min_users, 20)
            confidence = min(
                GraphAnalyzer.WEIGHTS["shared_ip"] + (extra * 2),
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "ip": G.nodes[ip_node].get("value"),
                    "user_count": count,
                    "sample_users": [
                        G.nodes[u].get("value") for u in users[:5]
                    ],
                },
            }

        return {"detected": False, "confidence": 0}

    @staticmethod
    def detect_shared_device(
        G: nx.Graph,
        device_node: str,
        min_users: int = 3,
    ) -> Dict[str, Any]:
        """بيكشف device مشترك بين users كتير."""
        if not G.has_node(device_node):
            return {"detected": False, "confidence": 0}

        neighbors = list(G.neighbors(device_node))
        users = [
            n for n in neighbors
            if G.nodes[n].get("type") == "user"
        ]

        count = len(users)

        if count >= min_users:
            extra = min(count - min_users, 10)
            confidence = min(
                GraphAnalyzer.WEIGHTS["shared_device"] + (extra * 5),
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "device": G.nodes[device_node].get("value"),
                    "user_count": count,
                    "sample_users": [
                        G.nodes[u].get("value") for u in users[:5]
                    ],
                },
            }

        return {"detected": False, "confidence": 0}

    @staticmethod
    def detect_user_fanout(
        G: nx.Graph,
        user_node: str,
    ) -> Dict[str, Any]:
        """بيكشف user بيستخدم IPs أو devices كتير."""
        if not G.has_node(user_node):
            return {"detected": False, "confidence": 0}

        neighbors = list(G.neighbors(user_node))
        ips = [n for n in neighbors if G.nodes[n].get("type") == "ip"]
        devices = [n for n in neighbors if G.nodes[n].get("type") == "device"]

        total_confidence = 0
        signals = []

        if len(ips) >= GraphAnalyzer.FANOUT_MIN_IPS:
            signals.append("fanout_ips")
            total_confidence += GraphAnalyzer.WEIGHTS["fanout_ips"]

        if len(devices) >= GraphAnalyzer.FANOUT_MIN_DEVICES:
            signals.append("fanout_devices")
            total_confidence += GraphAnalyzer.WEIGHTS["fanout_devices"]

        if signals:
            return {
                "detected": True,
                "confidence": min(total_confidence, 100),
                "details": {
                    "user": G.nodes[user_node].get("value"),
                    "unique_ips": len(ips),
                    "unique_devices": len(devices),
                    "signals": signals,
                },
            }

        return {"detected": False, "confidence": 0}

    @staticmethod
    def detect_dense_cluster(
        G: nx.Graph,
        *,
        min_size: int = 4,
        min_density: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """بيكشف clusters كثيفة (density عالية)."""
        if G.number_of_nodes() < min_size:
            return []

        clusters = []

        components = list(nx.connected_components(G))

        for comp in components:
            if len(comp) < min_size:
                continue

            subgraph = G.subgraph(comp)
            density = nx.density(subgraph)

            if density >= min_density:
                clusters.append({
                    "size": len(comp),
                    "density": round(density, 3),
                    "nodes": list(comp)[:10],
                })

        return clusters

    @staticmethod
    def detect_star_pattern(
        G: nx.Graph,
        center_node: str,
        *,
        min_spokes: int = 5,
        max_depth: int = 1,
    ) -> Dict[str, Any]:
        """بيكشف star pattern — node واحد متصل بكذا node بدون ترابط بينهم."""
        if not G.has_node(center_node):
            return {"detected": False, "confidence": 0}

        neighbors = list(G.neighbors(center_node))
        n_neighbors = len(neighbors)

        if n_neighbors < min_spokes:
            return {"detected": False, "confidence": 0}

        subgraph = G.subgraph(neighbors)
        edges_between = subgraph.number_of_edges()
        max_possible_edges = (n_neighbors * (n_neighbors - 1)) / 2

        if max_possible_edges == 0:
            return {"detected": False, "confidence": 0}

        neighbor_connectivity = edges_between / max_possible_edges

        if neighbor_connectivity < 0.2 and n_neighbors >= min_spokes:
            confidence = min(
                GraphAnalyzer.WEIGHTS["star_pattern"]
                + (n_neighbors - min_spokes) * 2,
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "center": G.nodes[center_node].get("value"),
                    "spokes": n_neighbors,
                    "neighbor_connectivity": round(neighbor_connectivity, 3),
                },
            }

        return {"detected": False, "confidence": 0}

    @staticmethod
    def detect_bridge_node(
        G: nx.Graph,
        node: str,
    ) -> Dict[str, Any]:
        """
        بيكشف bridge node (articulation point).

        Bridge node = node لو اتحذف، الـ graph بتتقسم لأجزاء.
        """
        if not G.has_node(node):
            return {"detected": False, "confidence": 0}

        # محتاج graph كافي للتحليل
        if G.number_of_nodes() < GraphAnalyzer.BRIDGE_MIN_NODES:
            return {"detected": False, "confidence": 0}

        neighbors = list(G.neighbors(node))

        # articulation point لازم يكون عنده 2+ connections
        if len(neighbors) < 2:
            return {"detected": False, "confidence": 0}

        try:
            # استخدم articulation_points algorithm (Tarjan)
            articulation_points = set(nx.articulation_points(G))

            if node not in articulation_points:
                return {"detected": False, "confidence": 0}

            # عدد الـ components قبل وبعد
            components_before = nx.number_connected_components(G)

            G_copy = G.copy()
            G_copy.remove_node(node)
            components_after = nx.number_connected_components(G_copy)

            bridges = components_after - components_before

            confidence = min(
                GraphAnalyzer.WEIGHTS["bridge_node"]
                + max(bridges, 1) * 5,
                100,
            )

            return {
                "detected": True,
                "confidence": confidence,
                "details": {
                    "node": G.nodes[node].get("value"),
                    "node_type": G.nodes[node].get("type"),
                    "neighbors": len(neighbors),
                    "components_before": components_before,
                    "components_after": components_after,
                    "bridges": bridges,
                },
            }

        except Exception as e:
            logger.debug("graph_bridge_detection_failed", error=str(e))
            return {"detected": False, "confidence": 0}

    # ═══════════════════════════════════════════════════════
    #  Main Analysis
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def analyze(
        cls,
        node_type: str,
        node_value: str,
        *,
        max_depth: int = 2,
    ) -> Dict[str, Any]:
        """
        تحليل شامل لـ node معين في الـ graph.
        """
        try:
            if not node_type or not node_value:
                return {
                    "success": False,
                    "error": "missing_node_info",
                }

            # ─── ابنِ الـ graph ───
            G = await cls.build_graph_from_node(
                node_type, node_value, max_depth=max_depth,
            )

            # Early return مع graph_stats
            if G.number_of_nodes() < 2:
                return {
                    "success": True,
                    "node": cls._node_id(node_type, node_value),
                    "node_type": node_type,
                    "node_value": node_value,
                    "is_suspicious": False,
                    "risk_score": 0,
                    "level": "clean",
                    "signals": [],
                    "signal_count": 0,
                    "details": {},
                    "graph_stats": {
                        "nodes": G.number_of_nodes(),
                        "edges": G.number_of_edges(),
                        "density": 0.0,
                        "avg_degree": 0.0,
                    },
                }

            signals: List[str] = []
            details: Dict[str, Any] = {}
            total_score = 0

            node_id = cls._node_id(node_type, node_value)

            # ─── 1. Shared IP ───
            if node_type == cls.NODE_IP:
                shared = cls.detect_shared_ip(
                    G, node_id, cls.SHARED_IP_MIN_USERS
                )
                if shared["detected"]:
                    signals.append("shared_ip")
                    total_score += shared["confidence"]
                    details["shared_ip"] = shared["details"]

            # ─── 2. Shared Device ───
            if node_type == cls.NODE_DEVICE:
                shared = cls.detect_shared_device(
                    G, node_id, cls.SHARED_DEVICE_MIN_USERS
                )
                if shared["detected"]:
                    signals.append("shared_device")
                    total_score += shared["confidence"]
                    details["shared_device"] = shared["details"]

            # ─── 3. User Fanout ───
            if node_type == cls.NODE_USER:
                fanout = cls.detect_user_fanout(G, node_id)
                if fanout["detected"]:
                    signals.extend(fanout["details"]["signals"])
                    total_score += fanout["confidence"]
                    details["fanout"] = fanout["details"]

            # ─── 4. Star Pattern ───
            star = cls.detect_star_pattern(G, node_id)
            if star["detected"]:
                signals.append("star_pattern")
                total_score += star["confidence"]
                details["star_pattern"] = star["details"]

            # ─── 5. Bridge Node ───
            bridge = cls.detect_bridge_node(G, node_id)
            if bridge["detected"]:
                signals.append("bridge_node")
                total_score += bridge["confidence"]
                details["bridge_node"] = bridge["details"]

            # ─── 6. Dense Cluster ───
            clusters = cls.detect_dense_cluster(G)
            if clusters:
                signals.append("dense_cluster")
                total_score += cls.WEIGHTS["dense_cluster"]
                details["dense_clusters"] = clusters

            # ─── 7. Graph stats ───
            density = nx.density(G)
            avg_degree = sum(dict(G.degree()).values()) / max(G.number_of_nodes(), 1)

            # ─── 8. Risk score ───
            risk_score = min(int(math.sqrt(total_score) * 10), 100)

            # ─── 9. Level ───
            level = "clean"
            if risk_score >= cls.THRESHOLDS["critical"]:
                level = "critical"
            elif risk_score >= cls.THRESHOLDS["high"]:
                level = "high"
            elif risk_score >= cls.THRESHOLDS["medium"]:
                level = "medium"
            elif risk_score >= cls.THRESHOLDS["low"]:
                level = "low"

            # ─── 10. Decision ───
            is_suspicious = risk_score >= cls.THRESHOLDS["low"]

            if is_suspicious:
                logger.warning(
                    "graph_anomaly_detected",
                    node=node_id,
                    risk_score=risk_score,
                    level=level,
                    signals=signals,
                )

            return {
                "success": True,
                "node": node_id,
                "node_type": node_type,
                "node_value": node_value,
                "is_suspicious": is_suspicious,
                "risk_score": risk_score,
                "level": level,
                "signals": signals,
                "signal_count": len(signals),
                "details": details,
                "graph_stats": {
                    "nodes": G.number_of_nodes(),
                    "edges": G.number_of_edges(),
                    "density": round(density, 4),
                    "avg_degree": round(avg_degree, 2),
                },
            }

        except Exception as e:
            logger.error("graph_analysis_failed", error=str(e))
            return {"success": False, "error": str(e)}

    # ═══════════════════════════════════════════════════════
    #  Utilities
    # ═══════════════════════════════════════════════════════

    @classmethod
    async def get_node_relationships(
        cls,
        node_type: str,
        node_value: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """بيرجع كل علاقات الـ node."""
        client = cls.get_client()
        if not client:
            return {}

        try:
            edges_key = cls._edges_key(node_type, node_value)
            edges = await client.hgetall(edges_key)

            grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

            for key, val in edges.items():
                if key.startswith("_meta:"):
                    continue

                try:
                    target_type, target_value = key.split(":", 1)
                    weight = int(val)

                    grouped[target_type].append({
                        "value": target_value,
                        "weight": weight,
                    })
                except (ValueError, TypeError):
                    continue

            for target_type in grouped:
                grouped[target_type].sort(
                    key=lambda x: x["weight"],
                    reverse=True,
                )

            return dict(grouped)

        except Exception as e:
            logger.error("graph_get_relationships_failed", error=str(e))
            return {}

    @classmethod
    async def clear_node(
        cls,
        node_type: str,
        node_value: str,
    ) -> Dict[str, Any]:
        """بيمسح node وكل علاقاته."""
        client = cls.get_client()
        if not client:
            return {"success": False, "error": "redis_unavailable"}

        try:
            keys = [
                cls._edges_key(node_type, node_value),
                cls._node_key(node_type, node_value),
            ]
            await client.delete(*keys)

            logger.info("graph_node_cleared", node=f"{node_type}:{node_value}")

            return {"success": True}

        except Exception as e:
            logger.error("graph_clear_node_failed", error=str(e))
            return {"success": False, "error": str(e)}

    @classmethod
    async def clear_all(cls) -> None:
        """بيمسح كل الـ graph data."""
        client = cls.get_client()
        if not client:
            return

        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match="graph:*",
                    count=100,
                )
                if keys:
                    await client.delete(*keys)
                if cursor == 0:
                    break

            logger.info("graph_all_cleared")
        except Exception as e:
            logger.error("graph_clear_all_failed", error=str(e))

    @classmethod
    async def close(cls) -> None:
        """بتقفل Redis."""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None


# ─── Standalone functions ─────────────────────────────

async def record_relationship(
    from_type: str,
    from_value: str,
    to_type: str,
    to_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for GraphAnalyzer.record_relationship."""
    return await GraphAnalyzer.record_relationship(
        from_type, from_value, to_type, to_value, **kwargs,
    )


async def analyze(
    node_type: str,
    node_value: str,
    **kwargs,
) -> Dict[str, Any]:
    """Shortcut for GraphAnalyzer.analyze."""
    return await GraphAnalyzer.analyze(node_type, node_value, **kwargs)