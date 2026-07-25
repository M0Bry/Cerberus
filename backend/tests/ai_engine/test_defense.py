"""
Defense Engine Unit Tests.
"""

from app.ai_engine.defense.tier1_gateway import GatewayProtection


class TestGatewayProtection:
    def setup_method(self):
        self.gateway = GatewayProtection()

    def test_clean_request_allowed(self):
        result = self.gateway.inspect_request(
            method="GET",
            path="/api/v1/users/me",
            headers={"authorization": "Bearer token123"},
            client_ip="192.168.1.1",
        )
        assert result["allowed"] is True

    def test_sql_injection_blocked(self):
        result = self.gateway.inspect_request(
            method="GET",
            path="/api/v1/users?id=1' OR '1'='1",
            headers={},
            client_ip="10.0.0.1",
        )
        assert result["allowed"] is False
        assert result["threat_type"] == "sql_injection"

    def test_xss_blocked(self):
        result = self.gateway.inspect_request(
            method="POST",
            path="/api/v1/comments",
            headers={},
            body='{"content": "<script>alert(1)</script>"}',
            client_ip="10.0.0.1",
        )
        assert result["allowed"] is False
        assert result["threat_type"] == "xss"

    def test_command_injection_blocked(self):
        result = self.gateway.inspect_request(
            method="GET",
            path="/api/v1/exec?cmd=;ls -la",
            headers={},
            client_ip="10.0.0.1",
        )
        assert result["allowed"] is False
        assert result["threat_type"] == "command_injection"

    def test_path_traversal_blocked(self):
        result = self.gateway.inspect_request(
            method="GET",
            path="/api/v1/files?path=../../../etc/passwd",
            headers={},
            client_ip="10.0.0.1",
        )
        assert result["allowed"] is False
        assert result["threat_type"] == "path_traversal"
