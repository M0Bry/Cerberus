"""
GitHub Scanner — Advanced GitHub secret and intelligence scanner.
Scans repositories for leaked credentials, sensitive files, and exposed endpoints.
"""

import base64
import math
import re

import aiohttp
import structlog

from osint_framework.core import IntelligenceResult
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class GitHubScanner(OSINTPlugin):
    """
    Scans GitHub for sensitive data exposure.

    Features:
    - Secret detection (AWS keys, API tokens, private keys, etc.)
    - Sensitive file discovery (.env, credentials, configs)
    - Endpoint extraction from source code
    - Contributor analysis
    - Commit history scanning
    """

    def __init__(self):
        super().__init__()
        self.name = "github_scan"
        self.description = "GitHub secret and intelligence scanner"
        self.category = "cybint"
        self.required_api_keys = ["github_token"]

        self.secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?['\x22]?[0-9a-zA-Z\/+]{40}['\x22]?",
            "google_api": r"AIza[0-9A-Za-z\-_]{35}",
            "github_token": r"ghp_[0-9a-zA-Z]{36}",
            "github_oauth": r"gho_[0-9a-zA-Z]{36}",
            "private_key": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
            "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "database_url": r"(?i)(mysql|postgresql|mongodb|redis)(.+?)://(.+?)@(.+)",
            "password_assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\x22][^\x22']+['\x22]",
            "stripe_key": r"sk_live_[0-9a-zA-Z]{24,}",
            "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "twilio_key": r"SK[0-9a-fA-F]{32}",
        }

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Scan GitHub for sensitive data related to the target."""
        logger.info("github_scan_started", target=target)

        findings: dict[str, list] = {
            "secrets_found": [],
            "sensitive_files": [],
            "exposed_endpoints": [],
            "repositories": [],
            "contributors": [],
        }

        headers = {"Accept": "application/vnd.github.v3+json"}
        token = kwargs.get("github_token") or ""
        if token:
            headers["Authorization"] = f"token {token}"

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers=headers,
        ) as session:
            # Search for code containing the target
            if "." in target:  # Domain
                await self._search_code(session, target, findings)
            else:  # Organization
                await self._search_org(session, target, findings)

        # Build processed data
        emails: set[str] = set()
        for secret in findings["secrets_found"]:
            context = secret.get("context", "")
            email_matches = re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", context
            )
            emails.update(email_matches)

        total_findings = len(findings["secrets_found"]) + len(findings["sensitive_files"])
        severity = (
            "critical" if findings["secrets_found"]
            else "medium" if findings["sensitive_files"]
            else "low"
        )

        processed = {
            "domain": target,
            "emails": list(emails),
            "secrets_found": findings["secrets_found"],
            "sensitive_files": findings["sensitive_files"],
            "exposed_endpoints": findings["exposed_endpoints"],
            "repositories": findings["repositories"],
            "total_findings": total_findings,
        }

        logger.info(
            "github_scan_completed",
            target=target,
            secrets=len(findings["secrets_found"]),
        )

        return IntelligenceResult(
            source="github_scanner",
            data_type="github_intelligence",
            confidence=0.85,
            raw_data=findings,
            processed_data=processed,
            category="credential" if findings["secrets_found"] else "technical",
            severity=severity,
            metadata={
                "target": target,
                "repos_scanned": len(findings["repositories"]),
            },
        )

    async def _search_code(
        self, session: aiohttp.ClientSession, domain: str, findings: dict[str, list]
    ) -> None:
        """Search GitHub code for domain references."""
        try:
            url = f"https://api.github.com/search/code?q={domain}+in:file&per_page=30"
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("items", [])[:20]:
                        try:
                            async with session.get(item["url"]) as file_resp:
                                if file_resp.status == 200:
                                    file_data = await file_resp.json()
                                    content = base64.b64decode(
                                        file_data.get("content", "")
                                    ).decode("utf-8", errors="ignore")

                                    secrets = self._find_secrets(
                                        content, item["html_url"]
                                    )
                                    findings["secrets_found"].extend(secrets)

                                    filename = item.get("name", "")
                                    if any(
                                        ext in filename.lower()
                                        for ext in [
                                            ".env", ".config", "credentials",
                                            "secret", ".key", ".pem",
                                        ]
                                    ):
                                        findings["sensitive_files"].append({
                                            "file": filename,
                                            "path": item.get("path", ""),
                                            "url": item.get("html_url", ""),
                                            "repo": item.get("repository", {}).get(
                                                "full_name", ""
                                            ),
                                        })

                                    endpoints = self._extract_endpoints(content)
                                    findings["exposed_endpoints"].extend(endpoints)
                        except Exception:
                            continue
        except Exception as e:
            logger.error("github_code_search_error", domain=domain, error=str(e))

    async def _search_org(
        self, session: aiohttp.ClientSession, org: str, findings: dict[str, list]
    ) -> None:
        """Search organization repositories."""
        try:
            url = f"https://api.github.com/orgs/{org}/repos?per_page=30&sort=updated"
            async with session.get(url) as resp:
                if resp.status == 200:
                    repos = await resp.json()
                    for repo in repos[:10]:
                        findings["repositories"].append({
                            "name": repo["full_name"],
                            "description": repo.get("description"),
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count", 0),
                            "updated_at": repo.get("updated_at"),
                        })
        except Exception as e:
            logger.error("github_org_search_error", org=org, error=str(e))

    def _find_secrets(self, content: str, source_url: str) -> list[dict]:
        """Scan content for secrets using regex patterns."""
        findings: list[dict] = []
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                matched = match.group()
                redacted = matched[:10] + "..." if len(matched) > 10 else matched
                confidence = self._calculate_confidence(secret_type, matched)
                context = content[max(0, match.start() - 30):match.end() + 30]
                findings.append({
                    "type": secret_type,
                    "value_redacted": redacted,
                    "source_url": source_url,
                    "confidence": confidence,
                    "context": context,
                })
        return findings

    def _extract_endpoints(self, content: str) -> list[str]:
        """Extract API endpoints from code."""
        patterns = [
            r'["\x27](/api/[^"\x27\s]+)["\x27]',
            r'["\x27](/v[0-9]+/[^"\x27\s]+)["\x27]',
            r'["\x27](/graphql[^"\x27\s]*)["\x27]',
            r'fetch\(["\x27]([^"\x27\s]+)["\x27]',
            r'axios\.(?:get|post|put|delete)\(["\x27]([^"\x27\s]+)["\x27]',
        ]
        endpoints: set[str] = set()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            endpoints.update(matches)
        return list(endpoints)

    @staticmethod
    def _calculate_confidence(secret_type: str, matched: str) -> float:
        """Calculate confidence that a finding is a real secret."""
        confidence = 0.5
        entropy = GitHubScanner._calculate_entropy(matched)
        if entropy > 3.5:
            confidence += 0.3
        if secret_type in ("aws_access_key", "github_token", "stripe_key"):
            confidence += 0.2
        return min(confidence, 1.0)

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(chr(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
