"""Recon Tools — Network reconnaissance, port scanning, banner grabbing."""

import asyncio

import structlog

logger = structlog.get_logger()


class ReconTools:
    """Network reconnaissance tools for Red Team operations."""

    async def port_scan(
        self, host: str, ports: list[int] | None = None, timeout: float = 2.0
    ) -> list[dict]:
        """TCP port scan using asyncio."""
        if ports is None:
            ports = [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                993, 995, 1433, 3306, 3389, 5432, 8080, 8443,
            ]

        open_ports = []
        for port in ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": self._guess_service(port),
                })
                writer.close()
            except (TimeoutError, ConnectionRefusedError, OSError):
                pass

        logger.info("port_scan_complete", host=host, open=len(open_ports))
        return open_ports

    async def banner_grab(self, host: str, port: int, timeout: float = 5.0) -> str:
        """Grab service banner from an open port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""

    def _guess_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            8080: "http-proxy", 8443: "https-alt",
        }
        return services.get(port, "unknown")
