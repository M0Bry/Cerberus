"""GeoIP lookup accuracy."""

import pytest  # type: ignore[import-not-found]

from app.utils.geoip import lookup_ip


@pytest.mark.asyncio
async def test_geoip():
    result = await lookup_ip("8.8.8.8")
    assert "country" in result
