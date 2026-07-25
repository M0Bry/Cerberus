"""Parse user-agent + extract OS / browser / device."""


def parse_user_agent(ua: str) -> dict[str, str]:
    """Extract browser, OS, and device type from a User-Agent string."""
    browser = "Unknown"
    if "Chrome" in ua and "Edg" not in ua:
        browser = "Chrome"
    elif "Firefox" in ua:
        browser = "Firefox"
    elif "Safari" in ua and "Chrome" not in ua:
        browser = "Safari"
    elif "Edg" in ua:
        browser = "Edge"

    os_name = "Unknown"
    if "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"

    device = "Desktop"
    if "Mobile" in ua:
        device = "Mobile"
    elif "Tablet" in ua:
        device = "Tablet"

    return {"browser": browser, "os": os_name, "device": device}
