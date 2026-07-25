"""
User Agent Parser — Extracts browser, OS, and device info from User-Agent strings.
"""


def parse_user_agent(user_agent: str | None) -> dict[str, str | None]:
    """
    Parse a User-Agent string into browser, OS, and device components.

    Returns:
        Dict with 'browser', 'os', and 'device' keys.
    """
    if not user_agent:
        return {"browser": None, "os": None, "device": None}

    ua = user_agent.lower()

    # Detect Browser
    browser = "Unknown"
    if "edg/" in ua or "edge/" in ua:
        browser = "Microsoft Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "chrome" in ua and "safari" in ua:
        browser = "Google Chrome"
    elif "firefox" in ua:
        browser = "Mozilla Firefox"
    elif "safari" in ua:
        browser = "Safari"
    elif "msie" in ua or "trident" in ua:
        browser = "Internet Explorer"

    # Detect OS
    os_name = "Unknown"
    if "windows nt 10" in ua:
        os_name = "Windows 10/11"
    elif "windows nt 6.3" in ua:
        os_name = "Windows 8.1"
    elif "windows nt 6.1" in ua:
        os_name = "Windows 7"
    elif "windows" in ua:
        os_name = "Windows"
    elif "mac os x" in ua:
        os_name = "macOS"
    elif "linux" in ua and "android" not in ua:
        os_name = "Linux"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"

    # Detect Device
    device = "Desktop"
    if "mobile" in ua or "android" in ua:
        device = "Mobile"
    elif "tablet" in ua or "ipad" in ua:
        device = "Tablet"

    return {
        "browser": browser,
        "os": os_name,
        "device": device,
    }
