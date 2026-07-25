"""Input validation + sanitization."""

from app.core.input_validator import (
    detect_sql_injection,
    detect_xss,
    validate_domain,
    validate_email,
    validate_input,
)


def test_sql_injection():
    assert detect_sql_injection("' OR '1'='1")


def test_xss():
    assert detect_xss("<script>alert(1)</script>")


def test_clean_input():
    assert validate_input("normal text", "test") == "normal text"


def test_email():
    assert validate_email("test@example.com")


def test_domain():
    assert validate_domain("example.com")
