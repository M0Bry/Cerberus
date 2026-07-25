"""Schema Validator — JSON schema validation for AI outputs."""

from typing import Any

import structlog

logger = structlog.get_logger()


class SchemaValidator:
    """Validates AI outputs against expected JSON schemas."""

    ATTACK_PATH_SCHEMA = {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["name", "description", "initial_entry_point"],
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "initial_entry_point": {"type": "string"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "priority": {"type": "integer", "minimum": 1},
            },
        },
    }

    def validate_attack_paths(self, data: Any) -> tuple[bool, list[str]]:
        """Validate attack path output from AI."""
        errors = []
        if not isinstance(data, (list, dict)):
            return False, ["Expected array or object"]
        paths = data if isinstance(data, list) else data.get("attack_paths", [])
        if not isinstance(paths, list):
            return False, ["attack_paths must be an array"]
        for i, path in enumerate(paths):
            if not path.get("name"):
                errors.append(f"Path {i}: missing 'name'")
            if not path.get("description"):
                errors.append(f"Path {i}: missing 'description'")
        return len(errors) == 0, errors

    def validate_scope(self, data: Any) -> tuple[bool, list[str]]:
        """Validate scope output from AI."""
        errors = []
        required = ["organization_profile", "business_objectives", "authorized_targets"]
        for field in required:
            if not data.get(field):
                errors.append(f"Missing required field: {field}")
        return len(errors) == 0, errors
