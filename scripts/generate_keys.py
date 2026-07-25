"""Generate encryption keys + JWT secrets."""
import secrets

print("Generated keys:")
print(f"SECRET_KEY={secrets.token_hex(32)}")
print(f"DB_PASSWORD={secrets.token_hex(16)}")
print(f"REDIS_PASSWORD={secrets.token_hex(16)}")
print(f"ENCRYPTION_KEY={secrets.token_hex(32)}")
