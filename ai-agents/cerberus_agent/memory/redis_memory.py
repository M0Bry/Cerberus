"""Redis-backed memory for agent conversations."""
class RedisMemory:
    def __init__(self, redis_client=None): self.redis = redis_client
    async def store(self, key: str, value: str): pass
    async def retrieve(self, key: str) -> str: return ""
