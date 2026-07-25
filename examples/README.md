# Cerberus AI — Examples

## Running an OSINT scan
```python
from osint_framework.core.engine import OSINTEngine
engine = OSINTEngine()
await engine.initialize()
report = await engine.run_intelligence_cycle("example.com", modules=["cybint"])
print(report.executive_summary)
```

## Creating an engagement
```bash
curl -X POST http://localhost:8000/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_name": "Q3 Assessment", "organization_name": "Acme Corp"}'
```

## Running attack plugins
```python
from plugins.attacks.web.sql_injection.attack import SqlInjectionAttack
attack = SqlInjectionAttack()
result = await attack.execute("https://example.com/api/users?id=1")
print(result.status, result.title)
```
