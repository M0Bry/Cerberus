# AI Architecture

## Components
- **Model Router** — Routes tasks to best available model (OpenAI, Anthropic, Local)
- **Prompt Engine** — 10 specialized prompts for each phase
- **Memory System** — Conversation, vector, context, and engagement memory
- **XAI** — Explainable AI with decision tracing and evidence tracking
- **Validators** — Hallucination guard, schema validation, output filtering
- **Sandbox** — Docker-isolated tool execution with network isolation

## Task Pipeline
1. User message → Context compression → Model selection
2. Model response → Schema validation → Hallucination check
3. Output filtering → Response delivery → Memory update
