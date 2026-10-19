"""
Prompt-injection guard (Tier 1, Part C).

AI-bound input (the pentest chat) is the only user text that reaches
the LLM. Prompt-injection payloads try to make the model ignore its
role and engagement scope ("you are now ..."), leak the system
prompt, or switch to an unrestricted persona.

Design decisions:
* FAMILY-based detection — each family catches one injection
  strategy (instruction override, role escape, prompt extraction,
  jailbreak markers, delimiter escape).
* GRADUATED response. The product's chat is a cyber-security
  assistant: a user legitimately discussing injection techniques
  (single pattern family, plain text, no concealment) must NOT be
  blocked. Blocking requires either
      - 2 or more distinct families (a real attack combines
        strategies), OR
      - any family + an OBFUSCATION marker (base64 blob, hex escape
        run, invisible-unicode density) — concealment is itself the
        signal.
  One family, no obfuscation → SHADOW alert only (visible in the
  defense alerts, request passes).
* ENCODED variants (PayloadDecoder, depth 3, no mutation decoders)
  are scanned as well, so a base64-wrapped injection is still caught
  at the pattern level — the same decode machinery the input
  validator already trusts.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import List

from app.core.config import settings
from app.core.payload_decoder import PayloadDecoder

# ─── Obfuscation markers (independent of families) ─────────────

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_ESCAPE_RUN = re.compile(r"(\\x[0-9a-fA-F]{2}){20,}")
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
)
_C0_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _has_obfuscation(text: str) -> bool:
    if _BASE64_BLOB.search(text):
        return True
    if _HEX_ESCAPE_RUN.search(text):
        return True
    if len(_INVISIBLE.findall(text)) >= 5:
        return True
    if len(_C0_CONTROL.findall(text)) >= 10:
        return True
    return False


# ─── Injection families ────────────────────────────────────────
# (family_name, [compiled patterns])

def _c(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_FAMILIES: List[tuple[str, List[re.Pattern]]] = [
    (
        "instruction_override",
        _c([
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|my)\s+(instructions?|prompts?|rules?|directives?|guidelines?)",
            r"(disregard|forget)\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?|training|programming)",
            r"new\s+instructions?\s*:",
            r"(override|bypass)\s+(the\s+)?(previous|system|above|your|current)\s+(prompt|instructions?|rules?)",
            r"from\s+now\s+on\s*,?\s+you\s+(must|will|are\s+to|shall)",
        ]),
    ),
    (
        "role_escape",
        _c([
            r"you\s+are\s+now\s+(in\s+)?[a-z]+\s+mode",
            r"act\s+as\s+(a\s+|an\s+)?(different|unrestricted|unfiltered|jailbroken|unbounded)\s+[a-z]*",
            r"pretend\s+(that\s+)?(you\s+)?(are|to\s+be)\s+(unrestricted|unlimited|unfiltered|without\s+any)",
            r"without\s+(any\s+)?(restrictions?|limitations?|filters?|guidelines?|censors?|safety\s+rules?)",
            r"you\s+can\s+now\s+do\s+anything",
            r"\bdo\s+anything\s+now\b",
            r"no\s+rules?\s+(anymore|applied|in\s+effect)",
        ]),
    ),
    (
        "prompt_extraction",
        _c([
            r"(reveal|show|print|repeat|output|display|leak|dump)\s+(?:your|the|me\s+the\s+)?\s*(system|initial|original|hidden|secret|full)\s+(prompt|instructions?|message|configuration|text)",
            r"what\s+(were|was|is)\s+(you|your)\s+(initially|originally|first|primarily)\s+(told|instructed|programmed|configured)",
            r"(full|entire|complete)\s+system\s+prompt",
            r"repeat\s+(the|your)\s+(last|first|initial)\s+message",
        ]),
    ),
    (
        "jailbreak_markers",
        _c([
            r"\bDAN\s+mode\b",
            r"\b(developer|god|sudo)\s+mode\b",
            r"\bjailbreak(?:ing)?\s+(method|technique|attack|payload|prompt)\b",
            r"enable\s+(jailbreak|unrestricted|free)\s+mode",
        ]),
    ),
    (
        "delimiter_escape",
        _c([
            r"<\s*/?\s*(system|prompt|instructions?|end[-_]?of[-_]?system)\s*>",
            r"#{2,}\s*(system|prompt|developer)\s*#{2,}",
            r"-{4,}\s*(system|developer)\s*-{4,}",
            r"\[\s*SYSTEM\s*(MESSAGE|PROMPT)\s*\]",
        ]),
    ),
]


@dataclass
class PromptGuardResult:
    """Outcome of analyzing one piece of AI-bound text."""

    clean: bool
    action: str  # "allow" | "shadow_alert" | "block"
    families: List[str] = field(default_factory=list)
    obfuscated: bool = False
    matched: List[str] = field(default_factory=list)


def _scan_text(text: str) -> tuple[List[str], List[str], bool]:
    """Scan one decoded variant.

    Returns (families, matched_snippets, obfuscated).
    """
    families: List[str] = []
    matched: List[str] = []
    for name, patterns in _FAMILIES:
        for pat in patterns:
            m = pat.search(text)
            if m:
                if name not in families:
                    families.append(name)
                snippet = m.group(0)[:80]
                if snippet not in matched:
                    matched.append(snippet)
                break  # one hit per family is enough
    return families, matched, _has_obfuscation(text)


def analyze_prompt(text: str) -> PromptGuardResult:
    """
    Analyze AI-bound user text for prompt-injection patterns.

    Returns a PromptGuardResult; the middleware decides the HTTP
    response from ``result.action``:
      * allow        — nothing suspicious
      * shadow_alert — one plain-text family (likely legitimate
                       security discussion); alert recorded, request
                       passes
      * block        — 2+ families, or family + obfuscation
    """
    if not text or not text.strip():
        return PromptGuardResult(clean=True, action="allow")

    # Cap the analysis input: a 1 MB chat message is not a real
    # conversation; pattern scanning stays bounded.
    probe = text[:60_000]

    # Raw text first (patterns are written to work on JSON-escaped
    # text too), then decoded variants.
    all_families: List[str] = []
    all_matched: List[str] = []
    obfuscated = False

    variants = [probe]
    try:
        variants.extend(
            v for v in PayloadDecoder.decode_all(probe, max_depth=2)
            if v not in variants
        )
    except Exception:  # noqa: BLE001 — decoding must never break the flow
        variants = [probe]

    # Embedded base64 tokens: the shared decoder only decodes WHOLE
    # values (its base64 check is an exact-match on the full string).
    # Injections are usually embedded in otherwise-normal chat text —
    # "decode this: <blob>" — so the tokens are scanned directly.
    # Tokens shorter than 40 chars almost never carry a real payload;
    # a decoded result must also be plausible text (≥20 printable
    # chars) to be treated as a variant.
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", probe):
        tok = m.group(0)
        try:
            padded = tok + "=" * (-len(tok) % 4)
            dec = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        if len(dec) >= 20 and dec.isprintable() and dec not in variants:
            variants.append(dec)

    for variant in variants[:12]:
        families, matched, obf = _scan_text(variant)
        if obf:
            obfuscated = True
        for f in families:
            if f not in all_families:
                all_families.append(f)
        for s in matched:
            if s not in all_matched:
                all_matched.append(s)
        if len(all_families) >= settings.PROMPT_GUARD_BLOCK_FAMILIES or (
            obfuscated and all_families
        ):
            break  # already block-worthy; stop decoding

    if not all_families and not obfuscated:
        return PromptGuardResult(clean=True, action="allow")

    if all_families and (
        len(all_families) >= settings.PROMPT_GUARD_BLOCK_FAMILIES
        or obfuscated
    ):
        action = "block"
    elif all_families:
        action = "shadow_alert"
    else:
        # Obfuscation alone with no family hit: shadow-level signal.
        action = "shadow_alert"

    return PromptGuardResult(
        clean=False,
        action=action,
        families=all_families,
        obfuscated=obfuscated,
        matched=all_matched[:5],
    )
