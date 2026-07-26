from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from llama_cpp import Llama

from soc_copilot.config import Settings, load_settings
from soc_copilot.parse.sysmon_event import SysmonEvent, parse_sysmon_message

_LLM_CACHE: dict[tuple[str, int, int], Llama] = {}

TRIAGE_PROMPT = """You are a SOC analyst. Analyze this security event for suspicious indicators before rating severity.

Red flags that indicate HIGH or CRITICAL severity:
- Base64-encoded PowerShell commands (-e or -EncodedCommand flags)
- PowerShell spawned from cmd.exe (unusual parent-child chain)
- Reconnaissance commands (whoami, hostname, net user, systeminfo) run via scripted automation
- Executables launched from user Temp or Downloads folders

Respond ONLY with JSON, nothing else:
{{"severity": "low|medium|high|critical", "technique_guess": "brief MITRE technique name", "summary": "one sentence", "confidence": 0.0}}

Confidence must be a number from 0.0 to 1.0. Use lower confidence when context is incomplete or the behavior could be benign.

Event:
{event}
JSON:"""


def get_llm(
    settings: Settings | None = None,
    *,
    model_path: str | None = None,
) -> Llama:
    """Lazy-load the local LLM so dashboard startup stays fast."""
    cfg = settings or load_settings()
    resolved_path = Path(model_path) if model_path else cfg.model_path
    cache_key = (str(resolved_path), cfg.n_ctx, cfg.n_threads)
    if cache_key not in _LLM_CACHE:
        if not resolved_path.exists():
            raise FileNotFoundError(
                f"Model not found at {resolved_path}. "
                "Download phi3-mini-q4.gguf into models/ or run with --demo using pre-triaged samples."
            )
        _LLM_CACHE[cache_key] = Llama(
            model_path=str(resolved_path),
            n_ctx=cfg.n_ctx,
            n_threads=cfg.n_threads,
            verbose=False,
        )
    return _LLM_CACHE[cache_key]


def _extract_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in LLM output: {text[:200]}")

    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("LLM output JSON is not an object")
    return parsed


def _normalize_confidence(value: Any) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    return round(max(0.0, min(1.0, confidence)), 2)


def _normalize_triage(parsed: dict[str, Any]) -> dict[str, Any]:
    severity = str(parsed.get("severity", "unknown")).lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "unknown"
    return {
        "severity": severity,
        "technique_guess": str(parsed.get("technique_guess", "")).strip(),
        "summary": str(parsed.get("summary", "")).strip(),
        "source": "llm",
        "confidence": _normalize_confidence(parsed.get("confidence")),
    }


def triage_event(
    event: dict | SysmonEvent,
    settings: Settings | None = None,
    *,
    model_path: str | None = None,
    source: str = "llm",
) -> dict[str, Any]:
    """Run LLM triage on a single Sysmon event. Returns a structured dict."""
    cfg = settings or load_settings()
    parsed = event if isinstance(event, SysmonEvent) else parse_sysmon_message(event)
    prompt = TRIAGE_PROMPT.format(event=parsed.to_prompt_text())

    llm = get_llm(cfg, model_path=model_path)
    resp = llm(prompt, max_tokens=cfg.max_tokens, temperature=cfg.temperature, stop=["##"])
    raw = resp["choices"][0]["text"].strip()

    try:
        verdict = _normalize_triage(_extract_json_object(raw))
        verdict["source"] = source
        return verdict
    except (json.JSONDecodeError, ValueError):
        return {
            "severity": "unknown",
            "technique_guess": "parse error",
            "summary": raw[:200] or "Failed to parse LLM response",
            "source": source,
            "confidence": None,
        }
